package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ai-observability/agent/internal/config"
	"github.com/ai-observability/agent/internal/sender"
	"go.uber.org/zap"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// ─── Threat signatures ────────────────────────────────────────────────────────

var (
	// Log patterns indicating potential external attacks
	reSSHBruteForce    = regexp.MustCompile(`(?i)(failed password|authentication failure|invalid user|failed publickey)`)
	rePortScan         = regexp.MustCompile(`(?i)(port scan|nmap|masscan|zmap|SYN flood)`)
	reWebAttack        = regexp.MustCompile(`(?i)(sql injection|' or '|union select|xss|<script>|javascript:|eval\(|base64_decode|/etc/passwd|/proc/self|\.\.\/\.\.\/|cmd=|exec=)`)
	reCredentialStuff  = regexp.MustCompile(`(?i)(credential stuffing|brute.?force|too many auth|rate limit exceeded.*login|login attempt)`)
	reDirTraversal     = regexp.MustCompile(`(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e)`)
	rePrivilegeEsc     = regexp.MustCompile(`(?i)(privilege escalat|sudo.*NOPASSWD|chmod.*777|chown.*root|setuid|ptrace|/proc/mem)`)
	reCryptoMiner      = regexp.MustCompile(`(?i)(xmrig|minerd|cryptonight|stratum\+tcp|mining pool|monero)`)
	reReverseShell     = regexp.MustCompile(`(?i)(bash -i >& /dev/tcp|nc -e /bin/sh|mkfifo|/dev/tcp/|python.*socket.*connect|perl.*socket)`)
	reContainerEscape  = regexp.MustCompile(`(?i)(container escape|docker\.sock|/proc/1/ns|nsenter|runc|cgroup.*release_agent)`)
	reSecretExfil      = regexp.MustCompile(`(?i)(curl.*secret|wget.*token|kubectl.*secret|base64.*KUBECONFIG|exfiltrat)`)
	reKubernetesThreat = regexp.MustCompile(`(?i)(kubectl exec|kubectl port-forward|create clusterrolebinding|impersonate.*system:masters|anonymous.*cluster-admin)`)
)

// threatSignature maps a compiled regex to its category and severity.
type threatSignature struct {
	pattern  *regexp.Regexp
	category string
	severity string // critical | high | medium | low
}

var threatSignatures = []threatSignature{
	{reWebAttack, "web_attack", "high"},
	{reSSHBruteForce, "brute_force", "high"},
	{reCredentialStuff, "brute_force", "high"},
	{rePrivilegeEsc, "privilege_escalation", "critical"},
	{reReverseShell, "reverse_shell", "critical"},
	{reContainerEscape, "container_escape", "critical"},
	{reCryptoMiner, "crypto_mining", "high"},
	{reDirTraversal, "path_traversal", "medium"},
	{rePortScan, "port_scan", "medium"},
	{reSecretExfil, "secret_exfiltration", "critical"},
	{reKubernetesThreat, "kubernetes_attack", "critical"},
}

// ─── Audit event (Kubernetes audit log JSON struct) ──────────────────────────

type k8sAuditEvent struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Level      string `json:"level"`
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	RequestURI string `json:"requestURI"`
	Verb       string `json:"verb"`
	User       struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser"`
	SourceIPs        []string               `json:"sourceIPs"`
	ObjectRef        map[string]interface{} `json:"objectRef"`
	ResponseStatus   map[string]interface{} `json:"responseStatus"`
	RequestTimestamp string                 `json:"requestTimestamp"`
}

// ─── SecurityThreatCollector ─────────────────────────────────────────────────

// SecurityThreatCollector watches three sources:
//  1. Application pod logs — scanned for attack patterns
//  2. Kubernetes audit logs — scanned for API abuse, RBAC violations, impersonation
//  3. RBAC resources — watches for suspicious ClusterRoleBindings granting cluster-admin
type SecurityThreatCollector struct {
	cfg          *config.Config
	logger       *zap.Logger
	sender       sender.Sender
	client       kubernetes.Interface
	auditLogPath string
}

func NewSecurityThreatCollector(cfg *config.Config, logger *zap.Logger, sndr sender.Sender) (*SecurityThreatCollector, error) {
	client, err := buildK8sClient(cfg.KubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("build k8s client: %w", err)
	}
	return &SecurityThreatCollector{
		cfg:          cfg,
		logger:       logger,
		sender:       sndr,
		client:       client,
		auditLogPath: getEnvDefault("AUDIT_LOG_PATH", "/var/log/kubernetes/audit/audit.log"),
	}, nil
}

func (s *SecurityThreatCollector) Start(ctx context.Context) error {
	s.logger.Info("Starting security threat collector")

	go s.watchRBAC(ctx)
	go s.watchAuditLog(ctx)
	go s.watchPrivilegedPods(ctx)
	go s.watchNetworkPolicies(ctx)

	<-ctx.Done()
	s.logger.Info("Security threat collector stopped")
	return nil
}

// ── Audit log watcher ────────────────────────────────────────────────────────

func (s *SecurityThreatCollector) watchAuditLog(ctx context.Context) {
	f, err := os.Open(s.auditLogPath)
	if err != nil {
		s.logger.Warn("Cannot open audit log (may not be accessible from pod)",
			zap.String("path", s.auditLogPath), zap.Error(err))
		return
	}
	defer f.Close()

	// Seek to end to only process new entries
	if _, err := f.Seek(0, 2); err != nil {
		return
	}

	scanner := bufio.NewScanner(f)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if scanner.Scan() {
			s.analyzeAuditLine(ctx, scanner.Text())
		} else {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func (s *SecurityThreatCollector) analyzeAuditLine(ctx context.Context, line string) {
	var evt k8sAuditEvent
	if err := json.Unmarshal([]byte(line), &evt); err != nil {
		return
	}

	threats := []sender.ThreatIndicator{}

	username := evt.User.Username
	groups := evt.User.Groups
	verb := strings.ToLower(evt.Verb)
	uri := evt.RequestURI

	// 1. Anonymous access attempts
	if username == "system:anonymous" {
		threats = append(threats, sender.ThreatIndicator{
			Category:    "unauthorized_access",
			Severity:    "high",
			Description: fmt.Sprintf("Anonymous API access attempt: %s %s", verb, uri),
			SourceIPs:   evt.SourceIPs,
		})
	}

	// 2. Impersonation
	if evt.ImpersonatedUser != nil {
		threats = append(threats, sender.ThreatIndicator{
			Category:    "privilege_escalation",
			Severity:    "critical",
			Description: fmt.Sprintf("User %q impersonating %q", username, evt.ImpersonatedUser.Username),
			SourceIPs:   evt.SourceIPs,
		})
	}

	// 3. Suspicious verbs on sensitive resources
	sensitiveResources := []string{"secrets", "serviceaccounts/token", "clusterrolebindings", "rolebindings"}
	for _, res := range sensitiveResources {
		if strings.Contains(uri, res) && (verb == "create" || verb == "update" || verb == "patch") {
			if !isSystemUser(username) {
				threats = append(threats, sender.ThreatIndicator{
					Category:    "suspicious_api_access",
					Severity:    "high",
					Description: fmt.Sprintf("Sensitive resource manipulation: %s %s %s by %s", verb, res, uri, username),
					SourceIPs:   evt.SourceIPs,
				})
			}
		}
	}

	// 4. exec / port-forward
	if strings.Contains(uri, "/exec") || strings.Contains(uri, "/portforward") {
		if !isSystemUser(username) {
			threats = append(threats, sender.ThreatIndicator{
				Category:    "kubernetes_attack",
				Severity:    "high",
				Description: fmt.Sprintf("Container exec/port-forward by %s: %s", username, uri),
				SourceIPs:   evt.SourceIPs,
			})
		}
	}

	// 5. system:masters group binding
	for _, g := range groups {
		if g == "system:masters" && !isSystemUser(username) {
			threats = append(threats, sender.ThreatIndicator{
				Category:    "privilege_escalation",
				Severity:    "critical",
				Description: fmt.Sprintf("Non-system user %q in system:masters group", username),
				SourceIPs:   evt.SourceIPs,
			})
		}
	}

	// 6. Excessive 403/401 — brute-force API
	if status, ok := evt.ResponseStatus["code"]; ok {
		code := fmt.Sprintf("%v", status)
		if code == "401" || code == "403" {
			threats = append(threats, sender.ThreatIndicator{
				Category:    "brute_force",
				Severity:    "medium",
				Description: fmt.Sprintf("API authorization failure %s for user %s: %s %s", code, username, verb, uri),
				SourceIPs:   evt.SourceIPs,
			})
		}
	}

	for _, t := range threats {
		t.Timestamp = time.Now().UTC()
		t.Source = "audit_log"
		t.NodeName = s.cfg.NodeName
		if err := s.sender.SendSecurityThreat(ctx, t); err != nil {
			s.logger.Warn("failed to send threat", zap.Error(err))
		}
	}
}

// ── RBAC watcher ─────────────────────────────────────────────────────────────

func (s *SecurityThreatCollector) watchRBAC(ctx context.Context) {
	watcher, err := s.client.RbacV1().ClusterRoleBindings().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		s.logger.Warn("Cannot watch ClusterRoleBindings", zap.Error(err))
		return
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			if event.Type == watch.Added || event.Type == watch.Modified {
				crb, ok := event.Object.(*rbacv1.ClusterRoleBinding)
				if !ok {
					continue
				}
				s.analyzeClusterRoleBinding(ctx, crb)
			}
		}
	}
}

func (s *SecurityThreatCollector) analyzeClusterRoleBinding(ctx context.Context, crb *rbacv1.ClusterRoleBinding) {
	dangerousRoles := map[string]bool{
		"cluster-admin": true,
		"system:masters": true,
	}

	if !dangerousRoles[crb.RoleRef.Name] {
		return
	}

	subjects := make([]string, 0, len(crb.Subjects))
	for _, s := range crb.Subjects {
		subjects = append(subjects, fmt.Sprintf("%s/%s", s.Kind, s.Name))
	}

	threat := sender.ThreatIndicator{
		Timestamp:   time.Now().UTC(),
		Category:    "privilege_escalation",
		Severity:    "critical",
		Source:      "rbac_watch",
		NodeName:    s.cfg.NodeName,
		Description: fmt.Sprintf("Dangerous ClusterRoleBinding created/modified: %s binds %v to role %s", crb.Name, subjects, crb.RoleRef.Name),
	}

	if err := s.sender.SendSecurityThreat(ctx, threat); err != nil {
		s.logger.Warn("failed to send rbac threat", zap.Error(err))
	}
}

// ── Privileged pod watcher ───────────────────────────────────────────────────

func (s *SecurityThreatCollector) watchPrivilegedPods(ctx context.Context) {
	ns := s.cfg.Namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}
	watcher, err := s.client.CoreV1().Pods(ns).Watch(ctx, metav1.ListOptions{})
	if err != nil {
		s.logger.Warn("Cannot watch pods for security", zap.Error(err))
		return
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			if event.Type != watch.Added {
				continue
			}
			pod, ok := event.Object.(interface {
				GetNamespace() string
				GetName() string
			})
			if !ok {
				continue
			}

			// Use the raw event object for security checks
			s.analyzePodSecurity(ctx, event)
			_ = pod
		}
	}
}

func (s *SecurityThreatCollector) analyzePodSecurity(ctx context.Context, event watch.Event) {
	// Use unstructured access to avoid import cycle for corev1.Pod
	// Rely on JSON marshaling
	data, err := json.Marshal(event.Object)
	if err != nil {
		return
	}

	var pod struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			HostPID     bool `json:"hostPID"`
			HostNetwork bool `json:"hostNetwork"`
			HostIPC     bool `json:"hostIPC"`
			Containers  []struct {
				Name            string `json:"name"`
				Image           string `json:"image"`
				SecurityContext *struct {
					Privileged             *bool `json:"privileged"`
					AllowPrivilegeEscalation *bool `json:"allowPrivilegeEscalation"`
					RunAsRoot              *bool `json:"runAsRoot"`
				} `json:"securityContext"`
				VolumeMounts []struct {
					MountPath string `json:"mountPath"`
				} `json:"volumeMounts"`
			} `json:"containers"`
			Volumes []struct {
				Name     string `json:"name"`
				HostPath *struct {
					Path string `json:"path"`
				} `json:"hostPath"`
			} `json:"volumes"`
		} `json:"spec"`
	}

	if err := json.Unmarshal(data, &pod); err != nil {
		return
	}

	var threats []string

	if pod.Spec.HostPID {
		threats = append(threats, "hostPID=true (can see host processes)")
	}
	if pod.Spec.HostNetwork {
		threats = append(threats, "hostNetwork=true (shares host network namespace)")
	}
	if pod.Spec.HostIPC {
		threats = append(threats, "hostIPC=true (shares host IPC namespace)")
	}

	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				threats = append(threats, fmt.Sprintf("container %q is privileged", c.Name))
			}
		}
		// Docker socket mount
		for _, vm := range c.VolumeMounts {
			if strings.Contains(vm.MountPath, "docker.sock") || strings.Contains(vm.MountPath, "/var/run/") {
				threats = append(threats, fmt.Sprintf("container %q mounts Docker socket", c.Name))
			}
		}
	}

	// Host path mounts to sensitive directories
	for _, vol := range pod.Spec.Volumes {
		if vol.HostPath != nil {
			sensitiveHostPaths := []string{"/", "/etc", "/proc", "/sys", "/var/run/docker.sock"}
			for _, sp := range sensitiveHostPaths {
				if vol.HostPath.Path == sp {
					threats = append(threats, fmt.Sprintf("hostPath mount to sensitive path: %s", sp))
				}
			}
		}
	}

	if len(threats) == 0 {
		return
	}

	threat := sender.ThreatIndicator{
		Timestamp: time.Now().UTC(),
		Category:  "privileged_workload",
		Severity:  "high",
		Source:    "pod_security_watch",
		NodeName:  s.cfg.NodeName,
		Namespace: pod.Metadata.Namespace,
		PodName:   pod.Metadata.Name,
		Description: fmt.Sprintf(
			"Security violation in pod %s/%s: %s",
			pod.Metadata.Namespace, pod.Metadata.Name,
			strings.Join(threats, "; "),
		),
	}

	if err := s.sender.SendSecurityThreat(ctx, threat); err != nil {
		s.logger.Warn("failed to send pod security threat", zap.Error(err))
	}
}

// ── Network policy watcher ───────────────────────────────────────────────────

func (s *SecurityThreatCollector) watchNetworkPolicies(ctx context.Context) {
	// Periodically check for namespaces with no NetworkPolicy (open namespaces)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	s.checkNetworkPolicies(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkNetworkPolicies(ctx)
		}
	}
}

func (s *SecurityThreatCollector) checkNetworkPolicies(ctx context.Context) {
	namespaces, err := s.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}

	for _, ns := range namespaces.Items {
		// Skip system namespaces
		if isSystemNamespace(ns.Name) {
			continue
		}

		policies, err := s.client.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		if len(policies.Items) == 0 {
			threat := sender.ThreatIndicator{
				Timestamp:   time.Now().UTC(),
				Category:    "network_exposure",
				Severity:    "medium",
				Source:      "network_policy_audit",
				NodeName:    s.cfg.NodeName,
				Namespace:   ns.Name,
				Description: fmt.Sprintf("Namespace %q has no NetworkPolicy — all pod-to-pod traffic is allowed", ns.Name),
			}
			if err := s.sender.SendSecurityThreat(ctx, threat); err != nil {
				s.logger.Warn("failed to send network policy threat", zap.Error(err))
			}
		}
	}
}

// ── Log-line security scanner (called from log collector) ────────────────────

// ScanLogLineForThreats checks a raw log line for attack signatures.
// Returns nil if clean, otherwise a ThreatIndicator to send.
func ScanLogLineForThreats(namespace, pod, container, message string) *sender.ThreatIndicator {
	for _, sig := range threatSignatures {
		if sig.pattern.MatchString(message) {
			return &sender.ThreatIndicator{
				Timestamp:   time.Now().UTC(),
				Category:    sig.category,
				Severity:    sig.severity,
				Source:      "log_scan",
				Namespace:   namespace,
				PodName:     pod,
				Container:   container,
				Description: fmt.Sprintf("[%s] Threat pattern detected in %s/%s: %.200s", sig.category, namespace, pod, message),
				RawLogLine:  message,
			}
		}
	}
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func isSystemUser(username string) bool {
	return strings.HasPrefix(username, "system:") ||
		username == "kubernetes-admin" ||
		username == ""
}

func isSystemNamespace(ns string) bool {
	system := map[string]bool{
		"kube-system":      true,
		"kube-public":      true,
		"kube-node-lease":  true,
		"cert-manager":     true,
		"monitoring":       true,
		"ai-observability": true,
	}
	return system[ns]
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
