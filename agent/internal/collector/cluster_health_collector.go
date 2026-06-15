package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/ai-observability/agent/internal/config"
	"github.com/ai-observability/agent/internal/sender"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ClusterHealthCollector polls cluster-wide health indicators every 60 seconds:
//   - Node conditions (Ready, MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable)
//   - PVC binding status
//   - Deployment / StatefulSet / DaemonSet availability
//   - Pod restart counts and CrashLoopBackOff pods
//   - Namespace resource quota saturation
type ClusterHealthCollector struct {
	cfg    *config.Config
	logger *zap.Logger
	sender sender.Sender
	client kubernetes.Interface
}

func NewClusterHealthCollector(cfg *config.Config, logger *zap.Logger, sndr sender.Sender) (*ClusterHealthCollector, error) {
	client, err := buildK8sClient(cfg.KubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("build k8s client: %w", err)
	}
	return &ClusterHealthCollector{
		cfg:    cfg,
		logger: logger,
		sender: sndr,
		client: client,
	}, nil
}

func (c *ClusterHealthCollector) Start(ctx context.Context) error {
	c.logger.Info("Starting cluster health collector")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	c.collect(ctx) // immediate first pass

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Cluster health collector stopped")
			return nil
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

func (c *ClusterHealthCollector) collect(ctx context.Context) {
	report := sender.ClusterHealthReport{
		Timestamp: time.Now().UTC(),
		NodeName:  c.cfg.NodeName,
	}

	// ── Node health ──────────────────────────────────────────────────────────
	nodes, err := c.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.logger.Warn("list nodes failed", zap.Error(err))
	} else {
		for _, node := range nodes.Items {
			ns := sender.NodeStatus{
				Name:   node.Name,
				Ready:  false,
				Conditions: make(map[string]bool),
			}
			for _, cond := range node.Status.Conditions {
				status := cond.Status == corev1.ConditionTrue
				ns.Conditions[string(cond.Type)] = status
				if cond.Type == corev1.NodeReady {
					ns.Ready = status
				}
			}
			// Collect allocatable vs capacity
			if cpu := node.Status.Allocatable.Cpu(); cpu != nil {
				ns.AllocatableCPUMillicores = cpu.MilliValue()
			}
			if mem := node.Status.Allocatable.Memory(); mem != nil {
				ns.AllocatableMemoryBytes = mem.Value()
			}
			report.Nodes = append(report.Nodes, ns)
			if !ns.Ready {
				report.NotReadyNodes++
			}
		}
		report.TotalNodes = len(nodes.Items)
	}

	// ── Pod health ───────────────────────────────────────────────────────────
	ns := c.cfg.Namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	pods, err := c.client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.logger.Warn("list pods failed", zap.Error(err))
	} else {
		report.TotalPods = len(pods.Items)
		for _, pod := range pods.Items {
			switch pod.Status.Phase {
			case corev1.PodRunning:
				report.RunningPods++
			case corev1.PodPending:
				report.PendingPods++
			case corev1.PodFailed:
				report.FailedPods++
			}
			// Restart count & CrashLoopBackOff
			for _, cs := range pod.Status.ContainerStatuses {
				report.TotalRestarts += int(cs.RestartCount)
				if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
					report.CrashLoopPods++
					report.CrashLoopDetails = append(report.CrashLoopDetails, sender.PodRef{
						Namespace:  pod.Namespace,
						Name:       pod.Name,
						Container:  cs.Name,
						Restarts:   int(cs.RestartCount),
					})
				}
			}
		}
	}

	// ── PVC health ───────────────────────────────────────────────────────────
	pvcs, err := c.client.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.logger.Warn("list pvcs failed", zap.Error(err))
	} else {
		report.TotalPVCs = len(pvcs.Items)
		for _, pvc := range pvcs.Items {
			if pvc.Status.Phase == corev1.ClaimBound {
				report.BoundPVCs++
			} else {
				report.UnboundPVCs++
				report.UnboundPVCNames = append(report.UnboundPVCNames, pvc.Namespace+"/"+pvc.Name)
			}
		}
	}

	// ── Deployment health ────────────────────────────────────────────────────
	deployments, err := c.client.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.logger.Warn("list deployments failed", zap.Error(err))
	} else {
		report.TotalDeployments = len(deployments.Items)
		for _, d := range deployments.Items {
			desired := int32(1)
			if d.Spec.Replicas != nil {
				desired = *d.Spec.Replicas
			}
			if d.Status.ReadyReplicas < desired {
				report.DegradedDeployments++
				report.DegradedDeploymentNames = append(
					report.DegradedDeploymentNames,
					fmt.Sprintf("%s/%s (ready %d/%d)", d.Namespace, d.Name, d.Status.ReadyReplicas, desired),
				)
			}
		}
	}

	// ── Namespace resource quota ─────────────────────────────────────────────
	quotas, err := c.client.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.logger.Warn("list resource quotas failed", zap.Error(err))
	} else {
		for _, q := range quotas.Items {
			hard := q.Status.Hard
			used := q.Status.Used
			for resource, hardVal := range hard {
				if usedVal, ok := used[resource]; ok {
					hardMilli := hardVal.MilliValue()
					if hardMilli > 0 {
						saturation := float64(usedVal.MilliValue()) / float64(hardMilli)
						if saturation > 0.85 {
							report.QuotaSaturations = append(report.QuotaSaturations, sender.QuotaSaturation{
								Namespace:   q.Namespace,
								Resource:    string(resource),
								Saturation:  saturation,
								Used:        usedVal.String(),
								Hard:        hardVal.String(),
							})
						}
					}
				}
			}
		}
	}

	if err := c.sender.SendClusterHealth(ctx, report); err != nil {
		c.logger.Warn("failed to send cluster health", zap.Error(err))
	}
}
