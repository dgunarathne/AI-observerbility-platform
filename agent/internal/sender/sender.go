package sender

import (
	"context"
	"time"
)

// LogEntry represents a single log line from a container.
type LogEntry struct {
	Timestamp     time.Time         `json:"timestamp"`
	Namespace     string            `json:"namespace"`
	PodName       string            `json:"pod_name"`
	ContainerName string            `json:"container_name"`
	NodeName      string            `json:"node_name"`
	Message       string            `json:"message"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// MetricEntry represents a point-in-time resource metric.
type MetricEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	Namespace     string    `json:"namespace,omitempty"`
	PodName       string    `json:"pod_name,omitempty"`
	ContainerName string    `json:"container_name,omitempty"`
	NodeName      string    `json:"node_name,omitempty"`
	CPUMillicores int64     `json:"cpu_millicores"`
	MemoryBytes   int64     `json:"memory_bytes"`
	IsNode        bool      `json:"is_node,omitempty"`
}

// InvolvedObject is the K8s resource involved in an event.
type InvolvedObject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid"`
}

// EventEntry represents a Kubernetes event.
type EventEntry struct {
	Timestamp      time.Time      `json:"timestamp"`
	FirstTimestamp time.Time      `json:"first_timestamp"`
	Namespace      string         `json:"namespace"`
	Name           string         `json:"name"`
	Reason         string         `json:"reason"`
	Message        string         `json:"message"`
	Type           string         `json:"type"` // Normal or Warning
	Count          int32          `json:"count"`
	InvolvedObject InvolvedObject `json:"involved_object"`
	NodeName       string         `json:"node_name"`
}

// AppHealthReport is a per-app aggregated log health summary (60s window).
type AppHealthReport struct {
	Timestamp      time.Time      `json:"timestamp"`
	Namespace      string         `json:"namespace"`
	AppLabel       string         `json:"app_label"`
	NodeName       string         `json:"node_name"`
	WindowSeconds  int            `json:"window_seconds"`
	TotalLogLines  int64          `json:"total_log_lines"`
	ErrorLines     int64          `json:"error_lines"`
	WarnLines      int64          `json:"warn_lines"`
	ErrorRate      float64        `json:"error_rate"`
	HTTP5xxCount   int64          `json:"http_5xx_count"`
	HTTP4xxCount   int64          `json:"http_4xx_count"`
	HTTP5xxRate    float64        `json:"http_5xx_rate"`
	ExceptionCount int64          `json:"exception_count"`
	ExceptionTypes map[string]int `json:"exception_types,omitempty"`
	AvgLatencyMs   float64        `json:"avg_latency_ms"`
	LatencySamples int64          `json:"latency_samples"`
}

// NodeStatus holds health conditions for a single node.
type NodeStatus struct {
	Name                     string          `json:"name"`
	Ready                    bool            `json:"ready"`
	Conditions               map[string]bool `json:"conditions"`
	AllocatableCPUMillicores int64           `json:"allocatable_cpu_millicores"`
	AllocatableMemoryBytes   int64           `json:"allocatable_memory_bytes"`
}

// PodRef is a lightweight reference to a pod with restart count.
type PodRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Container string `json:"container"`
	Restarts  int    `json:"restarts"`
}

// QuotaSaturation reports a namespace resource quota at >85% usage.
type QuotaSaturation struct {
	Namespace  string  `json:"namespace"`
	Resource   string  `json:"resource"`
	Saturation float64 `json:"saturation"`
	Used       string  `json:"used"`
	Hard       string  `json:"hard"`
}

// ClusterHealthReport is a snapshot of cluster-wide health.
type ClusterHealthReport struct {
	Timestamp               time.Time         `json:"timestamp"`
	NodeName                string            `json:"node_name"`
	TotalNodes              int               `json:"total_nodes"`
	NotReadyNodes           int               `json:"not_ready_nodes"`
	Nodes                   []NodeStatus      `json:"nodes"`
	TotalPods               int               `json:"total_pods"`
	RunningPods             int               `json:"running_pods"`
	PendingPods             int               `json:"pending_pods"`
	FailedPods              int               `json:"failed_pods"`
	CrashLoopPods           int               `json:"crash_loop_pods"`
	CrashLoopDetails        []PodRef          `json:"crash_loop_details,omitempty"`
	TotalRestarts           int               `json:"total_restarts"`
	TotalPVCs               int               `json:"total_pvcs"`
	BoundPVCs               int               `json:"bound_pvcs"`
	UnboundPVCs             int               `json:"unbound_pvcs"`
	UnboundPVCNames         []string          `json:"unbound_pvc_names,omitempty"`
	TotalDeployments        int               `json:"total_deployments"`
	DegradedDeployments     int               `json:"degraded_deployments"`
	DegradedDeploymentNames []string          `json:"degraded_deployment_names,omitempty"`
	QuotaSaturations        []QuotaSaturation `json:"quota_saturations,omitempty"`
}

// ThreatIndicator represents a detected or suspected security threat.
type ThreatIndicator struct {
	Timestamp   time.Time `json:"timestamp"`
	Category    string    `json:"category"`   // web_attack | brute_force | privilege_escalation | etc.
	Severity    string    `json:"severity"`   // critical | high | medium | low
	Source      string    `json:"source"`     // audit_log | log_scan | rbac_watch | pod_security_watch
	NodeName    string    `json:"node_name"`
	Namespace   string    `json:"namespace,omitempty"`
	PodName     string    `json:"pod_name,omitempty"`
	Container   string    `json:"container,omitempty"`
	SourceIPs   []string  `json:"source_ips,omitempty"`
	Description string    `json:"description"`
	RawLogLine  string    `json:"raw_log_line,omitempty"`
}

// Sender defines the interface for sending collected data to the AI engine.
type Sender interface {
	SendLogs(ctx context.Context, entries []LogEntry) error
	SendMetrics(ctx context.Context, entries []MetricEntry) error
	SendEvent(ctx context.Context, entry EventEntry) error
	SendAppHealthReports(ctx context.Context, reports []AppHealthReport) error
	SendClusterHealth(ctx context.Context, report ClusterHealthReport) error
	SendSecurityThreat(ctx context.Context, threat ThreatIndicator) error
	Close() error
}
