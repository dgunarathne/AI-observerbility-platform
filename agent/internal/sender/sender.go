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

// Sender defines the interface for sending collected data to the AI engine.
type Sender interface {
	SendLogs(ctx context.Context, entries []LogEntry) error
	SendMetrics(ctx context.Context, entries []MetricEntry) error
	SendEvent(ctx context.Context, entry EventEntry) error
	Close() error
}
