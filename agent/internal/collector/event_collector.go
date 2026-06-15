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
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// EventCollector watches Kubernetes events (OOMKill, BackOff, FailedScheduling, etc.)
type EventCollector struct {
	cfg    *config.Config
	logger *zap.Logger
	sender sender.Sender
	client kubernetes.Interface
}

func NewEventCollector(cfg *config.Config, logger *zap.Logger, sndr sender.Sender) (*EventCollector, error) {
	client, err := buildK8sClient(cfg.KubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("build k8s client: %w", err)
	}

	return &EventCollector{
		cfg:    cfg,
		logger: logger,
		sender: sndr,
		client: client,
	}, nil
}

func (ec *EventCollector) Start(ctx context.Context) error {
	ec.logger.Info("Starting event collector")

	namespace := ec.cfg.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	watcher, err := ec.client.CoreV1().Events(namespace).Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch events: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			ec.logger.Info("Event collector stopped")
			return nil
		case event, ok := <-watcher.ResultChan():
			if !ok {
				ec.logger.Warn("Event watch channel closed, restarting...")
				return ec.Start(ctx)
			}
			if event.Type == watch.Added || event.Type == watch.Modified {
				ec.handleEvent(ctx, event.Object.(*corev1.Event))
			}
		}
	}
}

func (ec *EventCollector) handleEvent(ctx context.Context, evt *corev1.Event) {
	// Focus on warning events and important normal events
	if evt.Type == corev1.EventTypeNormal && !isSignificantReason(evt.Reason) {
		return
	}

	entry := sender.EventEntry{
		Timestamp:     evt.LastTimestamp.Time,
		Namespace:     evt.Namespace,
		Name:          evt.Name,
		Reason:        evt.Reason,
		Message:       evt.Message,
		Type:          evt.Type,
		Count:         evt.Count,
		InvolvedObject: sender.InvolvedObject{
			Kind:      evt.InvolvedObject.Kind,
			Name:      evt.InvolvedObject.Name,
			Namespace: evt.InvolvedObject.Namespace,
			UID:       string(evt.InvolvedObject.UID),
		},
		FirstTimestamp: evt.FirstTimestamp.Time,
		NodeName:       ec.cfg.NodeName,
	}

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	if err := ec.sender.SendEvent(ctx, entry); err != nil {
		ec.logger.Warn("failed to send event", zap.Error(err), zap.String("event", evt.Name))
	}
}

// isSignificantReason returns true for event reasons that are worth sending to the AI engine
func isSignificantReason(reason string) bool {
	significant := map[string]bool{
		"Started":             true,
		"Created":             true,
		"Killing":             true,
		"Pulled":              true,
		"Failed":              true,
		"BackOff":             true,
		"OOMKilling":          true,
		"FailedScheduling":    true,
		"Unhealthy":           true,
		"NodeNotReady":        true,
		"Evicted":             true,
		"FailedMount":         true,
		"FailedAttachVolume":  true,
		"FailedCreatePodSandBox": true,
		"NetworkNotReady":     true,
		"Preempting":          true,
		"Rebooted":            true,
	}
	return significant[reason]
}
