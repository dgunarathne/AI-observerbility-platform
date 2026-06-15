package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/ai-observability/agent/internal/config"
	"github.com/ai-observability/agent/internal/sender"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	metricsv1beta1 "k8s.io/metrics/pkg/client/clientset/versioned"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// MetricCollector polls the Kubernetes Metrics API for pod and node resource usage.
type MetricCollector struct {
	cfg           *config.Config
	logger        *zap.Logger
	sender        sender.Sender
	k8sClient     kubernetes.Interface
	metricsClient metricsv1beta1.Interface
}

func NewMetricCollector(cfg *config.Config, logger *zap.Logger, sndr sender.Sender) (*MetricCollector, error) {
	var restCfg *rest.Config
	var err error

	if cfg.KubeconfigPath != "" {
		restCfg, err = clientcmd.BuildConfigFromFlags("", cfg.KubeconfigPath)
	} else {
		restCfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("build rest config: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build k8s client: %w", err)
	}

	metricsClient, err := metricsv1beta1.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build metrics client: %w", err)
	}

	return &MetricCollector{
		cfg:           cfg,
		logger:        logger,
		sender:        sndr,
		k8sClient:     k8sClient,
		metricsClient: metricsClient,
	}, nil
}

func (mc *MetricCollector) Start(ctx context.Context) error {
	mc.logger.Info("Starting metric collector")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Collect immediately on start
	mc.collectMetrics(ctx)

	for {
		select {
		case <-ctx.Done():
			mc.logger.Info("Metric collector stopped")
			return nil
		case <-ticker.C:
			mc.collectMetrics(ctx)
		}
	}
}

func (mc *MetricCollector) collectMetrics(ctx context.Context) {
	namespace := mc.cfg.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	// Collect pod metrics
	podMetrics, err := mc.metricsClient.MetricsV1beta1().PodMetricses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		mc.logger.Warn("failed to get pod metrics", zap.Error(err))
		return
	}

	var metrics []sender.MetricEntry
	ts := time.Now().UTC()

	for _, pm := range podMetrics.Items {
		for _, container := range pm.Containers {
			cpuMillicores := container.Usage.Cpu().MilliValue()
			memBytes := container.Usage.Memory().Value()

			metrics = append(metrics, sender.MetricEntry{
				Timestamp:     ts,
				Namespace:     pm.Namespace,
				PodName:       pm.Name,
				ContainerName: container.Name,
				CPUMillicores: cpuMillicores,
				MemoryBytes:   memBytes,
				NodeName:      mc.cfg.NodeName,
			})
		}
	}

	// Collect node metrics
	nodeMetrics, err := mc.metricsClient.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{})
	if err != nil {
		mc.logger.Warn("failed to get node metrics", zap.Error(err))
	} else {
		for _, nm := range nodeMetrics.Items {
			if nm.Name != mc.cfg.NodeName && mc.cfg.NodeName != "" {
				continue
			}
			cpuMillicores := nm.Usage.Cpu().MilliValue()
			memBytes := nm.Usage.Memory().Value()
			metrics = append(metrics, sender.MetricEntry{
				Timestamp:     ts,
				NodeName:      nm.Name,
				CPUMillicores: cpuMillicores,
				MemoryBytes:   memBytes,
				IsNode:        true,
			})
		}
	}

	if len(metrics) > 0 {
		if err := mc.sender.SendMetrics(ctx, metrics); err != nil {
			mc.logger.Warn("failed to send metrics", zap.Error(err))
		}
	}
}
