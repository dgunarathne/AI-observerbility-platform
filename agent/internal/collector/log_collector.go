package collector

import (
	"bufio"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ai-observability/agent/internal/config"
	"github.com/ai-observability/agent/internal/sender"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// LogCollector watches Kubernetes pods and streams their logs to the AI engine.
type LogCollector struct {
	cfg      *config.Config
	logger   *zap.Logger
	sender   sender.Sender
	client   kubernetes.Interface
	mu       sync.Mutex
	watching map[string]context.CancelFunc // podUID -> cancel
}

func NewLogCollector(cfg *config.Config, logger *zap.Logger, sndr sender.Sender) (*LogCollector, error) {
	client, err := buildK8sClient(cfg.KubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("build k8s client: %w", err)
	}

	return &LogCollector{
		cfg:      cfg,
		logger:   logger,
		sender:   sndr,
		client:   client,
		watching: make(map[string]context.CancelFunc),
	}, nil
}

func (lc *LogCollector) Start(ctx context.Context) error {
	lc.logger.Info("Starting log collector")

	namespace := lc.cfg.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	// Watch for pod events
	watcher, err := lc.client.CoreV1().Pods(namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", lc.cfg.NodeName),
	})
	if err != nil {
		return fmt.Errorf("watch pods: %w", err)
	}
	defer watcher.Stop()

	// Also tail logs for all currently running pods
	go lc.tailExistingPods(ctx, namespace)

	for {
		select {
		case <-ctx.Done():
			lc.logger.Info("Log collector stopped")
			return nil
		case event, ok := <-watcher.ResultChan():
			if !ok {
				lc.logger.Warn("Pod watch channel closed, restarting...")
				return lc.Start(ctx) // restart watch
			}
			lc.handlePodEvent(ctx, event)
		}
	}
}

func (lc *LogCollector) tailExistingPods(ctx context.Context, namespace string) {
	pods, err := lc.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", lc.cfg.NodeName),
	})
	if err != nil {
		lc.logger.Error("list existing pods", zap.Error(err))
		return
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodRunning {
			lc.startPodLogStream(ctx, pod)
		}
	}
}

func (lc *LogCollector) handlePodEvent(ctx context.Context, event watch.Event) {
	pod, ok := event.Object.(*corev1.Pod)
	if !ok {
		return
	}

	switch event.Type {
	case watch.Added, watch.Modified:
		if pod.Status.Phase == corev1.PodRunning {
			lc.startPodLogStream(ctx, pod)
		}
	case watch.Deleted:
		lc.stopPodLogStream(string(pod.UID))
	}
}

func (lc *LogCollector) startPodLogStream(ctx context.Context, pod *corev1.Pod) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	uid := string(pod.UID)
	if _, exists := lc.watching[uid]; exists {
		return // already watching
	}

	podCtx, cancel := context.WithCancel(ctx)
	lc.watching[uid] = cancel

	for _, container := range pod.Spec.Containers {
		go lc.streamContainerLogs(podCtx, pod, container.Name)
	}
}

func (lc *LogCollector) stopPodLogStream(uid string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if cancel, exists := lc.watching[uid]; exists {
		cancel()
		delete(lc.watching, uid)
	}
}

func (lc *LogCollector) streamContainerLogs(ctx context.Context, pod *corev1.Pod, containerName string) {
	tailLines := lc.cfg.LogTailLines
	req := lc.client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
		Container: containerName,
		Follow:    true,
		TailLines: &tailLines,
		Timestamps: true,
	})

	stream, err := req.Stream(ctx)
	if err != nil {
		lc.logger.Warn("failed to stream logs",
			zap.String("pod", pod.Name),
			zap.String("container", containerName),
			zap.Error(err),
		)
		return
	}
	defer stream.Close()

	scanner := bufio.NewScanner(stream)
	batch := make([]sender.LogEntry, 0, lc.cfg.BatchSize)
	ticker := time.NewTicker(time.Duration(lc.cfg.FlushIntervalSeconds) * time.Second)
	defer ticker.Stop()

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		if err := lc.sender.SendLogs(ctx, batch); err != nil {
			lc.logger.Warn("failed to send log batch", zap.Error(err))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flushBatch()
			return
		case <-ticker.C:
			flushBatch()
		default:
			if scanner.Scan() {
				line := scanner.Text()
				entry := sender.LogEntry{
					Timestamp:     time.Now().UTC(),
					Namespace:     pod.Namespace,
					PodName:       pod.Name,
					ContainerName: containerName,
					NodeName:      pod.Spec.NodeName,
					Message:       line,
					Labels:        pod.Labels,
				}
				batch = append(batch, entry)

				// Security: scan every log line for attack patterns
				if threat := ScanLogLineForThreats(pod.Namespace, pod.Name, containerName, line); threat != nil {
					threat.NodeName = pod.Spec.NodeName
					if err := lc.sender.SendSecurityThreat(ctx, *threat); err != nil {
						lc.logger.Warn("failed to send log threat", zap.Error(err))
					}
				}

				if len(batch) >= lc.cfg.BatchSize {
					flushBatch()
				}
			} else {
				if err := scanner.Err(); err != nil {
					lc.logger.Warn("log scanner error", zap.Error(err))
				}
				return
			}
		}
	}
}

func buildK8sClient(kubeconfigPath string) (kubernetes.Interface, error) {
	var restCfg *rest.Config
	var err error

	if kubeconfigPath != "" {
		restCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		restCfg, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, fmt.Errorf("build rest config: %w", err)
	}

	return kubernetes.NewForConfig(restCfg)
}
