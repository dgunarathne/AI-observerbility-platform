package collector

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ai-observability/agent/internal/config"
	"github.com/ai-observability/agent/internal/sender"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AppLogSignal tracks rolling statistics per application (namespace/service).
type AppLogSignal struct {
	mu             sync.Mutex
	windowStart    time.Time
	totalLines     int64
	errorLines     int64
	warnLines      int64
	http5xxCount   int64
	http4xxCount   int64
	exceptionCount int64
	latencySumMs   float64
	latencyCount   int64
	exceptionTypes map[string]int // exception class → count
}

func newAppLogSignal() *AppLogSignal {
	return &AppLogSignal{
		windowStart:    time.Now(),
		exceptionTypes: make(map[string]int),
	}
}

// Compiled patterns for common application log formats.
var (
	// HTTP access log patterns (nginx, envoy, apache, spring)
	reHTTPStatus    = regexp.MustCompile(`\b([1-5]\d{2})\b`)
	reHTTPLatencyMs = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)\s*ms`)
	reHTTPLatencySec = regexp.MustCompile(`(?i)rt=(\d+\.\d+)`)

	// Error level patterns
	reLogLevel = regexp.MustCompile(
		`(?i)\b(CRITICAL|FATAL|ERROR|ERRO|WARN|WARNING|INFO|DEBUG|TRACE)\b`,
	)

	// Exception / stack trace patterns
	reException = regexp.MustCompile(
		`(?i)(Exception|Error|Panic|FATAL):\s*(.{0,120})`,
	)
	reJavaException = regexp.MustCompile(
		`([a-zA-Z_$][a-zA-Z\d_$]*\.)+[A-Z][a-zA-Z\d_$]*(Exception|Error)\b`,
	)
	rePythonTraceback = regexp.MustCompile(`Traceback \(most recent call last\)`)
	reGoRuntimePanic  = regexp.MustCompile(`goroutine \d+ \[`)

	// Latency / response time patterns
	reResponseTime = regexp.MustCompile(
		`(?i)(?:duration|elapsed|latency|response.?time)[=:\s]+(\d+(?:\.\d+)?)\s*(ms|s|µs)?`,
	)
)

// AppLogAnalyzer periodically sends per-app health signals to the AI engine.
type AppLogAnalyzer struct {
	cfg     *config.Config
	logger  *zap.Logger
	sender  sender.Sender
	client  kubernetes.Interface
	mu      sync.Mutex
	signals map[string]*AppLogSignal // "namespace/app-label" → signal
}

func NewAppLogAnalyzer(cfg *config.Config, logger *zap.Logger, sndr sender.Sender) (*AppLogAnalyzer, error) {
	client, err := buildK8sClient(cfg.KubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("build k8s client: %w", err)
	}
	return &AppLogAnalyzer{
		cfg:     cfg,
		logger:  logger,
		sender:  sndr,
		client:  client,
		signals: make(map[string]*AppLogSignal),
	}, nil
}

// RecordLogLine is called by the log collector for every log line; it updates
// per-app statistics without sending anything (flush happens on a timer).
func (a *AppLogAnalyzer) RecordLogLine(namespace, appLabel, message string) {
	key := namespace + "/" + appLabel
	a.mu.Lock()
	sig, ok := a.signals[key]
	if !ok {
		sig = newAppLogSignal()
		a.signals[key] = sig
	}
	a.mu.Unlock()

	sig.mu.Lock()
	defer sig.mu.Unlock()

	sig.totalLines++

	// Log level
	if m := reLogLevel.FindString(message); m != "" {
		upper := strings.ToUpper(m)
		switch upper {
		case "ERROR", "ERRO", "CRITICAL", "FATAL":
			sig.errorLines++
		case "WARN", "WARNING":
			sig.warnLines++
		}
	}

	// HTTP status codes
	if matches := reHTTPStatus.FindAllString(message, -1); len(matches) > 0 {
		for _, code := range matches {
			if len(code) == 3 {
				if code[0] == '5' {
					sig.http5xxCount++
				} else if code[0] == '4' {
					sig.http4xxCount++
				}
			}
		}
	}

	// Latency extraction (ms preferred, seconds converted)
	if m := reResponseTime.FindStringSubmatch(message); len(m) >= 3 {
		if val, err := strconv.ParseFloat(m[1], 64); err == nil {
			unit := strings.ToLower(m[2])
			ms := val
			if unit == "s" {
				ms = val * 1000
			} else if unit == "µs" {
				ms = val / 1000
			}
			sig.latencySumMs += ms
			sig.latencyCount++
		}
	} else if m := reHTTPLatencyMs.FindStringSubmatch(message); len(m) >= 2 {
		if val, err := strconv.ParseFloat(m[1], 64); err == nil {
			sig.latencySumMs += val
			sig.latencyCount++
		}
	}

	// Exception detection
	if rePythonTraceback.MatchString(message) || reGoRuntimePanic.MatchString(message) {
		sig.exceptionCount++
		sig.exceptionTypes["runtime_panic"]++
	} else if m := reJavaException.FindString(message); m != "" {
		sig.exceptionCount++
		sig.exceptionTypes[m]++
	} else if m := reException.FindStringSubmatch(message); len(m) >= 2 {
		sig.exceptionCount++
		sig.exceptionTypes[m[1]]++
	}
}

// Start flushes per-app health signals to the AI engine every 60 seconds.
func (a *AppLogAnalyzer) Start(ctx context.Context) error {
	a.logger.Info("Starting app log analyzer (flush interval: 60s)")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			a.flushSignals(ctx)
		}
	}
}

func (a *AppLogAnalyzer) flushSignals(ctx context.Context) {
	a.mu.Lock()
	// Snapshot and reset signals
	snapshot := make(map[string]*AppLogSignal, len(a.signals))
	for k, v := range a.signals {
		snapshot[k] = v
		a.signals[k] = newAppLogSignal()
	}
	a.mu.Unlock()

	var reports []sender.AppHealthReport
	now := time.Now().UTC()

	for key, sig := range snapshot {
		sig.mu.Lock()
		if sig.totalLines == 0 {
			sig.mu.Unlock()
			continue
		}
		parts := strings.SplitN(key, "/", 2)
		ns := parts[0]
		app := ""
		if len(parts) > 1 {
			app = parts[1]
		}

		windowDur := now.Sub(sig.windowStart).Seconds()
		if windowDur <= 0 {
			windowDur = 60
		}

		var avgLatencyMs float64
		if sig.latencyCount > 0 {
			avgLatencyMs = sig.latencySumMs / float64(sig.latencyCount)
		}

		errorRate := 0.0
		if sig.totalLines > 0 {
			errorRate = float64(sig.errorLines) / float64(sig.totalLines)
		}
		http5xxRate := 0.0
		httpTotal := sig.http5xxCount + sig.http4xxCount
		if httpTotal > 0 {
			http5xxRate = float64(sig.http5xxCount) / float64(httpTotal)
		}

		// Clone exception map
		exTypes := make(map[string]int, len(sig.exceptionTypes))
		for k, v := range sig.exceptionTypes {
			exTypes[k] = v
		}
		sig.mu.Unlock()

		reports = append(reports, sender.AppHealthReport{
			Timestamp:         now,
			Namespace:         ns,
			AppLabel:          app,
			NodeName:          a.cfg.NodeName,
			WindowSeconds:     int(windowDur),
			TotalLogLines:     sig.totalLines,
			ErrorLines:        sig.errorLines,
			WarnLines:         sig.warnLines,
			ErrorRate:         errorRate,
			HTTP5xxCount:      sig.http5xxCount,
			HTTP4xxCount:      sig.http4xxCount,
			HTTP5xxRate:       http5xxRate,
			ExceptionCount:    sig.exceptionCount,
			ExceptionTypes:    exTypes,
			AvgLatencyMs:      avgLatencyMs,
			LatencySamples:    sig.latencyCount,
		})
	}

	if len(reports) > 0 {
		if err := a.sender.SendAppHealthReports(ctx, reports); err != nil {
			a.logger.Warn("failed to send app health reports", zap.Error(err))
		}
	}
}
