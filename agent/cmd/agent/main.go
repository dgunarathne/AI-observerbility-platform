package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ai-observability/agent/internal/collector"
	"github.com/ai-observability/agent/internal/config"
	"github.com/ai-observability/agent/internal/sender"
	"go.uber.org/zap"
)

func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting AI Observability Agent", zap.String("version", "1.0.0"))

	// Load config
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize gRPC sender to AI engine
	sndr, err := sender.NewGRPCSender(cfg.AIEngineAddress, logger)
	if err != nil {
		logger.Fatal("failed to init gRPC sender", zap.Error(err))
	}
	defer sndr.Close()

	// Initialize collectors
	logCollector, err := collector.NewLogCollector(cfg, logger, sndr)
	if err != nil {
		logger.Fatal("failed to init log collector", zap.Error(err))
	}

	metricCollector, err := collector.NewMetricCollector(cfg, logger, sndr)
	if err != nil {
		logger.Fatal("failed to init metric collector", zap.Error(err))
	}

	eventCollector, err := collector.NewEventCollector(cfg, logger, sndr)
	if err != nil {
		logger.Fatal("failed to init event collector", zap.Error(err))
	}

	appLogAnalyzer, err := collector.NewAppLogAnalyzer(cfg, logger, sndr)
	if err != nil {
		logger.Fatal("failed to init app log analyzer", zap.Error(err))
	}

	clusterHealthCollector, err := collector.NewClusterHealthCollector(cfg, logger, sndr)
	if err != nil {
		logger.Fatal("failed to init cluster health collector", zap.Error(err))
	}

	securityCollector, err := collector.NewSecurityThreatCollector(cfg, logger, sndr)
	if err != nil {
		logger.Fatal("failed to init security threat collector", zap.Error(err))
	}

	// Start collectors
	go func() {
		if err := logCollector.Start(ctx); err != nil {
			logger.Error("log collector error", zap.Error(err))
		}
	}()

	go func() {
		if err := metricCollector.Start(ctx); err != nil {
			logger.Error("metric collector error", zap.Error(err))
		}
	}()

	go func() {
		if err := eventCollector.Start(ctx); err != nil {
			logger.Error("event collector error", zap.Error(err))
		}
	}()

	go func() {
		if err := appLogAnalyzer.Start(ctx); err != nil {
			logger.Error("app log analyzer error", zap.Error(err))
		}
	}()

	go func() {
		if err := clusterHealthCollector.Start(ctx); err != nil {
			logger.Error("cluster health collector error", zap.Error(err))
		}
	}()

	go func() {
		if err := securityCollector.Start(ctx); err != nil {
			logger.Error("security threat collector error", zap.Error(err))
		}
	}()

	logger.Info("Agent running, collecting logs/metrics/events",
		zap.String("ai_engine", cfg.AIEngineAddress),
		zap.Duration("flush_interval", time.Duration(cfg.FlushIntervalSeconds)*time.Second),
	)

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("Shutdown signal received, stopping agent...")
	cancel()
	time.Sleep(2 * time.Second) // Allow goroutines to clean up
	logger.Info("Agent stopped")
}
