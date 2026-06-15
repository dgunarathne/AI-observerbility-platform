package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all agent configuration loaded from environment variables.
type Config struct {
	// AI Engine gRPC endpoint
	AIEngineAddress string

	// Kubernetes config
	Namespace          string // empty = all namespaces
	NodeName           string // injected via downward API
	KubeconfigPath     string // empty = in-cluster config

	// Collection settings
	FlushIntervalSeconds int
	BatchSize            int
	LogTailLines         int64

	// Log filtering
	ExcludeNamespaces []string
	IncludeNamespaces []string

	// TLS
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string
}

func Load() (*Config, error) {
	cfg := &Config{
		AIEngineAddress:      getEnv("AI_ENGINE_ADDRESS", "ai-engine-service:50051"),
		Namespace:            getEnv("WATCH_NAMESPACE", ""),
		NodeName:             getEnv("NODE_NAME", ""),
		KubeconfigPath:       getEnv("KUBECONFIG", ""),
		FlushIntervalSeconds: getEnvInt("FLUSH_INTERVAL_SECONDS", 5),
		BatchSize:            getEnvInt("BATCH_SIZE", 100),
		LogTailLines:         int64(getEnvInt("LOG_TAIL_LINES", 100)),
		TLSEnabled:           getEnvBool("TLS_ENABLED", false),
		TLSCertFile:          getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:           getEnv("TLS_KEY_FILE", ""),
		TLSCAFile:            getEnv("TLS_CA_FILE", ""),
	}

	if cfg.AIEngineAddress == "" {
		return nil, fmt.Errorf("AI_ENGINE_ADDRESS is required")
	}

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return defaultVal
}
