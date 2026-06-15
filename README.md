# AI Observability Platform

An AI-powered observability platform that deploys as a Kubernetes agent, analyzes logs in real-time, predicts incidents proactively, performs Root Cause Analysis (RCA), and sends alerts via Slack or other messaging platforms.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                        │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐   ┌───────────────┐  │
│  │  K8s Agent   │───▶│  AI Engine   │──▶│ Alert Manager │  │
│  │ (Log/Metric  │    │  (Predict +  │   │ (Slack/Teams/ │  │
│  │  Collector)  │    │   RCA/LLM)   │   │  PagerDuty)   │  │
│  └──────────────┘    └──────────────┘   └───────────────┘  │
│         │                   │                   │           │
│         ▼                   ▼                   ▼           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              PostgreSQL + Redis + VectorDB           │   │
│  └──────────────────────────────────────────────────────┘   │
│                            │                                 │
│                    ┌───────────────┐                        │
│                    │  REST API +   │                        │
│                    │   Dashboard   │                        │
│                    └───────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| `agent/` | Go | Kubernetes DaemonSet agent - collects logs, metrics, events |
| `ai-engine/` | Python (FastAPI) | ML anomaly detection, incident prediction, LLM-powered RCA |
| `alert-manager/` | Python | Multi-channel alerting (Slack, Teams, PagerDuty, webhooks) |
| `api-server/` | Python (FastAPI) | REST API for dashboard and external integrations |
| `dashboard/` | React + TypeScript | Web UI for incidents, predictions, RCA reports |
| `helm/` | Helm | Kubernetes deployment charts |
| `proto/` | Protobuf | gRPC definitions for agent ↔ backend communication |

## Features

- **Real-time Log Analysis** - Streams logs from all pods, parses structured/unstructured logs
- **Anomaly Detection** - ML-based detection using Isolation Forest + LSTM models
- **Proactive Incident Prediction** - Predicts incidents before they happen using time-series forecasting
- **AI-Powered RCA** - Uses LLM (OpenAI/Ollama) to analyze correlated logs and provide root cause analysis
- **Preventive Action Recommendations** - Suggests actionable fixes based on historical patterns
- **Multi-channel Alerting** - Slack, Microsoft Teams, PagerDuty, email, generic webhooks
- **Kubernetes Native** - Deploys as DaemonSet + Deployment, RBAC-enabled, Helm chart provided

## Quick Start

### Prerequisites
- Kubernetes cluster (1.24+)
- Helm 3+
- OpenAI API key (or Ollama for local LLM)
- Slack webhook URL (optional)

### Install via Helm
```bash
helm repo add ai-observability https://your-repo/charts
helm install ai-obs ./helm/ai-observability \
  --namespace ai-observability \
  --create-namespace \
  --set aiEngine.openaiApiKey=sk-... \
  --set alertManager.slack.webhookUrl=https://hooks.slack.com/...
```

### Local Development
```bash
# Start all services
docker-compose up -d

# Run agent locally (requires kubeconfig)
cd agent && go run ./cmd/agent

# Run AI engine
cd ai-engine && pip install -r requirements.txt && uvicorn main:app --reload
```

## Configuration

See `helm/ai-observability/values.yaml` for all configuration options.

## License

MIT
