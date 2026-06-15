"""Application configuration loaded from environment variables."""

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Server
    HTTP_PORT: int = 8080
    GRPC_PORT: int = 50051
    CORS_ORIGINS: List[str] = ["*"]

    # Database (PostgreSQL)
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/ai_observability"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Vector DB (for log embeddings / semantic search)
    QDRANT_URL: str = "http://localhost:6333"
    QDRANT_COLLECTION: str = "log_embeddings"

    # LLM configuration
    LLM_PROVIDER: str = "openai"          # "openai" | "ollama" | "anthropic"
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o"
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    OLLAMA_MODEL: str = "llama3"
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-3-5-sonnet-20241022"

    # Anomaly detection
    ANOMALY_SENSITIVITY: float = 0.05     # contamination rate for IsolationForest
    ANOMALY_WINDOW_MINUTES: int = 15      # sliding window for LSTM
    MODEL_RETRAIN_INTERVAL_HOURS: int = 24

    # Incident prediction
    PREDICTION_HORIZON_MINUTES: int = 30  # how far ahead to predict
    PREDICTION_THRESHOLD: float = 0.75    # probability threshold for alerting

    # RCA
    RCA_LOG_LOOKBACK_MINUTES: int = 60    # how far back to fetch logs for RCA
    RCA_MAX_LOG_LINES: int = 500          # max log lines to send to LLM

    # Alerting
    SLACK_WEBHOOK_URL: Optional[str] = None
    SLACK_CHANNEL: str = "#alerts"
    TEAMS_WEBHOOK_URL: Optional[str] = None
    PAGERDUTY_ROUTING_KEY: Optional[str] = None
    PAGERDUTY_API_URL: str = "https://events.pagerduty.com/v2/enqueue"
    ALERT_COOLDOWN_MINUTES: int = 15      # suppress duplicate alerts

    # Security
    API_SECRET_KEY: str = "change-me-in-production"
    ENABLE_AUTH: bool = False


settings = Settings()
