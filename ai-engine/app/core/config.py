"""Application configuration loaded from environment variables."""

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── Server ────────────────────────────────────────────────────────────────
    HTTP_PORT: int = 8080
    GRPC_PORT: int = 50051
    CORS_ORIGINS: List[str] = ["*"]
    DASHBOARD_URL: str = "http://localhost:3000"

    # ── Database (PostgreSQL) ─────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/ai_observability"

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── Vector DB ─────────────────────────────────────────────────────────────
    QDRANT_URL: str = "http://localhost:6333"
    QDRANT_COLLECTION: str = "log_embeddings"

    # ── LLM configuration ─────────────────────────────────────────────────────
    LLM_PROVIDER: str = "openai"          # "openai" | "ollama" | "anthropic"
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o"
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    OLLAMA_MODEL: str = "llama3"
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-3-5-sonnet-20241022"

    # ── Anomaly detection ─────────────────────────────────────────────────────
    ANOMALY_SENSITIVITY: float = 0.05
    ANOMALY_WINDOW_MINUTES: int = 15
    MODEL_RETRAIN_INTERVAL_HOURS: int = 24

    # ── Incident prediction ───────────────────────────────────────────────────
    PREDICTION_HORIZON_MINUTES: int = 30
    PREDICTION_THRESHOLD: float = 0.75

    # ── RCA ───────────────────────────────────────────────────────────────────
    RCA_LOG_LOOKBACK_MINUTES: int = 60
    RCA_MAX_LOG_LINES: int = 500

    # ── Alert general ─────────────────────────────────────────────────────────
    ALERT_COOLDOWN_MINUTES: int = 15

    # ─────────────────────────────────────────────────────────────────────────
    # ALERT CHANNELS
    # ─────────────────────────────────────────────────────────────────────────

    # ── Slack ─────────────────────────────────────────────────────────────────
    SLACK_WEBHOOK_URL: Optional[str] = None
    SLACK_CHANNEL: str = "#alerts"

    # ── Microsoft Teams ───────────────────────────────────────────────────────
    TEAMS_WEBHOOK_URL: Optional[str] = None

    # ── Email (SMTP) ──────────────────────────────────────────────────────────
    EMAIL_ENABLED: bool = False
    EMAIL_HOST: str = "smtp.gmail.com"
    EMAIL_PORT: int = 587
    EMAIL_USE_TLS: bool = True        # STARTTLS
    EMAIL_USE_SSL: bool = False       # SSL/TLS on port 465
    EMAIL_USERNAME: Optional[str] = None
    EMAIL_PASSWORD: Optional[str] = None
    EMAIL_FROM_ADDRESS: str = "alerts@ai-observability.local"
    # Comma-separated list of recipient emails
    EMAIL_TO_ADDRESSES: str = ""
    # Optional: separate on-call recipients for critical only
    EMAIL_ONCALL_ADDRESSES: str = ""

    # ── Twilio (SMS + Voice + WhatsApp) ───────────────────────────────────────
    TWILIO_ACCOUNT_SID: Optional[str] = None
    TWILIO_AUTH_TOKEN: Optional[str] = None
    TWILIO_FROM_NUMBER: str = ""          # E.164 e.g. +15551234567

    # SMS — comma-separated E.164 numbers
    SMS_TO_NUMBERS: str = ""              # e.g. "+15559990001,+15559990002"

    # Voice call — comma-separated E.164 numbers (on-call rotation)
    VOICE_CALL_NUMBERS: str = ""          # e.g. "+15559990001"
    # Optional: URL to a hosted TwiML response (overrides built-in twimlet)
    TWILIO_TWIML_URL: Optional[str] = None

    # WhatsApp — comma-separated E.164 numbers (must be WhatsApp-enabled)
    WHATSAPP_TO_NUMBERS: str = ""         # e.g. "+15559990001"
    TWILIO_WHATSAPP_FROM: str = ""        # Twilio WhatsApp sandbox number

    # ── Discord ───────────────────────────────────────────────────────────────
    DISCORD_WEBHOOK_URL: Optional[str] = None

    # ── Telegram ──────────────────────────────────────────────────────────────
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    # Comma-separated chat IDs (user or group)
    TELEGRAM_CHAT_IDS: str = ""           # e.g. "-1001234567890,987654321"

    # ── OpsGenie ──────────────────────────────────────────────────────────────
    OPSGENIE_API_KEY: Optional[str] = None
    # Comma-separated team names for routing
    OPSGENIE_RESPONDERS: str = ""         # e.g. "platform-team,sre-team"

    # ── PagerDuty ─────────────────────────────────────────────────────────────
    PAGERDUTY_ROUTING_KEY: Optional[str] = None
    PAGERDUTY_API_URL: str = "https://events.pagerduty.com/v2/enqueue"

    # ── Generic Webhook ───────────────────────────────────────────────────────
    # Comma-separated URLs that will receive a JSON POST for every alert
    GENERIC_WEBHOOK_URLS: str = ""
    # Optional shared secret sent as X-AI-Obs-Secret header
    GENERIC_WEBHOOK_SECRET: Optional[str] = None

    # ── Security ──────────────────────────────────────────────────────────────
    API_SECRET_KEY: str = "change-me-in-production"
    ENABLE_AUTH: bool = False


settings = Settings()
