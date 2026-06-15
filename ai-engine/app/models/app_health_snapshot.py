"""SQLAlchemy model for per-app health snapshots."""

from datetime import datetime
from sqlalchemy import DateTime, String, Integer, Float, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AppHealthSnapshot(Base):
    __tablename__ = "app_health_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    namespace: Mapped[str] = mapped_column(String(253), index=True)
    app_label: Mapped[str] = mapped_column(String(253), index=True)
    node_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    window_seconds: Mapped[int] = mapped_column(Integer, default=60)

    # Log stats
    total_log_lines: Mapped[int] = mapped_column(Integer, default=0)
    error_lines: Mapped[int] = mapped_column(Integer, default=0)
    warn_lines: Mapped[int] = mapped_column(Integer, default=0)
    error_rate: Mapped[float] = mapped_column(Float, default=0.0)

    # HTTP stats
    http_5xx_count: Mapped[int] = mapped_column(Integer, default=0)
    http_4xx_count: Mapped[int] = mapped_column(Integer, default=0)
    http_5xx_rate: Mapped[float] = mapped_column(Float, default=0.0)

    # Exceptions
    exception_count: Mapped[int] = mapped_column(Integer, default=0)
    exception_types: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Performance
    avg_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    latency_samples: Mapped[int] = mapped_column(Integer, default=0)

    # Anomaly
    is_anomaly: Mapped[bool] = mapped_column(default=False, index=True)
    anomalies: Mapped[list | None] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_app_health_ns_app_time", "namespace", "app_label", "timestamp"),
    )
