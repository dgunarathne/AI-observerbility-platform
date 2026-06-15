"""SQLAlchemy model for persisted log entries."""

from datetime import datetime
from sqlalchemy import DateTime, String, Text, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    namespace: Mapped[str] = mapped_column(String(253), index=True)
    pod_name: Mapped[str] = mapped_column(String(253), index=True)
    container_name: Mapped[str] = mapped_column(String(253))
    node_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    message: Mapped[str] = mapped_column(Text)
    log_level: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    labels: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(nullable=True)
    is_anomaly: Mapped[bool] = mapped_column(default=False, index=True)

    __table_args__ = (
        Index("ix_log_entries_ns_pod_time", "namespace", "pod_name", "timestamp"),
    )
