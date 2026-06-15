"""SQLAlchemy model for incidents."""

from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import DateTime, String, Text, JSON, Enum
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class IncidentSeverity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, PyEnum):
    PREDICTED = "predicted"   # AI predicted, not yet triggered
    ACTIVE = "active"         # Currently happening
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM, index=True
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus), default=IncidentStatus.ACTIVE, index=True
    )
    namespace: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    pod_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    node_name: Mapped[str | None] = mapped_column(String(253), nullable=True)

    # Timing
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    predicted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # RCA
    rca_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    rca_root_causes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    rca_preventive_actions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    rca_generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Context
    related_log_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    anomaly_scores: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    prediction_confidence: Mapped[float | None] = mapped_column(nullable=True)
    alert_sent: Mapped[bool] = mapped_column(default=False)
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)
