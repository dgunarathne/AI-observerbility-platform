"""SQLAlchemy model for sent alerts."""

from datetime import datetime
from sqlalchemy import DateTime, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    incident_id: Mapped[int | None] = mapped_column(nullable=True, index=True)
    channel: Mapped[str] = mapped_column(String(50))   # slack, teams, pagerduty, webhook
    status: Mapped[str] = mapped_column(String(20), default="sent")  # sent, failed, suppressed
    message: Mapped[str] = mapped_column(Text)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    response: Mapped[dict | None] = mapped_column(JSON, nullable=True)
