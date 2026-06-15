"""SQLAlchemy model for security threat events."""

from datetime import datetime
from sqlalchemy import DateTime, String, Text, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SecurityThreat(Base):
    __tablename__ = "security_threats"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    # Classification
    category: Mapped[str] = mapped_column(String(64), index=True)   # web_attack, brute_force, etc.
    severity: Mapped[str] = mapped_column(String(20), index=True)   # critical | high | medium | low
    source: Mapped[str] = mapped_column(String(64))                 # audit_log | log_scan | rbac_watch | etc.

    # Location
    node_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    namespace: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    pod_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    container: Mapped[str | None] = mapped_column(String(253), nullable=True)

    # Details
    description: Mapped[str] = mapped_column(Text)
    source_ips: Mapped[list | None] = mapped_column(JSON, nullable=True)
    raw_log_line: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Response
    alerted: Mapped[bool] = mapped_column(default=False)
    suppressed: Mapped[bool] = mapped_column(default=False)
    mitigation: Mapped[str | None] = mapped_column(Text, nullable=True)
    incident_id: Mapped[int | None] = mapped_column(nullable=True, index=True)

    __table_args__ = (
        Index("ix_sec_threats_cat_time", "category", "timestamp"),
    )
