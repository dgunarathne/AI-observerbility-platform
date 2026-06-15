"""SQLAlchemy model for metric snapshots."""

from datetime import datetime
from sqlalchemy import DateTime, String, BigInteger, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    namespace: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    pod_name: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    container_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    node_name: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    cpu_millicores: Mapped[int] = mapped_column(BigInteger, default=0)
    memory_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    is_node: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        Index("ix_metric_ns_pod_time", "namespace", "pod_name", "timestamp"),
    )
