"""SQLAlchemy model for cluster health snapshots."""

from datetime import datetime
from sqlalchemy import DateTime, String, Integer, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ClusterHealthSnapshot(Base):
    __tablename__ = "cluster_health_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    node_name: Mapped[str | None] = mapped_column(String(253), nullable=True)

    # Counts
    total_nodes: Mapped[int] = mapped_column(Integer, default=0)
    not_ready_nodes: Mapped[int] = mapped_column(Integer, default=0)
    total_pods: Mapped[int] = mapped_column(Integer, default=0)
    running_pods: Mapped[int] = mapped_column(Integer, default=0)
    pending_pods: Mapped[int] = mapped_column(Integer, default=0)
    failed_pods: Mapped[int] = mapped_column(Integer, default=0)
    crash_loop_pods: Mapped[int] = mapped_column(Integer, default=0)
    total_restarts: Mapped[int] = mapped_column(Integer, default=0)
    unbound_pvcs: Mapped[int] = mapped_column(Integer, default=0)
    degraded_deployments: Mapped[int] = mapped_column(Integer, default=0)

    # Health score (0–100)
    health_score: Mapped[int] = mapped_column(Integer, default=100)

    # Issue details (JSON list of ClusterHealthIssue dicts)
    issues: Mapped[list | None] = mapped_column(JSON, nullable=True)
    summary: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    raw_report: Mapped[dict | None] = mapped_column(JSON, nullable=True)
