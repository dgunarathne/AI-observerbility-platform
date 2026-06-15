"""FastAPI router - exposes incidents, RCA, logs, and metrics endpoints."""

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.log_entry import LogEntry
from app.models.metric_snapshot import MetricSnapshot
from app.services.rca_engine import RCAEngine

router = APIRouter()


# ─── Schemas ────────────────────────────────────────────────────────────────

class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    namespace: Optional[str]
    pod_name: Optional[str]
    node_name: Optional[str]
    detected_at: datetime
    predicted_at: Optional[datetime]
    resolved_at: Optional[datetime]
    rca_summary: Optional[str]
    rca_root_causes: Optional[list]
    rca_preventive_actions: Optional[list]
    prediction_confidence: Optional[float]

    class Config:
        from_attributes = True


class RCARequest(BaseModel):
    incident_id: int


class ResolveRequest(BaseModel):
    incident_id: int


# ─── Incidents ───────────────────────────────────────────────────────────────

@router.get("/incidents", response_model=List[IncidentResponse])
async def list_incidents(
    db: AsyncSession = Depends(get_db),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    namespace: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
):
    """List incidents with optional filtering."""
    q = select(Incident).order_by(desc(Incident.detected_at))

    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)
    if namespace:
        q = q.where(Incident.namespace == namespace)

    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: int, db: AsyncSession = Depends(get_db)):
    incident = await db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: int, db: AsyncSession = Depends(get_db)):
    incident = await db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = IncidentStatus.RESOLVED
    incident.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": "Incident resolved", "incident_id": incident_id}


@router.post("/incidents/{incident_id}/rca")
async def trigger_rca(incident_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Manually trigger RCA for an incident."""
    incident = await db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    rca_engine: RCAEngine = request.app.state.rca_engine

    # Fetch related logs
    from app.core.config import settings
    from datetime import timedelta

    lookback = incident.detected_at - timedelta(minutes=settings.RCA_LOG_LOOKBACK_MINUTES)
    result = await db.execute(
        select(LogEntry)
        .where(LogEntry.namespace == incident.namespace)
        .where(LogEntry.pod_name == incident.pod_name)
        .where(LogEntry.timestamp >= lookback)
        .where(LogEntry.timestamp <= incident.detected_at)
        .order_by(desc(LogEntry.timestamp))
        .limit(settings.RCA_MAX_LOG_LINES)
    )
    log_rows = result.scalars().all()
    logs = [
        {
            "timestamp": str(row.timestamp),
            "namespace": row.namespace,
            "pod_name": row.pod_name,
            "container_name": row.container_name,
            "message": row.message,
        }
        for row in log_rows
    ]

    rca = await rca_engine.generate_rca(
        incident_title=incident.title,
        incident_description=incident.description,
        logs=logs,
        events=[],
    )

    incident.rca_summary = rca.get("summary", "")
    incident.rca_root_causes = rca.get("root_causes", [])
    incident.rca_preventive_actions = rca.get("preventive_actions", [])
    incident.rca_generated_at = datetime.now(timezone.utc)
    await db.commit()

    return rca


# ─── Logs ────────────────────────────────────────────────────────────────────

@router.get("/logs")
async def get_logs(
    db: AsyncSession = Depends(get_db),
    namespace: Optional[str] = Query(None),
    pod_name: Optional[str] = Query(None),
    anomalies_only: bool = Query(False),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
):
    q = select(LogEntry).order_by(desc(LogEntry.timestamp))
    if namespace:
        q = q.where(LogEntry.namespace == namespace)
    if pod_name:
        q = q.where(LogEntry.pod_name == pod_name)
    if anomalies_only:
        q = q.where(LogEntry.is_anomaly == True)  # noqa: E712
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp,
            "namespace": r.namespace,
            "pod_name": r.pod_name,
            "container_name": r.container_name,
            "message": r.message,
            "anomaly_score": r.anomaly_score,
            "is_anomaly": r.is_anomaly,
        }
        for r in rows
    ]


# ─── Metrics ─────────────────────────────────────────────────────────────────

@router.get("/metrics")
async def get_metrics(
    db: AsyncSession = Depends(get_db),
    namespace: Optional[str] = Query(None),
    pod_name: Optional[str] = Query(None),
    limit: int = Query(200, le=2000),
):
    q = select(MetricSnapshot).order_by(desc(MetricSnapshot.timestamp))
    if namespace:
        q = q.where(MetricSnapshot.namespace == namespace)
    if pod_name:
        q = q.where(MetricSnapshot.pod_name == pod_name)
    q = q.limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        {
            "timestamp": r.timestamp,
            "namespace": r.namespace,
            "pod_name": r.pod_name,
            "container_name": r.container_name,
            "node_name": r.node_name,
            "cpu_millicores": r.cpu_millicores,
            "memory_mb": round(r.memory_bytes / (1024 * 1024), 2),
        }
        for r in rows
    ]


# ─── Stats ───────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Dashboard summary statistics."""
    from sqlalchemy import func

    total_incidents = await db.scalar(select(func.count(Incident.id)))
    active_incidents = await db.scalar(
        select(func.count(Incident.id)).where(Incident.status == IncidentStatus.ACTIVE)
    )
    predicted_incidents = await db.scalar(
        select(func.count(Incident.id)).where(Incident.status == IncidentStatus.PREDICTED)
    )
    total_anomalies = await db.scalar(
        select(func.count(LogEntry.id)).where(LogEntry.is_anomaly == True)  # noqa: E712
    )

    return {
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "predicted_incidents": predicted_incidents,
        "total_anomalies": total_anomalies,
    }
