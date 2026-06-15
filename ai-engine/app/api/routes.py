"""FastAPI router - exposes incidents, RCA, logs, metrics, security, cluster health, and app health endpoints."""

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import desc, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentType
from app.models.log_entry import LogEntry
from app.models.metric_snapshot import MetricSnapshot
from app.models.security_threat import SecurityThreat
from app.models.cluster_health_snapshot import ClusterHealthSnapshot
from app.models.app_health_snapshot import AppHealthSnapshot
from app.services.rca_engine import RCAEngine

router = APIRouter()


# ─── Schemas ────────────────────────────────────────────────────────────────

class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    incident_type: str
    threat_category: Optional[str]
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
    """Dashboard summary statistics covering all domains."""
    total_incidents = await db.scalar(select(func.count(Incident.id)))
    active_incidents = await db.scalar(
        select(func.count(Incident.id)).where(Incident.status == IncidentStatus.ACTIVE)
    )
    predicted_incidents = await db.scalar(
        select(func.count(Incident.id)).where(Incident.status == IncidentStatus.PREDICTED)
    )
    security_incidents = await db.scalar(
        select(func.count(Incident.id)).where(Incident.incident_type == IncidentType.SECURITY_THREAT)
        .where(Incident.status == IncidentStatus.ACTIVE)
    )
    total_anomalies = await db.scalar(
        select(func.count(LogEntry.id)).where(LogEntry.is_anomaly == True)  # noqa: E712
    )
    total_threats = await db.scalar(select(func.count(SecurityThreat.id)))
    critical_threats = await db.scalar(
        select(func.count(SecurityThreat.id)).where(SecurityThreat.severity == "critical")
    )

    # Latest cluster health score
    latest_health = await db.execute(
        select(ClusterHealthSnapshot.health_score)
        .order_by(desc(ClusterHealthSnapshot.timestamp))
        .limit(1)
    )
    health_score = latest_health.scalar_one_or_none()

    app_anomalies = await db.scalar(
        select(func.count(AppHealthSnapshot.id)).where(AppHealthSnapshot.is_anomaly == True)  # noqa: E712
    )

    return {
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "predicted_incidents": predicted_incidents,
        "security_incidents": security_incidents,
        "total_anomalies": total_anomalies,
        "total_security_threats": total_threats,
        "critical_security_threats": critical_threats,
        "cluster_health_score": health_score,
        "app_anomalies": app_anomalies,
    }


# ─── Security Threats ────────────────────────────────────────────────────────

@router.get("/security/threats")
async def list_security_threats(
    db: AsyncSession = Depends(get_db),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    namespace: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
):
    """List security threats with optional filters."""
    q = select(SecurityThreat).order_by(desc(SecurityThreat.timestamp))
    if category:
        q = q.where(SecurityThreat.category == category)
    if severity:
        q = q.where(SecurityThreat.severity == severity)
    if namespace:
        q = q.where(SecurityThreat.namespace == namespace)
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp,
            "category": r.category,
            "severity": r.severity,
            "source": r.source,
            "namespace": r.namespace,
            "pod_name": r.pod_name,
            "description": r.description,
            "source_ips": r.source_ips,
            "mitigation": r.mitigation,
            "incident_id": r.incident_id,
            "alerted": r.alerted,
        }
        for r in rows
    ]


@router.get("/security/stats")
async def security_stats(db: AsyncSession = Depends(get_db)):
    """Security threat statistics for the dashboard."""
    total = await db.scalar(select(func.count(SecurityThreat.id)))
    critical = await db.scalar(
        select(func.count(SecurityThreat.id)).where(SecurityThreat.severity == "critical")
    )
    high = await db.scalar(
        select(func.count(SecurityThreat.id)).where(SecurityThreat.severity == "high")
    )
    # Category breakdown
    cat_result = await db.execute(
        select(SecurityThreat.category, func.count(SecurityThreat.id).label("count"))
        .group_by(SecurityThreat.category)
        .order_by(desc("count"))
        .limit(10)
    )
    categories = [{"category": row.category, "count": row.count} for row in cat_result]

    return {
        "total_threats": total,
        "critical": critical,
        "high": high,
        "top_categories": categories,
    }


@router.get("/security/correlation")
async def security_correlation(request: Request):
    """Real-time threat correlation data from the security detector."""
    detector = request.app.state.security_threat_detector
    return detector.get_threat_summary()


# ─── Cluster Health ───────────────────────────────────────────────────────────

@router.get("/cluster/health")
async def cluster_health_history(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, le=200),
):
    """Recent cluster health snapshots (time series for dashboard)."""
    result = await db.execute(
        select(ClusterHealthSnapshot)
        .order_by(desc(ClusterHealthSnapshot.timestamp))
        .limit(limit)
    )
    rows = result.scalars().all()
    return [
        {
            "timestamp": r.timestamp,
            "health_score": r.health_score,
            "total_nodes": r.total_nodes,
            "not_ready_nodes": r.not_ready_nodes,
            "total_pods": r.total_pods,
            "running_pods": r.running_pods,
            "pending_pods": r.pending_pods,
            "failed_pods": r.failed_pods,
            "crash_loop_pods": r.crash_loop_pods,
            "unbound_pvcs": r.unbound_pvcs,
            "degraded_deployments": r.degraded_deployments,
            "summary": r.summary,
            "issues": r.issues or [],
        }
        for r in rows
    ]


@router.get("/cluster/health/latest")
async def cluster_health_latest(db: AsyncSession = Depends(get_db)):
    """Most recent cluster health snapshot."""
    result = await db.execute(
        select(ClusterHealthSnapshot)
        .order_by(desc(ClusterHealthSnapshot.timestamp))
        .limit(1)
    )
    row = result.scalar_one_or_none()
    if not row:
        return {"message": "No cluster health data yet"}
    return {
        "timestamp": row.timestamp,
        "health_score": row.health_score,
        "summary": row.summary,
        "issues": row.issues or [],
        "total_nodes": row.total_nodes,
        "not_ready_nodes": row.not_ready_nodes,
        "running_pods": row.running_pods,
        "total_pods": row.total_pods,
        "crash_loop_pods": row.crash_loop_pods,
        "degraded_deployments": row.degraded_deployments,
        "unbound_pvcs": row.unbound_pvcs,
    }


# ─── App Health ───────────────────────────────────────────────────────────────

@router.get("/apps/health")
async def app_health_list(
    db: AsyncSession = Depends(get_db),
    namespace: Optional[str] = Query(None),
    app_label: Optional[str] = Query(None),
    anomalies_only: bool = Query(False),
    limit: int = Query(100, le=500),
):
    """Per-app health snapshots."""
    q = select(AppHealthSnapshot).order_by(desc(AppHealthSnapshot.timestamp))
    if namespace:
        q = q.where(AppHealthSnapshot.namespace == namespace)
    if app_label:
        q = q.where(AppHealthSnapshot.app_label == app_label)
    if anomalies_only:
        q = q.where(AppHealthSnapshot.is_anomaly == True)  # noqa: E712
    q = q.limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp,
            "namespace": r.namespace,
            "app_label": r.app_label,
            "error_rate": r.error_rate,
            "http_5xx_count": r.http_5xx_count,
            "http_5xx_rate": r.http_5xx_rate,
            "exception_count": r.exception_count,
            "avg_latency_ms": r.avg_latency_ms,
            "total_log_lines": r.total_log_lines,
            "is_anomaly": r.is_anomaly,
            "anomalies": r.anomalies or [],
        }
        for r in rows
    ]


@router.get("/apps/baselines")
async def app_baselines(request: Request):
    """Current learned baselines per app from the app log analyzer."""
    analyzer = request.app.state.app_log_analyzer
    return analyzer.get_baselines_summary()


@router.get("/alerts/channels")
async def list_alert_channels():
    """Return which alert channels are configured (for dashboard and demo runner)."""
    from app.core.config import settings as cfg
    channels = [
        {"name": "Slack",        "enabled": bool(cfg.SLACK_WEBHOOK_URL)},
        {"name": "Teams",        "enabled": bool(cfg.TEAMS_WEBHOOK_URL)},
        {"name": "Email",        "enabled": cfg.EMAIL_ENABLED and bool(cfg.EMAIL_TO_ADDRESSES)},
        {"name": "SMS (Twilio)", "enabled": bool(cfg.TWILIO_ACCOUNT_SID and cfg.SMS_TO_NUMBERS)},
        {"name": "Voice Call",   "enabled": bool(cfg.TWILIO_ACCOUNT_SID and cfg.VOICE_CALL_NUMBERS)},
        {"name": "WhatsApp",     "enabled": bool(cfg.TWILIO_ACCOUNT_SID and cfg.WHATSAPP_TO_NUMBERS)},
        {"name": "Discord",      "enabled": bool(cfg.DISCORD_WEBHOOK_URL)},
        {"name": "Telegram",     "enabled": bool(cfg.TELEGRAM_BOT_TOKEN and cfg.TELEGRAM_CHAT_IDS)},
        {"name": "OpsGenie",     "enabled": bool(cfg.OPSGENIE_API_KEY)},
        {"name": "PagerDuty",    "enabled": bool(cfg.PAGERDUTY_ROUTING_KEY)},
        {"name": "Webhook",      "enabled": bool(cfg.GENERIC_WEBHOOK_URLS)},
    ]
    return channels(db: AsyncSession = Depends(get_db)):
    """Aggregated per-app anomaly counts for the dashboard."""
    result = await db.execute(
        select(
            AppHealthSnapshot.namespace,
            AppHealthSnapshot.app_label,
            func.count(AppHealthSnapshot.id).label("total_windows"),
            func.sum(
                func.cast(AppHealthSnapshot.is_anomaly, db.bind.dialect.name == "postgresql" and "int" or "INTEGER")
            ).label("anomaly_windows"),
            func.avg(AppHealthSnapshot.error_rate).label("avg_error_rate"),
            func.avg(AppHealthSnapshot.avg_latency_ms).label("avg_latency_ms"),
            func.max(AppHealthSnapshot.timestamp).label("last_seen"),
        )
        .group_by(AppHealthSnapshot.namespace, AppHealthSnapshot.app_label)
        .order_by(desc("anomaly_windows"))
        .limit(50)
    )
    rows = result.all()
    return [
        {
            "namespace": r.namespace,
            "app_label": r.app_label,
            "total_windows": r.total_windows,
            "anomaly_windows": r.anomaly_windows or 0,
            "avg_error_rate": round(r.avg_error_rate or 0, 4),
            "avg_latency_ms": round(r.avg_latency_ms or 0, 1),
            "last_seen": r.last_seen,
        }
        for r in rows
    ]

# ─── Alert Channels ───────────────────────────────────────────────────────────

@router.get("/alerts/channels")
async def list_alert_channels():
    """Return which alert channels are configured (for dashboard and demo runner)."""
    from app.core.config import settings as cfg
    return [
        {"name": "Slack",        "enabled": bool(cfg.SLACK_WEBHOOK_URL)},
        {"name": "Teams",        "enabled": bool(cfg.TEAMS_WEBHOOK_URL)},
        {"name": "Email",        "enabled": cfg.EMAIL_ENABLED and bool(cfg.EMAIL_TO_ADDRESSES)},
        {"name": "SMS (Twilio)", "enabled": bool(cfg.TWILIO_ACCOUNT_SID and cfg.SMS_TO_NUMBERS)},
        {"name": "Voice Call",   "enabled": bool(cfg.TWILIO_ACCOUNT_SID and cfg.VOICE_CALL_NUMBERS)},
        {"name": "WhatsApp",     "enabled": bool(cfg.TWILIO_ACCOUNT_SID and cfg.WHATSAPP_TO_NUMBERS)},
        {"name": "Discord",      "enabled": bool(cfg.DISCORD_WEBHOOK_URL)},
        {"name": "Telegram",     "enabled": bool(cfg.TELEGRAM_BOT_TOKEN and cfg.TELEGRAM_CHAT_IDS)},
        {"name": "OpsGenie",     "enabled": bool(cfg.OPSGENIE_API_KEY)},
        {"name": "PagerDuty",    "enabled": bool(cfg.PAGERDUTY_ROUTING_KEY)},
        {"name": "Webhook",      "enabled": bool(cfg.GENERIC_WEBHOOK_URLS)},
    ]
