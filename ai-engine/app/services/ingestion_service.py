"""
Ingestion Service.

Central pipeline that handles all data streams:
1. Logs → anomaly detection, incident prediction
2. Metrics → anomaly detection, prediction
3. K8s Events → direct incident creation
4. App Health Reports → per-app error rate / latency / exception analysis
5. Cluster Health → node/pod/pvc/deployment health analysis
6. Security Threats → threat correlation, alerting
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import List

from sqlalchemy import select, desc

from app.core.database import AsyncSessionLocal
from app.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentType
from app.models.log_entry import LogEntry
from app.models.metric_snapshot import MetricSnapshot
from app.models.security_threat import SecurityThreat
from app.models.cluster_health_snapshot import ClusterHealthSnapshot
from app.models.app_health_snapshot import AppHealthSnapshot
from app.services.alert_dispatcher import AlertDispatcher
from app.services.anomaly_detector import AnomalyDetector
from app.services.app_log_analyzer import AppLogAnalyzer
from app.services.cluster_health_analyzer import ClusterHealthAnalyzer
from app.services.incident_predictor import IncidentPredictor
from app.services.rca_engine import RCAEngine
from app.services.security_threat_detector import SecurityThreatDetector

logger = logging.getLogger(__name__)


class IngestionService:
    def __init__(
        self,
        anomaly_detector: AnomalyDetector,
        incident_predictor: IncidentPredictor,
        rca_engine: RCAEngine,
        alert_dispatcher: AlertDispatcher,
        app_log_analyzer: AppLogAnalyzer,
        cluster_health_analyzer: ClusterHealthAnalyzer,
        security_threat_detector: SecurityThreatDetector,
    ):
        self.anomaly_detector = anomaly_detector
        self.incident_predictor = incident_predictor
        self.rca_engine = rca_engine
        self.alert_dispatcher = alert_dispatcher
        self.app_log_analyzer = app_log_analyzer
        self.cluster_health_analyzer = cluster_health_analyzer
        self.security_threat_detector = security_threat_detector

    # ── Log ingestion ────────────────────────────────────────────────────────

    async def ingest_logs(self, log_entries: List[dict]):
        """Process and store a batch of log entries."""
        async with AsyncSessionLocal() as db:
            for raw in log_entries:
                ts = _parse_ts(raw.get("timestamp"))
                message = raw.get("message", "")

                result = await self.anomaly_detector.analyze_log(message)

                entry = LogEntry(
                    timestamp=ts,
                    namespace=raw.get("namespace", ""),
                    pod_name=raw.get("pod_name", ""),
                    container_name=raw.get("container_name", ""),
                    node_name=raw.get("node_name"),
                    message=message,
                    labels=raw.get("labels"),
                    anomaly_score=result.score,
                    is_anomaly=result.is_anomaly,
                )
                db.add(entry)

                if result.is_anomaly:
                    await self.incident_predictor.record_log_anomaly(
                        namespace=raw.get("namespace", ""),
                        pod_name=raw.get("pod_name", ""),
                        anomaly_score=result.score,
                        ts=ts,
                    )

            await db.commit()

        namespaces_pods = {
            (raw.get("namespace", ""), raw.get("pod_name", ""))
            for raw in log_entries
        }
        for ns, pod in namespaces_pods:
            await self._check_and_create_prediction(ns, pod)

    # ── Metric ingestion ─────────────────────────────────────────────────────

    async def ingest_metrics(self, metric_entries: List[dict]):
        """Process and store metric snapshots."""
        async with AsyncSessionLocal() as db:
            for raw in metric_entries:
                ts = _parse_ts(raw.get("timestamp"))
                cpu = raw.get("cpu_millicores", 0)
                mem = raw.get("memory_bytes", 0)
                ns = raw.get("namespace", "")
                pod = raw.get("pod_name", "")

                snap = MetricSnapshot(
                    timestamp=ts,
                    namespace=ns,
                    pod_name=pod,
                    container_name=raw.get("container_name"),
                    node_name=raw.get("node_name"),
                    cpu_millicores=cpu,
                    memory_bytes=mem,
                    is_node=raw.get("is_node", False),
                )
                db.add(snap)

                if ns and pod:
                    await self.incident_predictor.record_metric(ns, pod, cpu, mem, ts)

                result = await self.anomaly_detector.analyze_metrics(cpu, mem, pod)
                if result.is_anomaly:
                    await self.incident_predictor.record_log_anomaly(ns, pod, result.score, ts)

            await db.commit()

    # ── K8s Event ingestion ──────────────────────────────────────────────────

    async def ingest_events(self, event_entries: List[dict]):
        """Process Kubernetes events."""
        for raw in event_entries:
            evt_type = raw.get("type", "Normal")
            reason = raw.get("reason", "")

            if evt_type == "Warning":
                ns = raw.get("namespace", "")
                obj = raw.get("involved_object", {})
                pod_name = obj.get("name", "") if obj.get("kind") == "Pod" else ""

                await self._create_incident(
                    title=f"K8s Warning: {reason}",
                    description=raw.get("message", ""),
                    severity=_event_severity(reason),
                    incident_type=IncidentType.K8S_EVENT,
                    namespace=ns,
                    pod_name=pod_name,
                )

    # ── App health report ingestion ──────────────────────────────────────────

    async def ingest_app_health(self, reports: List[dict]):
        """
        Process per-app aggregated health reports.
        Analyzes for error rate / latency / exception anomalies.
        """
        for report in reports:
            # Run analysis
            result = await self.app_log_analyzer.analyze_report(report)

            # Persist snapshot
            ts = _parse_ts(report.get("timestamp"))
            async with AsyncSessionLocal() as db:
                snap = AppHealthSnapshot(
                    timestamp=ts,
                    namespace=report.get("namespace", ""),
                    app_label=report.get("app_label", ""),
                    node_name=report.get("node_name"),
                    window_seconds=report.get("window_seconds", 60),
                    total_log_lines=report.get("total_log_lines", 0),
                    error_lines=report.get("error_lines", 0),
                    warn_lines=report.get("warn_lines", 0),
                    error_rate=report.get("error_rate", 0.0),
                    http_5xx_count=report.get("http_5xx_count", 0),
                    http_4xx_count=report.get("http_4xx_count", 0),
                    http_5xx_rate=report.get("http_5xx_rate", 0.0),
                    exception_count=report.get("exception_count", 0),
                    exception_types=report.get("exception_types"),
                    avg_latency_ms=report.get("avg_latency_ms", 0.0),
                    latency_samples=report.get("latency_samples", 0),
                    is_anomaly=result.is_anomaly,
                    anomalies=result.anomalies if result.is_anomaly else None,
                )
                db.add(snap)
                await db.commit()

            if not result.is_anomaly:
                continue

            # Build incident description from anomaly list
            anomaly_lines = [f"• {a['message']}" for a in result.anomalies]
            description = "\n".join(anomaly_lines)

            # Determine severity from worst anomaly
            severities = [a.get("severity", "medium") for a in result.anomalies]
            severity = _worst_severity(severities)

            ns = result.namespace
            app = result.app_label

            await self._create_incident(
                title=f"App anomaly: {app} in {ns}",
                description=description,
                severity=_str_to_severity(severity),
                incident_type=IncidentType.APP_ANOMALY,
                namespace=ns,
                pod_name=app,
                extra={"anomalies": result.anomalies},
            )

    # ── Cluster health ingestion ─────────────────────────────────────────────

    async def ingest_cluster_health(self, report: dict):
        """
        Process cluster health snapshot.
        Creates incidents for each serious health issue found.
        """
        analysis = self.cluster_health_analyzer.analyze(report)

        ts = _parse_ts(report.get("timestamp"))
        async with AsyncSessionLocal() as db:
            snap = ClusterHealthSnapshot(
                timestamp=ts,
                node_name=report.get("node_name"),
                total_nodes=report.get("total_nodes", 0),
                not_ready_nodes=report.get("not_ready_nodes", 0),
                total_pods=report.get("total_pods", 0),
                running_pods=report.get("running_pods", 0),
                pending_pods=report.get("pending_pods", 0),
                failed_pods=report.get("failed_pods", 0),
                crash_loop_pods=report.get("crash_loop_pods", 0),
                total_restarts=report.get("total_restarts", 0),
                unbound_pvcs=report.get("unbound_pvcs", 0),
                degraded_deployments=report.get("degraded_deployments", 0),
                health_score=analysis.health_score,
                issues=[
                    {
                        "category": i.category,
                        "severity": i.severity,
                        "title": i.title,
                        "description": i.description,
                        "affected_resources": i.affected_resources,
                    }
                    for i in analysis.issues
                ],
                summary=analysis.summary,
                raw_report=report,
            )
            db.add(snap)
            await db.commit()

        # Create incidents for each high/critical issue
        for issue in analysis.issues:
            if issue.severity not in ("critical", "high"):
                continue
            severity = ClusterHealthAnalyzer.issue_severity_to_incident_severity(issue.severity)
            await self._create_incident(
                title=issue.title,
                description=issue.description,
                severity=severity,
                incident_type=IncidentType.CLUSTER_HEALTH,
                extra={"affected_resources": issue.affected_resources, "category": issue.category},
            )

        # Alert if cluster health score drops below 60
        if analysis.health_score < 60:
            await self.alert_dispatcher.dispatch(
                incident_id=0,
                title=f"Cluster Health Degraded — Score: {analysis.health_score}/100",
                description=analysis.summary,
                severity=IncidentSeverity.HIGH if analysis.health_score < 40 else IncidentSeverity.MEDIUM,
                namespace="cluster-wide",
            )

    # ── Security threat ingestion ────────────────────────────────────────────

    async def ingest_security_threats(self, threats: List[dict]):
        """
        Process security threat indicators.
        Correlates, deduplicates, and alerts.
        """
        for raw in threats:
            # Persist raw threat
            ts = _parse_ts(raw.get("timestamp"))
            async with AsyncSessionLocal() as db:
                threat_row = SecurityThreat(
                    timestamp=ts,
                    category=raw.get("category", "unknown"),
                    severity=raw.get("severity", "medium"),
                    source=raw.get("source", "unknown"),
                    node_name=raw.get("node_name"),
                    namespace=raw.get("namespace"),
                    pod_name=raw.get("pod_name"),
                    container=raw.get("container"),
                    description=raw.get("description", ""),
                    source_ips=raw.get("source_ips"),
                    raw_log_line=raw.get("raw_log_line"),
                )
                db.add(threat_row)
                await db.commit()
                await db.refresh(threat_row)

            # Run correlation & analysis
            analysis = await self.security_threat_detector.analyze_threat(raw)

            if not analysis.should_alert:
                continue

            severity = _str_to_severity(analysis.severity)

            # Create security incident
            incident_id = await self._create_incident(
                title=analysis.title,
                description=analysis.description,
                severity=severity,
                incident_type=IncidentType.SECURITY_THREAT,
                threat_category=raw.get("category"),
                namespace=raw.get("namespace", ""),
                pod_name=raw.get("pod_name", ""),
                node_name=raw.get("node_name"),
                extra={
                    "source_ips": raw.get("source_ips"),
                    "correlation_count": analysis.correlation_count,
                    "mitigation": analysis.mitigation,
                },
            )

            # Update threat row with incident link
            if incident_id:
                async with AsyncSessionLocal() as db:
                    t = await db.get(SecurityThreat, threat_row.id)
                    if t:
                        t.incident_id = incident_id
                        t.alerted = True
                        t.mitigation = analysis.mitigation
                        await db.commit()

            # Dispatch alert
            await self.alert_dispatcher.dispatch(
                incident_id=incident_id or 0,
                title=analysis.title,
                description=analysis.description,
                severity=severity,
                namespace=raw.get("namespace", ""),
                pod_name=raw.get("pod_name", ""),
                rca_summary=analysis.mitigation,
                is_prediction=False,
                alert_type="security",
            )

    # ── Shared helpers ───────────────────────────────────────────────────────

    async def _create_incident(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity,
        incident_type: IncidentType = IncidentType.K8S_EVENT,
        threat_category: str | None = None,
        namespace: str = "",
        pod_name: str = "",
        node_name: str | None = None,
        extra: dict | None = None,
    ) -> int | None:
        async with AsyncSessionLocal() as db:
            incident = Incident(
                title=title,
                description=description,
                severity=severity,
                status=IncidentStatus.ACTIVE,
                incident_type=incident_type,
                threat_category=threat_category,
                namespace=namespace,
                pod_name=pod_name,
                node_name=node_name,
                detected_at=datetime.now(timezone.utc),
                extra=extra,
            )
            db.add(incident)
            await db.commit()
            await db.refresh(incident)

        logger.info("Incident created: id=%d type=%s title=%s", incident.id, incident_type, title)

        # Dispatch alert (skip for security threats — they handle their own alert)
        if incident_type != IncidentType.SECURITY_THREAT:
            await self.alert_dispatcher.dispatch(
                incident_id=incident.id,
                title=title,
                description=description,
                severity=severity,
                namespace=namespace,
                pod_name=pod_name,
            )

            # Generate RCA for app anomalies and cluster health issues
            if incident_type in (IncidentType.APP_ANOMALY, IncidentType.K8S_EVENT):
                asyncio.create_task(
                    self._generate_rca(incident.id, title, description, namespace, pod_name)
                )

        return incident.id

    async def _check_and_create_prediction(self, namespace: str, pod_name: str):
        prediction = await self.incident_predictor.predict(namespace, pod_name)
        if not prediction:
            return

        async with AsyncSessionLocal() as db:
            incident = Incident(
                title=f"Predicted incident: {pod_name} in {namespace}",
                description=prediction.reason,
                severity=prediction.severity,
                status=IncidentStatus.PREDICTED,
                incident_type=IncidentType.PREDICTION,
                namespace=namespace,
                pod_name=pod_name,
                detected_at=datetime.now(timezone.utc),
                predicted_at=datetime.now(timezone.utc),
                prediction_confidence=prediction.confidence,
            )
            db.add(incident)
            await db.commit()
            await db.refresh(incident)

        logger.info("Predicted incident: id=%d ns=%s pod=%s conf=%.2f",
                    incident.id, namespace, pod_name, prediction.confidence)

        await self.alert_dispatcher.dispatch(
            incident_id=incident.id,
            title=incident.title,
            description=prediction.reason,
            severity=prediction.severity,
            namespace=namespace,
            pod_name=pod_name,
            is_prediction=True,
        )

    async def _generate_rca(self, incident_id: int, title: str, description: str,
                             namespace: str, pod_name: str):
        from app.core.config import settings as cfg

        lookback = datetime.now(timezone.utc) - timedelta(minutes=cfg.RCA_LOG_LOOKBACK_MINUTES)

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(LogEntry)
                .where(LogEntry.namespace == namespace)
                .where(LogEntry.pod_name == pod_name)
                .where(LogEntry.timestamp >= lookback)
                .order_by(desc(LogEntry.timestamp))
                .limit(cfg.RCA_MAX_LOG_LINES)
            )
            log_rows = result.scalars().all()

        logs = [
            {
                "timestamp": str(r.timestamp),
                "namespace": r.namespace,
                "pod_name": r.pod_name,
                "container_name": r.container_name,
                "message": r.message,
            }
            for r in log_rows
        ]

        rca = await self.rca_engine.generate_rca(
            incident_title=title,
            incident_description=description,
            logs=logs,
            events=[],
        )

        async with AsyncSessionLocal() as db:
            incident = await db.get(Incident, incident_id)
            if incident:
                incident.rca_summary = rca.get("summary", "")
                incident.rca_root_causes = rca.get("root_causes", [])
                incident.rca_preventive_actions = rca.get("preventive_actions", [])
                incident.rca_generated_at = datetime.now(timezone.utc)
                await db.commit()

        logger.info("RCA generated for incident %d", incident_id)

        await self.alert_dispatcher.dispatch(
            incident_id=incident_id,
            title=f"RCA Complete: {title}",
            description=rca.get("summary", description),
            severity=IncidentSeverity.MEDIUM,
            namespace=namespace,
            pod_name=pod_name,
            rca_summary=rca.get("summary"),
            preventive_actions=rca.get("preventive_actions", []),
        )


# ─── Utilities ────────────────────────────────────────────────────────────────

def _parse_ts(ts_value) -> datetime:
    if isinstance(ts_value, datetime):
        return ts_value
    if isinstance(ts_value, str):
        try:
            return datetime.fromisoformat(ts_value.replace("Z", "+00:00"))
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _event_severity(reason: str) -> IncidentSeverity:
    critical = {"OOMKilling", "FailedScheduling", "Evicted", "NodeNotReady"}
    high = {"BackOff", "CrashLoopBackOff", "FailedMount", "Unhealthy"}
    if reason in critical:
        return IncidentSeverity.CRITICAL
    elif reason in high:
        return IncidentSeverity.HIGH
    return IncidentSeverity.MEDIUM


def _str_to_severity(s: str) -> IncidentSeverity:
    return {
        "critical": IncidentSeverity.CRITICAL,
        "high": IncidentSeverity.HIGH,
        "medium": IncidentSeverity.MEDIUM,
        "low": IncidentSeverity.LOW,
    }.get(s.lower(), IncidentSeverity.MEDIUM)


def _worst_severity(severities: list) -> str:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return min(severities, key=lambda s: order.get(s, 99), default="medium")
