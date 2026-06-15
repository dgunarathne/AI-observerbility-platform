"""
Ingestion Service.

Central pipeline that:
1. Persists incoming logs/metrics/events to PostgreSQL
2. Runs anomaly detection on each entry
3. Feeds anomaly scores to the incident predictor
4. Triggers RCA + alerting when predictions exceed threshold
"""

import logging
from datetime import datetime, timezone
from typing import List

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.log_entry import LogEntry
from app.models.metric_snapshot import MetricSnapshot
from app.services.alert_dispatcher import AlertDispatcher
from app.services.anomaly_detector import AnomalyDetector
from app.services.incident_predictor import IncidentPredictor
from app.services.rca_engine import RCAEngine

logger = logging.getLogger(__name__)


class IngestionService:
    def __init__(
        self,
        anomaly_detector: AnomalyDetector,
        incident_predictor: IncidentPredictor,
        rca_engine: RCAEngine,
        alert_dispatcher: AlertDispatcher,
    ):
        self.anomaly_detector = anomaly_detector
        self.incident_predictor = incident_predictor
        self.rca_engine = rca_engine
        self.alert_dispatcher = alert_dispatcher

    async def ingest_logs(self, log_entries: List[dict]):
        """Process and store a batch of log entries."""
        async with AsyncSessionLocal() as db:
            for raw in log_entries:
                ts = _parse_ts(raw.get("timestamp"))
                message = raw.get("message", "")

                # Run anomaly detection
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

                # Feed signal to predictor
                if result.is_anomaly:
                    await self.incident_predictor.record_log_anomaly(
                        namespace=raw.get("namespace", ""),
                        pod_name=raw.get("pod_name", ""),
                        anomaly_score=result.score,
                        ts=ts,
                    )

            await db.commit()

        # Check predictions after batch
        namespaces_pods = {
            (raw.get("namespace", ""), raw.get("pod_name", ""))
            for raw in log_entries
        }
        for ns, pod in namespaces_pods:
            await self._check_and_create_prediction(ns, pod)

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

                # Record for prediction
                if ns and pod:
                    await self.incident_predictor.record_metric(ns, pod, cpu, mem, ts)

                # Detect metric anomalies
                result = await self.anomaly_detector.analyze_metrics(cpu, mem, pod)
                if result.is_anomaly:
                    await self.incident_predictor.record_log_anomaly(ns, pod, result.score, ts)

            await db.commit()

    async def ingest_events(self, event_entries: List[dict]):
        """Process Kubernetes events — treat warning events as potential incidents."""
        for raw in event_entries:
            evt_type = raw.get("type", "Normal")
            reason = raw.get("reason", "")

            if evt_type == "Warning":
                ns = raw.get("namespace", "")
                obj = raw.get("involved_object", {})
                pod_name = obj.get("name", "") if obj.get("kind") == "Pod" else ""

                title = f"K8s Warning: {reason}"
                description = raw.get("message", "")

                await self._create_incident_from_event(
                    title=title,
                    description=description,
                    severity=_event_severity(reason),
                    namespace=ns,
                    pod_name=pod_name,
                )

    async def _check_and_create_prediction(self, namespace: str, pod_name: str):
        """Check if prediction threshold is met, create predicted incident if so."""
        prediction = await self.incident_predictor.predict(namespace, pod_name)
        if not prediction:
            return

        async with AsyncSessionLocal() as db:
            incident = Incident(
                title=f"Predicted incident: {pod_name} in {namespace}",
                description=prediction.reason,
                severity=prediction.severity,
                status=IncidentStatus.PREDICTED,
                namespace=namespace,
                pod_name=pod_name,
                detected_at=datetime.now(timezone.utc),
                predicted_at=datetime.now(timezone.utc),
                prediction_confidence=prediction.confidence,
            )
            db.add(incident)
            await db.commit()
            await db.refresh(incident)

        logger.info(
            "Predicted incident created: id=%d ns=%s pod=%s confidence=%.2f",
            incident.id, namespace, pod_name, prediction.confidence,
        )

        # Alert proactively
        await self.alert_dispatcher.dispatch(
            incident_id=incident.id,
            title=incident.title,
            description=prediction.reason,
            severity=prediction.severity,
            namespace=namespace,
            pod_name=pod_name,
            is_prediction=True,
        )

    async def _create_incident_from_event(
        self, title: str, description: str,
        severity: IncidentSeverity, namespace: str, pod_name: str
    ):
        async with AsyncSessionLocal() as db:
            incident = Incident(
                title=title,
                description=description,
                severity=severity,
                status=IncidentStatus.ACTIVE,
                namespace=namespace,
                pod_name=pod_name,
                detected_at=datetime.now(timezone.utc),
            )
            db.add(incident)
            await db.commit()
            await db.refresh(incident)

        logger.info("Incident created from K8s event: id=%d title=%s", incident.id, title)

        # Dispatch alert
        await self.alert_dispatcher.dispatch(
            incident_id=incident.id,
            title=title,
            description=description,
            severity=severity,
            namespace=namespace,
            pod_name=pod_name,
        )

        # Generate RCA asynchronously
        import asyncio
        asyncio.create_task(
            self._generate_rca(incident.id, title, description, namespace, pod_name)
        )

    async def _generate_rca(
        self, incident_id: int, title: str, description: str,
        namespace: str, pod_name: str
    ):
        """Fetch recent logs and generate RCA, then update the incident."""
        from app.core.config import settings
        from datetime import timedelta
        from sqlalchemy import select, desc

        lookback = datetime.now(timezone.utc) - timedelta(
            minutes=settings.RCA_LOG_LOOKBACK_MINUTES
        )

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(LogEntry)
                .where(LogEntry.namespace == namespace)
                .where(LogEntry.pod_name == pod_name)
                .where(LogEntry.timestamp >= lookback)
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

        rca = await self.rca_engine.generate_rca(
            incident_title=title,
            incident_description=description,
            logs=logs,
            events=[],
        )

        # Update incident with RCA
        async with AsyncSessionLocal() as db:
            incident = await db.get(Incident, incident_id)
            if incident:
                incident.rca_summary = rca.get("summary", "")
                incident.rca_root_causes = rca.get("root_causes", [])
                incident.rca_preventive_actions = rca.get("preventive_actions", [])
                incident.rca_generated_at = datetime.now(timezone.utc)
                await db.commit()

        logger.info("RCA generated for incident %d", incident_id)

        # Send updated alert with RCA
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
    critical_reasons = {"OOMKilling", "FailedScheduling", "Evicted", "NodeNotReady"}
    high_reasons = {"BackOff", "CrashLoopBackOff", "FailedMount", "Unhealthy"}

    if reason in critical_reasons:
        return IncidentSeverity.CRITICAL
    elif reason in high_reasons:
        return IncidentSeverity.HIGH
    return IncidentSeverity.MEDIUM
