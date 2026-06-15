"""
Cluster Health Analyzer Service.

Analyzes ClusterHealthReports from agents and:
1. Alerts when nodes go NotReady
2. Alerts when pods are stuck in CrashLoopBackOff
3. Alerts when PVCs are unbound
4. Alerts when deployments are degraded
5. Alerts when resource quota saturation >85%
6. Tracks cluster health score (0–100)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from app.models.incident import IncidentSeverity

logger = logging.getLogger(__name__)


@dataclass
class ClusterHealthIssue:
    """A single health issue found in a cluster health report."""
    category: str       # node | pod | pvc | deployment | quota
    severity: str       # critical | high | medium | low
    title: str
    description: str
    affected_resources: List[str] = field(default_factory=list)


@dataclass
class ClusterHealthAnalysisResult:
    issues: List[ClusterHealthIssue]
    health_score: int   # 0 (dead) – 100 (perfect)
    summary: str


class ClusterHealthAnalyzer:
    """Stateless analysis of cluster health snapshots."""

    def analyze(self, report: dict) -> ClusterHealthAnalysisResult:
        issues = []

        # ── Node health ──────────────────────────────────────────────────────
        total_nodes = report.get("total_nodes", 0)
        not_ready = report.get("not_ready_nodes", 0)

        if not_ready > 0:
            nodes = report.get("nodes", [])
            not_ready_names = [n["name"] for n in nodes if not n.get("ready", True)]
            severity = "critical" if not_ready >= total_nodes else "high"
            issues.append(ClusterHealthIssue(
                category="node",
                severity=severity,
                title=f"{not_ready}/{total_nodes} node(s) NotReady",
                description=(
                    f"Nodes not ready: {', '.join(not_ready_names)}. "
                    "This may indicate hardware failures, kubelet crashes, or network partitions."
                ),
                affected_resources=not_ready_names,
            ))

        # Check node pressure conditions
        for node in report.get("nodes", []):
            conditions = node.get("conditions", {})
            pressures = []
            if conditions.get("MemoryPressure"):
                pressures.append("MemoryPressure")
            if conditions.get("DiskPressure"):
                pressures.append("DiskPressure")
            if conditions.get("PIDPressure"):
                pressures.append("PIDPressure")
            if conditions.get("NetworkUnavailable"):
                pressures.append("NetworkUnavailable")
            if pressures:
                issues.append(ClusterHealthIssue(
                    category="node",
                    severity="high",
                    title=f"Node {node['name']} under pressure: {', '.join(pressures)}",
                    description=(
                        f"Node {node['name']} is reporting conditions: {', '.join(pressures)}. "
                        "Pods may be evicted or fail to schedule."
                    ),
                    affected_resources=[node["name"]],
                ))

        # ── Pod health ───────────────────────────────────────────────────────
        crash_loop_pods = report.get("crash_loop_pods", 0)
        if crash_loop_pods > 0:
            details = report.get("crash_loop_details", [])
            names = [f"{d.get('namespace')}/{d.get('name')} (restarts: {d.get('restarts')})" for d in details[:10]]
            issues.append(ClusterHealthIssue(
                category="pod",
                severity="high",
                title=f"{crash_loop_pods} pod(s) in CrashLoopBackOff",
                description=(
                    f"Pods in CrashLoopBackOff: {'; '.join(names)}. "
                    "Check application logs and resource limits."
                ),
                affected_resources=[d.get("namespace", "") + "/" + d.get("name", "") for d in details],
            ))

        failed_pods = report.get("failed_pods", 0)
        if failed_pods > 0:
            issues.append(ClusterHealthIssue(
                category="pod",
                severity="medium",
                title=f"{failed_pods} pod(s) in Failed phase",
                description=f"{failed_pods} pods have entered Failed phase. These may need manual cleanup.",
            ))

        pending_pods = report.get("pending_pods", 0)
        total_pods = report.get("total_pods", 1)
        if pending_pods > 0 and pending_pods / max(total_pods, 1) > 0.2:
            issues.append(ClusterHealthIssue(
                category="pod",
                severity="medium",
                title=f"{pending_pods}/{total_pods} pods are Pending",
                description="High ratio of pending pods. Possible causes: insufficient node resources, unschedulable nodes, or missing PVCs.",
            ))

        # ── PVC health ───────────────────────────────────────────────────────
        unbound_pvcs = report.get("unbound_pvcs", 0)
        if unbound_pvcs > 0:
            names = report.get("unbound_pvc_names", [])
            issues.append(ClusterHealthIssue(
                category="pvc",
                severity="high",
                title=f"{unbound_pvcs} PVC(s) not bound",
                description=(
                    f"Unbound PVCs: {', '.join(names[:10])}. "
                    "Pods requiring these volumes will be stuck in Pending."
                ),
                affected_resources=names,
            ))

        # ── Deployment health ────────────────────────────────────────────────
        degraded_deployments = report.get("degraded_deployments", 0)
        if degraded_deployments > 0:
            names = report.get("degraded_deployment_names", [])
            issues.append(ClusterHealthIssue(
                category="deployment",
                severity="high" if degraded_deployments > 2 else "medium",
                title=f"{degraded_deployments} deployment(s) degraded",
                description=(
                    f"Deployments with unavailable replicas: {'; '.join(names[:10])}. "
                    "Services may be impacted."
                ),
                affected_resources=names,
            ))

        # ── Resource quota saturation ────────────────────────────────────────
        for quota in report.get("quota_saturations", []):
            saturation = quota.get("saturation", 0)
            severity = "critical" if saturation >= 0.95 else "high"
            issues.append(ClusterHealthIssue(
                category="quota",
                severity=severity,
                title=f"Resource quota {quota['resource']} at {saturation:.0%} in {quota['namespace']}",
                description=(
                    f"Namespace {quota['namespace']} resource quota for {quota['resource']}: "
                    f"used={quota['used']}, limit={quota['hard']} ({saturation:.0%}). "
                    "New workloads will be rejected when quota is exhausted."
                ),
                affected_resources=[quota["namespace"]],
            ))

        # ── Health score ─────────────────────────────────────────────────────
        health_score = self._compute_health_score(report, issues)
        summary = self._build_summary(report, issues, health_score)

        return ClusterHealthAnalysisResult(
            issues=issues,
            health_score=health_score,
            summary=summary,
        )

    def _compute_health_score(self, report: dict, issues: List[ClusterHealthIssue]) -> int:
        score = 100
        for issue in issues:
            if issue.severity == "critical":
                score -= 25
            elif issue.severity == "high":
                score -= 15
            elif issue.severity == "medium":
                score -= 8
            else:
                score -= 3

        # Bonus/penalty for pod ratios
        total = report.get("total_pods", 0)
        running = report.get("running_pods", 0)
        if total > 0:
            run_ratio = running / total
            if run_ratio < 0.7:
                score -= 20
            elif run_ratio < 0.9:
                score -= 10

        return max(0, min(100, score))

    def _build_summary(self, report: dict, issues: List[ClusterHealthIssue], score: int) -> str:
        total_nodes = report.get("total_nodes", 0)
        not_ready = report.get("not_ready_nodes", 0)
        total_pods = report.get("total_pods", 0)
        running = report.get("running_pods", 0)

        if score >= 90:
            status = "healthy"
        elif score >= 70:
            status = "degraded"
        elif score >= 50:
            status = "unhealthy"
        else:
            status = "critical"

        parts = [
            f"Cluster is {status} (score {score}/100). ",
            f"Nodes: {total_nodes - not_ready}/{total_nodes} ready. ",
            f"Pods: {running}/{total_pods} running. ",
        ]
        if issues:
            parts.append(f"Issues detected: {len(issues)} ({', '.join(set(i.category for i in issues))}).")

        return "".join(parts)

    @staticmethod
    def issue_severity_to_incident_severity(severity: str) -> IncidentSeverity:
        return {
            "critical": IncidentSeverity.CRITICAL,
            "high": IncidentSeverity.HIGH,
            "medium": IncidentSeverity.MEDIUM,
            "low": IncidentSeverity.LOW,
        }.get(severity, IncidentSeverity.MEDIUM)
