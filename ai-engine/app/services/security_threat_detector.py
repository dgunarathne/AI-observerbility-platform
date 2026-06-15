"""
Security Threat Detector Service.

Receives ThreatIndicator events from agents and:
1. Correlates multiple low-severity signals into higher-severity incidents
   (e.g. many brute_force events from same IP → confirmed attack)
2. Tracks attack source IPs across time windows
3. Uses LLM to enrich high/critical threats with context and mitigation steps
4. De-duplicates using Redis TTL keys to avoid alert storms
5. Creates SecurityIncident records and dispatches alerts
"""

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set

from app.core.config import settings
from app.core.redis_client import get_redis
from app.models.incident import IncidentSeverity

logger = logging.getLogger(__name__)

# Correlation windows
CORRELATION_WINDOW_SECONDS = 300   # 5 minutes
BRUTE_FORCE_THRESHOLD = 10         # same IP, same category in window
IP_REPUTATION_THRESHOLD = 3        # distinct threat types from same IP

# Category display names for alerts
CATEGORY_LABELS = {
    "web_attack":            "Web Application Attack",
    "brute_force":           "Brute Force / Credential Attack",
    "privilege_escalation":  "Privilege Escalation",
    "reverse_shell":         "Reverse Shell / Code Execution",
    "container_escape":      "Container Escape Attempt",
    "crypto_mining":         "Crypto Mining Detected",
    "path_traversal":        "Path Traversal Attack",
    "port_scan":             "Port Scanning Activity",
    "secret_exfiltration":   "Secret/Credential Exfiltration",
    "kubernetes_attack":     "Kubernetes API Attack",
    "unauthorized_access":   "Unauthorized API Access",
    "suspicious_api_access": "Suspicious API Access",
    "privileged_workload":   "Privileged Workload Security Violation",
    "network_exposure":      "Network Policy Exposure",
}


@dataclass
class ThreatCorrelation:
    """Sliding window for correlating threats from a single source IP or pod."""
    events: deque = field(default_factory=lambda: deque(maxlen=100))
    categories: Set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_count: int = 0


@dataclass
class ThreatAnalysisResult:
    """Result of analyzing one threat indicator."""
    should_alert: bool
    severity: str
    title: str
    description: str
    is_correlated: bool = False
    correlation_count: int = 0
    mitigation: Optional[str] = None


class SecurityThreatDetector:
    """
    Stateful security threat detector with correlation and LLM enrichment.
    """

    def __init__(self):
        self._ip_correlations: Dict[str, ThreatCorrelation] = defaultdict(ThreatCorrelation)
        self._pod_correlations: Dict[str, ThreatCorrelation] = defaultdict(ThreatCorrelation)
        self._lock = asyncio.Lock()
        self._llm_client = None
        self._llm_initialized = False

    async def analyze_threat(self, threat: dict) -> ThreatAnalysisResult:
        """
        Analyze a single threat indicator.
        Returns ThreatAnalysisResult with alert recommendation.
        """
        category = threat.get("category", "unknown")
        severity = threat.get("severity", "medium")
        description = threat.get("description", "")
        source_ips = threat.get("source_ips", [])
        pod_name = threat.get("pod_name", "")
        namespace = threat.get("namespace", "")
        ts = _parse_ts(threat.get("timestamp"))

        label = CATEGORY_LABELS.get(category, category.replace("_", " ").title())

        # ── Deduplication check via Redis ───────────────────────────────────
        dedup_key = f"sec_threat:{category}:{namespace}:{pod_name}"
        redis = get_redis()
        if await redis.exists(dedup_key):
            return ThreatAnalysisResult(
                should_alert=False,
                severity=severity,
                title=f"[SUPPRESSED] {label}",
                description="Duplicate threat suppressed by cooldown",
            )

        # ── Always-alert for critical categories ────────────────────────────
        critical_categories = {
            "reverse_shell", "container_escape", "secret_exfiltration",
            "privilege_escalation", "crypto_mining",
        }
        if category in critical_categories:
            mitigation = await self._get_llm_mitigation(category, description, severity)
            await self._set_dedup(redis, dedup_key, 300)
            return ThreatAnalysisResult(
                should_alert=True,
                severity="critical",
                title=f"🔴 Critical Security Threat: {label}",
                description=description,
                mitigation=mitigation,
            )

        # ── Correlation: track by source IP and pod ─────────────────────────
        async with self._lock:
            corr_result = self._correlate(
                source_ips=source_ips,
                pod_key=f"{namespace}/{pod_name}" if pod_name else "",
                category=category,
                ts=ts,
            )

        if corr_result["elevated"]:
            upgraded_severity = "critical" if corr_result["count"] > 20 else "high"
            mitigation = await self._get_llm_mitigation(category, description, upgraded_severity)
            await self._set_dedup(redis, dedup_key, 600)
            return ThreatAnalysisResult(
                should_alert=True,
                severity=upgraded_severity,
                title=f"🔴 Correlated Attack: {label} ({corr_result['count']} events in 5 min)",
                description=(
                    f"{description}\n\n"
                    f"Correlation: {corr_result['count']} related events detected in the last 5 minutes "
                    f"from {corr_result.get('source', 'unknown source')}."
                ),
                is_correlated=True,
                correlation_count=corr_result["count"],
                mitigation=mitigation,
            )

        # ── Low-severity: individual alert only for high+ ───────────────────
        if severity in ("high", "critical"):
            await self._set_dedup(redis, dedup_key, 180)
            return ThreatAnalysisResult(
                should_alert=True,
                severity=severity,
                title=f"⚠️ Security Alert: {label}",
                description=description,
            )

        # medium / low — track but don't alert yet (wait for correlation)
        return ThreatAnalysisResult(
            should_alert=False,
            severity=severity,
            title=f"[TRACKED] {label}",
            description="Low-severity threat tracked for correlation",
        )

    def _correlate(self, source_ips: list, pod_key: str, category: str, ts: datetime) -> dict:
        """Update correlation windows and return elevation result."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=CORRELATION_WINDOW_SECONDS)
        elevated = False
        count = 0
        source = ""

        # IP-based correlation
        for ip in source_ips:
            corr = self._ip_correlations[ip]
            corr.events.append(ts)
            corr.categories.add(category)
            corr.last_seen = ts
            corr.total_count += 1

            # Purge old events
            while corr.events and corr.events[0] < cutoff:
                corr.events.popleft()

            recent_count = len(corr.events)

            if recent_count >= BRUTE_FORCE_THRESHOLD:
                elevated = True
                count = recent_count
                source = f"IP {ip}"
            elif len(corr.categories) >= IP_REPUTATION_THRESHOLD:
                elevated = True
                count = recent_count
                source = f"IP {ip} (multi-vector: {', '.join(list(corr.categories)[:3])})"

        # Pod-based correlation
        if pod_key:
            corr = self._pod_correlations[pod_key]
            corr.events.append(ts)
            corr.categories.add(category)
            corr.last_seen = ts
            corr.total_count += 1

            while corr.events and corr.events[0] < cutoff:
                corr.events.popleft()

            recent_count = len(corr.events)
            if recent_count >= 5:   # lower threshold for same pod
                elevated = True
                count = max(count, recent_count)
                source = source or f"pod {pod_key}"

        return {"elevated": elevated, "count": count, "source": source}

    async def _get_llm_mitigation(self, category: str, description: str, severity: str) -> Optional[str]:
        """Use LLM to generate a short mitigation recommendation for critical threats."""
        if not settings.OPENAI_API_KEY and not settings.ANTHROPIC_API_KEY:
            return _static_mitigation(category)

        try:
            await self._ensure_llm()
            if not self._llm_client:
                return _static_mitigation(category)

            prompt = (
                f"Security threat detected in Kubernetes cluster:\n"
                f"Category: {category}\n"
                f"Severity: {severity}\n"
                f"Description: {description[:500]}\n\n"
                f"Provide 3-5 concrete, actionable mitigation steps in plain text bullet points. "
                f"Be specific to Kubernetes. Maximum 200 words."
            )

            if settings.LLM_PROVIDER == "openai":
                resp = await self._llm_client.chat.completions.create(
                    model=settings.OPENAI_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=300,
                )
                return resp.choices[0].message.content
            elif settings.LLM_PROVIDER == "anthropic":
                resp = await self._llm_client.messages.create(
                    model=settings.ANTHROPIC_MODEL,
                    max_tokens=300,
                    messages=[{"role": "user", "content": prompt}],
                )
                return resp.content[0].text

        except Exception as e:
            logger.warning("LLM mitigation generation failed: %s", e)
        return _static_mitigation(category)

    async def _ensure_llm(self):
        if self._llm_initialized:
            return
        try:
            if settings.LLM_PROVIDER == "openai" and settings.OPENAI_API_KEY:
                from openai import AsyncOpenAI
                self._llm_client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            elif settings.LLM_PROVIDER == "anthropic" and settings.ANTHROPIC_API_KEY:
                import anthropic
                self._llm_client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        except Exception as e:
            logger.warning("Could not init LLM for security: %s", e)
        self._llm_initialized = True

    @staticmethod
    async def _set_dedup(redis, key: str, ttl_seconds: int):
        await redis.setex(key, ttl_seconds, "1")

    def get_threat_summary(self) -> dict:
        """Return active correlation stats for the dashboard."""
        active_ips = {
            ip: {
                "count": corr.total_count,
                "categories": list(corr.categories),
                "last_seen": corr.last_seen.isoformat(),
            }
            for ip, corr in self._ip_correlations.items()
            if corr.total_count > 0
        }
        active_pods = {
            pod: {
                "count": corr.total_count,
                "categories": list(corr.categories),
                "last_seen": corr.last_seen.isoformat(),
            }
            for pod, corr in self._pod_correlations.items()
            if corr.total_count > 0
        }
        return {"active_ip_threats": active_ips, "active_pod_threats": active_pods}


# ─── Static mitigations as fallback ──────────────────────────────────────────

_STATIC_MITIGATIONS = {
    "web_attack": (
        "• Deploy a WAF (Web Application Firewall) in front of exposed services\n"
        "• Enable rate limiting on ingress controllers\n"
        "• Review and tighten NetworkPolicies to restrict ingress traffic\n"
        "• Update vulnerable dependencies and apply security patches"
    ),
    "brute_force": (
        "• Block source IP at the ingress/firewall level immediately\n"
        "• Enable account lockout after N failed attempts\n"
        "• Require MFA for all administrative access\n"
        "• Review authentication logs for compromised accounts"
    ),
    "privilege_escalation": (
        "• Audit all ClusterRoleBindings immediately: kubectl get clusterrolebindings\n"
        "• Remove unnecessary cluster-admin bindings\n"
        "• Enable PodSecurity admission controller with restricted profiles\n"
        "• Review service account token mounts (automountServiceAccountToken: false)"
    ),
    "container_escape": (
        "• Immediately isolate the affected node\n"
        "• Remove all privileged containers and hostPath mounts\n"
        "• Enable seccompProfile and AppArmor/SELinux profiles\n"
        "• Audit and rotate all credentials that may have been exposed"
    ),
    "crypto_mining": (
        "• Kill the affected pod immediately: kubectl delete pod <name>\n"
        "• Scan container images with tools like Trivy or Grype\n"
        "• Set CPU/memory limits on all pods to limit mining impact\n"
        "• Implement image signing and admission policies"
    ),
    "reverse_shell": (
        "• Isolate the compromised pod by applying a deny-all NetworkPolicy\n"
        "• Kill the pod and preserve logs for forensics\n"
        "• Audit the container image for malicious content\n"
        "• Rotate all secrets the pod had access to"
    ),
    "secret_exfiltration": (
        "• Rotate all Kubernetes secrets immediately\n"
        "• Audit RBAC permissions for secrets access\n"
        "• Enable audit logging for secrets read operations\n"
        "• Consider using an external secrets manager (Vault, AWS Secrets Manager)"
    ),
    "kubernetes_attack": (
        "• Review and revoke suspicious API tokens\n"
        "• Enable Kubernetes audit logging if not already active\n"
        "• Tighten RBAC — apply least-privilege principles\n"
        "• Block the source IP at the API server firewall"
    ),
}


def _static_mitigation(category: str) -> str:
    return _STATIC_MITIGATIONS.get(
        category,
        "• Investigate the affected workload immediately\n"
        "• Review recent logs and events\n"
        "• Apply least-privilege access controls\n"
        "• Consult your security runbook"
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
