"""
Alert Dispatcher Service.

Sends alerts to configured channels: Slack, Microsoft Teams,
PagerDuty, and generic webhooks. Implements cooldown logic to
avoid alert storms.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.core.config import settings
from app.core.redis_client import get_redis
from app.models.incident import IncidentSeverity

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    IncidentSeverity.CRITICAL: "🔴",
    IncidentSeverity.HIGH: "🟠",
    IncidentSeverity.MEDIUM: "🟡",
    IncidentSeverity.LOW: "🔵",
}

SEVERITY_COLOR = {
    IncidentSeverity.CRITICAL: "#FF0000",
    IncidentSeverity.HIGH: "#FF6600",
    IncidentSeverity.MEDIUM: "#FFAA00",
    IncidentSeverity.LOW: "#0066FF",
}


class AlertDispatcher:
    """Dispatches alerts to all configured channels."""

    def __init__(self):
        self._http = httpx.AsyncClient(timeout=10.0)

    async def dispatch(
        self,
        incident_id: int,
        title: str,
        description: str,
        severity: IncidentSeverity,
        namespace: str = "",
        pod_name: str = "",
        rca_summary: Optional[str] = None,
        preventive_actions: Optional[list] = None,
        is_prediction: bool = False,
        alert_type: str = "incident",   # "incident" | "security" | "cluster_health" | "app_anomaly"
    ) -> dict:
        """
        Send alert to all enabled channels.
        Returns dict of channel -> success/failure status.
        """
        # Cooldown check
        cooldown_key = f"alert_cooldown:{namespace}:{pod_name}:{severity}"
        redis = get_redis()
        if await redis.exists(cooldown_key):
            logger.info("Alert suppressed (cooldown active): %s", cooldown_key)
            return {"suppressed": True, "reason": "cooldown"}

        results = {}
        prefix_map = {
            "security": "🛡️ SECURITY THREAT",
            "cluster_health": "🏥 CLUSTER HEALTH",
            "app_anomaly": "📊 APP ANOMALY",
        }
        if is_prediction:
            prefix = "⚠️ PREDICTED INCIDENT"
        else:
            prefix = prefix_map.get(alert_type, "🚨 INCIDENT DETECTED")
        full_title = f"{SEVERITY_EMOJI.get(severity, '')} {prefix}: {title}"

        if settings.SLACK_WEBHOOK_URL:
            results["slack"] = await self._send_slack(
                full_title, description, severity, namespace, pod_name,
                rca_summary, preventive_actions
            )

        if settings.TEAMS_WEBHOOK_URL:
            results["teams"] = await self._send_teams(
                full_title, description, severity, namespace, pod_name, rca_summary
            )

        if settings.PAGERDUTY_ROUTING_KEY:
            results["pagerduty"] = await self._send_pagerduty(
                incident_id, full_title, description, severity, namespace, pod_name
            )

        # Set cooldown
        await redis.setex(
            cooldown_key,
            settings.ALERT_COOLDOWN_MINUTES * 60,
            "1"
        )

        logger.info("Alert dispatched for incident %d: %s", incident_id, results)
        return results

    async def _send_slack(
        self, title: str, description: str, severity: IncidentSeverity,
        namespace: str, pod_name: str,
        rca_summary: Optional[str], preventive_actions: Optional[list]
    ) -> str:
        color = SEVERITY_COLOR.get(severity, "#888888")
        fields = [
            {"title": "Namespace", "value": namespace or "N/A", "short": True},
            {"title": "Pod", "value": pod_name or "N/A", "short": True},
            {"title": "Severity", "value": severity.value.upper(), "short": True},
            {"title": "Time", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "short": True},
        ]

        attachments = [
            {
                "color": color,
                "title": title,
                "text": description,
                "fields": fields,
                "footer": "AI Observability Platform",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ]

        if rca_summary:
            attachments.append({
                "color": "#36a64f",
                "title": "🔍 Root Cause Analysis",
                "text": rca_summary,
            })

        if preventive_actions:
            actions_text = "\n".join(
                f"• [{a.get('priority', '').upper()}] {a.get('action', '')}"
                for a in preventive_actions[:5]
            )
            attachments.append({
                "color": "#0066FF",
                "title": "✅ Preventive Actions",
                "text": actions_text,
            })

        payload = {
            "channel": settings.SLACK_CHANNEL,
            "attachments": attachments,
        }

        try:
            resp = await self._http.post(settings.SLACK_WEBHOOK_URL, json=payload)
            resp.raise_for_status()
            return "sent"
        except Exception as e:
            logger.error("Slack alert failed: %s", e)
            return f"failed: {e}"

    async def _send_teams(
        self, title: str, description: str, severity: IncidentSeverity,
        namespace: str, pod_name: str, rca_summary: Optional[str]
    ) -> str:
        color = SEVERITY_COLOR.get(severity, "#888888").lstrip("#")
        facts = [
            {"name": "Namespace", "value": namespace or "N/A"},
            {"name": "Pod", "value": pod_name or "N/A"},
            {"name": "Severity", "value": severity.value.upper()},
        ]
        if rca_summary:
            facts.append({"name": "Root Cause", "value": rca_summary[:300]})

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": title,
            "sections": [
                {
                    "activityTitle": title,
                    "activitySubtitle": description,
                    "facts": facts,
                    "markdown": True,
                }
            ],
        }

        try:
            resp = await self._http.post(settings.TEAMS_WEBHOOK_URL, json=payload)
            resp.raise_for_status()
            return "sent"
        except Exception as e:
            logger.error("Teams alert failed: %s", e)
            return f"failed: {e}"

    async def _send_pagerduty(
        self, incident_id: int, title: str, description: str,
        severity: IncidentSeverity, namespace: str, pod_name: str
    ) -> str:
        pd_severity = {
            IncidentSeverity.CRITICAL: "critical",
            IncidentSeverity.HIGH: "error",
            IncidentSeverity.MEDIUM: "warning",
            IncidentSeverity.LOW: "info",
        }.get(severity, "warning")

        payload = {
            "routing_key": settings.PAGERDUTY_ROUTING_KEY,
            "event_action": "trigger",
            "dedup_key": f"ai-obs-{incident_id}",
            "payload": {
                "summary": title,
                "source": f"ai-observability/{namespace}/{pod_name}",
                "severity": pd_severity,
                "custom_details": {
                    "description": description,
                    "namespace": namespace,
                    "pod": pod_name,
                    "incident_id": incident_id,
                },
            },
        }

        try:
            resp = await self._http.post(settings.PAGERDUTY_API_URL, json=payload)
            resp.raise_for_status()
            return "sent"
        except Exception as e:
            logger.error("PagerDuty alert failed: %s", e)
            return f"failed: {e}"
