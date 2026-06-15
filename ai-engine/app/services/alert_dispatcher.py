"""
Alert Dispatcher Service.

Supported channels:
  ✅ Slack              — rich block-kit attachments with RCA
  ✅ Microsoft Teams    — Adaptive Card with full incident context
  ✅ Email (SMTP)       — HTML + plain-text multipart to multiple recipients
  ✅ SMS (Twilio)       — concise SMS to on-call numbers
  ✅ Voice Call (Twilio) — automated phone call with TwiML read-out
  ✅ Discord            — embedded message via webhook
  ✅ Telegram           — message via Bot API
  ✅ WhatsApp (Twilio)  — WhatsApp message to on-call
  ✅ OpsGenie           — alert with responder routing
  ✅ PagerDuty          — Events API v2
  ✅ Generic Webhook    — POST JSON to any URL

Routing rules:
  - CRITICAL            → all enabled channels + voice call
  - HIGH (security)     → all + SMS
  - HIGH                → Slack + Teams + email + SMS + pagerduty/opsgenie
  - MEDIUM              → Slack + Teams + email
  - LOW                 → Slack only
  - Prediction          → Slack + email
"""

import asyncio
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import httpx

from app.core.config import settings
from app.core.redis_client import get_redis
from app.models.incident import IncidentSeverity

logger = logging.getLogger(__name__)

# ─── Display helpers ──────────────────────────────────────────────────────────

SEVERITY_EMOJI = {
    IncidentSeverity.CRITICAL: "🔴",
    IncidentSeverity.HIGH:     "🟠",
    IncidentSeverity.MEDIUM:   "🟡",
    IncidentSeverity.LOW:      "🔵",
}

SEVERITY_COLOR = {
    IncidentSeverity.CRITICAL: "#FF0000",
    IncidentSeverity.HIGH:     "#FF6600",
    IncidentSeverity.MEDIUM:   "#FFAA00",
    IncidentSeverity.LOW:      "#0066FF",
}

SEVERITY_HEX_INT = {          # Discord uses integer colors
    IncidentSeverity.CRITICAL: 0xFF0000,
    IncidentSeverity.HIGH:     0xFF6600,
    IncidentSeverity.MEDIUM:   0xFFAA00,
    IncidentSeverity.LOW:      0x0066FF,
}


# ─── Channel routing by severity + type ──────────────────────────────────────

def _channels_for(severity: IncidentSeverity, alert_type: str, is_prediction: bool) -> list:
    """Return list of channel names to use for this alert."""
    sev = severity.value

    if is_prediction:
        return ["slack", "email"]

    if sev == "critical":
        return ["slack", "teams", "email", "sms", "voice", "discord",
                "telegram", "whatsapp", "pagerduty", "opsgenie", "webhook"]

    if sev == "high":
        if alert_type == "security":
            return ["slack", "teams", "email", "sms", "voice", "discord",
                    "telegram", "pagerduty", "opsgenie", "webhook"]
        return ["slack", "teams", "email", "sms", "discord",
                "pagerduty", "opsgenie", "webhook"]

    if sev == "medium":
        return ["slack", "teams", "email", "discord", "telegram", "webhook"]

    # low
    return ["slack", "webhook"]


# ─── Main dispatcher ──────────────────────────────────────────────────────────

class AlertDispatcher:
    """Dispatches alerts to all configured channels with per-severity routing."""

    def __init__(self):
        self._http = httpx.AsyncClient(timeout=15.0)

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
        alert_type: str = "incident",
    ) -> dict:
        """Send alert to all enabled channels appropriate for severity."""

        # ── Cooldown check ───────────────────────────────────────────────────
        cooldown_key = f"alert_cooldown:{namespace}:{pod_name}:{severity.value}"
        redis = get_redis()
        if await redis.exists(cooldown_key):
            logger.info("Alert suppressed (cooldown): %s", cooldown_key)
            return {"suppressed": True, "reason": "cooldown"}

        # ── Build full title ─────────────────────────────────────────────────
        prefix_map = {
            "security":      "🛡️ SECURITY THREAT",
            "cluster_health": "🏥 CLUSTER HEALTH",
            "app_anomaly":   "📊 APP ANOMALY",
        }
        prefix = "⚠️ PREDICTED INCIDENT" if is_prediction else prefix_map.get(alert_type, "🚨 INCIDENT DETECTED")
        full_title = f"{SEVERITY_EMOJI.get(severity, '')} {prefix}: {title}"
        ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        channels = _channels_for(severity, alert_type, is_prediction)
        results = {}

        # Run all channel sends concurrently
        tasks = {}

        if "slack" in channels and settings.SLACK_WEBHOOK_URL:
            tasks["slack"] = self._send_slack(
                full_title, description, severity, namespace, pod_name,
                rca_summary, preventive_actions, ts_str
            )

        if "teams" in channels and settings.TEAMS_WEBHOOK_URL:
            tasks["teams"] = self._send_teams(
                full_title, description, severity, namespace, pod_name,
                rca_summary, preventive_actions, ts_str
            )

        if "email" in channels and settings.EMAIL_ENABLED:
            tasks["email"] = self._send_email(
                full_title, description, severity, namespace, pod_name,
                rca_summary, preventive_actions, ts_str
            )

        if "sms" in channels and settings.TWILIO_ACCOUNT_SID and settings.SMS_TO_NUMBERS:
            tasks["sms"] = self._send_sms(
                full_title, severity, namespace, pod_name, ts_str
            )

        if "voice" in channels and settings.TWILIO_ACCOUNT_SID and settings.VOICE_CALL_NUMBERS:
            tasks["voice"] = self._send_voice_call(
                full_title, description, severity, namespace
            )

        if "discord" in channels and settings.DISCORD_WEBHOOK_URL:
            tasks["discord"] = self._send_discord(
                full_title, description, severity, namespace, pod_name,
                rca_summary, ts_str
            )

        if "telegram" in channels and settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_IDS:
            tasks["telegram"] = self._send_telegram(
                full_title, description, severity, namespace, pod_name,
                rca_summary, ts_str
            )

        if "whatsapp" in channels and settings.TWILIO_ACCOUNT_SID and settings.WHATSAPP_TO_NUMBERS:
            tasks["whatsapp"] = self._send_whatsapp(
                full_title, severity, namespace, pod_name, ts_str
            )

        if "opsgenie" in channels and settings.OPSGENIE_API_KEY:
            tasks["opsgenie"] = self._send_opsgenie(
                incident_id, full_title, description, severity, namespace, pod_name
            )

        if "pagerduty" in channels and settings.PAGERDUTY_ROUTING_KEY:
            tasks["pagerduty"] = self._send_pagerduty(
                incident_id, full_title, description, severity, namespace, pod_name
            )

        if "webhook" in channels and settings.GENERIC_WEBHOOK_URLS:
            tasks["webhook"] = self._send_generic_webhooks(
                incident_id, full_title, description, severity,
                namespace, pod_name, alert_type, ts_str,
                rca_summary, preventive_actions
            )

        if tasks:
            done = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for key, result in zip(tasks.keys(), done):
                results[key] = str(result) if isinstance(result, Exception) else result

        # ── Set cooldown ─────────────────────────────────────────────────────
        await redis.setex(cooldown_key, settings.ALERT_COOLDOWN_MINUTES * 60, "1")

        enabled = list(results.keys())
        logger.info("Alert dispatched for incident %d via %s", incident_id, enabled)
        return results

    # ── Slack ─────────────────────────────────────────────────────────────────

    async def _send_slack(self, title, description, severity, namespace, pod_name,
                          rca_summary, preventive_actions, ts_str) -> str:
        color = SEVERITY_COLOR.get(severity, "#888888")
        fields = [
            {"title": "Namespace", "value": namespace or "N/A", "short": True},
            {"title": "Pod / App",  "value": pod_name or "N/A",  "short": True},
            {"title": "Severity",   "value": severity.value.upper(), "short": True},
            {"title": "Time",       "value": ts_str, "short": True},
        ]
        attachments = [{
            "color": color, "title": title, "text": description,
            "fields": fields, "footer": "AI Observability Platform",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
        if rca_summary:
            attachments.append({"color": "#36a64f", "title": "🔍 Root Cause Analysis", "text": rca_summary})
        if preventive_actions:
            text = "\n".join(
                f"• [{a.get('priority','').upper()}] {a.get('action','')}"
                for a in preventive_actions[:5]
            )
            attachments.append({"color": "#0066FF", "title": "✅ Preventive Actions", "text": text})

        payload = {"channel": settings.SLACK_CHANNEL, "attachments": attachments}
        try:
            r = await self._http.post(settings.SLACK_WEBHOOK_URL, json=payload)
            r.raise_for_status()
            return "sent"
        except Exception as e:
            logger.error("Slack failed: %s", e)
            return f"failed:{e}"

    # ── Microsoft Teams ───────────────────────────────────────────────────────

    async def _send_teams(self, title, description, severity, namespace, pod_name,
                          rca_summary, preventive_actions, ts_str) -> str:
        color = SEVERITY_COLOR.get(severity, "#888888").lstrip("#")
        facts = [
            {"name": "Namespace", "value": namespace or "N/A"},
            {"name": "Pod / App",  "value": pod_name or "N/A"},
            {"name": "Severity",   "value": severity.value.upper()},
            {"name": "Time",       "value": ts_str},
        ]
        if rca_summary:
            facts.append({"name": "Root Cause", "value": rca_summary[:300]})

        sections = [{"activityTitle": title, "activitySubtitle": description,
                     "facts": facts, "markdown": True}]

        if preventive_actions:
            action_lines = "\n".join(
                f"• **[{a.get('priority','').upper()}]** {a.get('action','')}"
                for a in preventive_actions[:5]
            )
            sections.append({"activityTitle": "✅ Preventive Actions",
                              "text": action_lines, "markdown": True})

        payload = {
            "@type": "MessageCard", "@context": "http://schema.org/extensions",
            "themeColor": color, "summary": title, "sections": sections,
        }
        try:
            r = await self._http.post(settings.TEAMS_WEBHOOK_URL, json=payload)
            r.raise_for_status()
            return "sent"
        except Exception as e:
            logger.error("Teams failed: %s", e)
            return f"failed:{e}"

    # ── Email (SMTP) ──────────────────────────────────────────────────────────

    async def _send_email(self, title, description, severity, namespace, pod_name,
                          rca_summary, preventive_actions, ts_str) -> str:
        subject = f"[{severity.value.upper()}] {title}"
        html_body = _build_email_html(
            title, description, severity, namespace, pod_name,
            rca_summary, preventive_actions, ts_str
        )
        plain_body = _build_email_plain(
            title, description, severity, namespace, pod_name,
            rca_summary, preventive_actions, ts_str
        )

        recipients = [r.strip() for r in settings.EMAIL_TO_ADDRESSES.split(",") if r.strip()]
        if not recipients:
            return "skipped:no recipients"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = settings.EMAIL_FROM_ADDRESS
        msg["To"]      = ", ".join(recipients)
        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            await asyncio.get_event_loop().run_in_executor(
                None, _smtp_send, msg, recipients
            )
            return f"sent:{len(recipients)} recipients"
        except Exception as e:
            logger.error("Email failed: %s", e)
            return f"failed:{e}"

    # ── SMS (Twilio) ──────────────────────────────────────────────────────────

    async def _send_sms(self, title, severity, namespace, pod_name, ts_str) -> str:
        body = (
            f"[AI-OBS {severity.value.upper()}] {title}\n"
            f"Namespace: {namespace or 'N/A'} | Pod: {pod_name or 'N/A'}\n"
            f"{ts_str}\nDashboard: {settings.DASHBOARD_URL}"
        )
        results = []
        for to_number in [n.strip() for n in settings.SMS_TO_NUMBERS.split(",") if n.strip()]:
            result = await self._twilio_send_message(
                to=to_number, body=body, channel="sms"
            )
            results.append(f"{to_number}:{result}")
        return ", ".join(results)

    # ── Voice Call (Twilio) ────────────────────────────────────────────────────

    async def _send_voice_call(self, title, description, severity, namespace) -> str:
        """Trigger an automated phone call that reads out the incident summary."""
        say_text = (
            f"ALERT. Severity {severity.value}. {title}. "
            f"Namespace: {namespace or 'unknown'}. "
            f"This is an automated alert from the AI Observability Platform. "
            f"Please check the dashboard immediately. "
            f"Repeating: {title}."
        )
        # TwiML response URL — we use Twilio's twiml.twilio.com shorthand
        # or you can host your own TwiML endpoint
        twiml_url = settings.TWILIO_TWIML_URL or _build_twiml_url(say_text)

        results = []
        auth = (settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        calls_url = f"https://api.twilio.com/2010-04-01/Accounts/{settings.TWILIO_ACCOUNT_SID}/Calls.json"

        for to_number in [n.strip() for n in settings.VOICE_CALL_NUMBERS.split(",") if n.strip()]:
            payload = {
                "To":   to_number,
                "From": settings.TWILIO_FROM_NUMBER,
                "Url":  twiml_url,
                "Method": "GET",
            }
            try:
                r = await self._http.post(calls_url, data=payload, auth=auth)
                r.raise_for_status()
                call_sid = r.json().get("sid", "?")
                results.append(f"{to_number}:initiated({call_sid})")
                logger.info("Voice call initiated to %s, SID=%s", to_number, call_sid)
            except Exception as e:
                logger.error("Voice call to %s failed: %s", to_number, e)
                results.append(f"{to_number}:failed({e})")

        return ", ".join(results)

    # ── Discord ───────────────────────────────────────────────────────────────

    async def _send_discord(self, title, description, severity, namespace, pod_name,
                            rca_summary, ts_str) -> str:
        color = SEVERITY_HEX_INT.get(severity, 0x888888)
        fields = [
            {"name": "Namespace", "value": namespace or "N/A", "inline": True},
            {"name": "Pod / App",  "value": pod_name or "N/A",  "inline": True},
            {"name": "Severity",   "value": severity.value.upper(), "inline": True},
        ]
        if rca_summary:
            fields.append({"name": "Root Cause", "value": rca_summary[:1024], "inline": False})

        payload = {
            "embeds": [{
                "title": title,
                "description": description[:2000],
                "color": color,
                "fields": fields,
                "footer": {"text": "AI Observability Platform"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }]
        }
        try:
            r = await self._http.post(settings.DISCORD_WEBHOOK_URL, json=payload)
            r.raise_for_status()
            return "sent"
        except Exception as e:
            logger.error("Discord failed: %s", e)
            return f"failed:{e}"

    # ── Telegram ──────────────────────────────────────────────────────────────

    async def _send_telegram(self, title, description, severity, namespace, pod_name,
                              rca_summary, ts_str) -> str:
        sev_emoji = SEVERITY_EMOJI.get(severity, "⚡")
        text = (
            f"{sev_emoji} *{_esc(title)}*\n\n"
            f"{_esc(description[:500])}\n\n"
            f"📍 Namespace: `{namespace or 'N/A'}`\n"
            f"📦 Pod: `{pod_name or 'N/A'}`\n"
            f"🕐 {ts_str}"
        )
        if rca_summary:
            text += f"\n\n🔍 *RCA:* {_esc(rca_summary[:300])}"

        chat_ids = [c.strip() for c in settings.TELEGRAM_CHAT_IDS.split(",") if c.strip()]
        results = []
        url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"

        for chat_id in chat_ids:
            try:
                r = await self._http.post(url, json={
                    "chat_id": chat_id, "text": text,
                    "parse_mode": "MarkdownV2", "disable_web_page_preview": True,
                })
                r.raise_for_status()
                results.append(f"{chat_id}:sent")
            except Exception as e:
                logger.error("Telegram to %s failed: %s", chat_id, e)
                results.append(f"{chat_id}:failed({e})")

        return ", ".join(results)

    # ── WhatsApp (Twilio) ──────────────────────────────────────────────────────

    async def _send_whatsapp(self, title, severity, namespace, pod_name, ts_str) -> str:
        body = (
            f"🚨 *AI Observability Alert*\n"
            f"*{severity.value.upper()}*: {title}\n"
            f"Namespace: {namespace or 'N/A'}\n"
            f"Pod: {pod_name or 'N/A'}\n"
            f"Time: {ts_str}"
        )
        results = []
        for to_number in [n.strip() for n in settings.WHATSAPP_TO_NUMBERS.split(",") if n.strip()]:
            result = await self._twilio_send_message(
                to=f"whatsapp:{to_number}",
                from_=f"whatsapp:{settings.TWILIO_WHATSAPP_FROM}",
                body=body,
                channel="whatsapp",
            )
            results.append(f"{to_number}:{result}")
        return ", ".join(results)

    # ── OpsGenie ─────────────────────────────────────────────────────────────

    async def _send_opsgenie(self, incident_id, title, description, severity,
                              namespace, pod_name) -> str:
        og_priority = {
            IncidentSeverity.CRITICAL: "P1",
            IncidentSeverity.HIGH:     "P2",
            IncidentSeverity.MEDIUM:   "P3",
            IncidentSeverity.LOW:      "P4",
        }.get(severity, "P3")

        payload = {
            "message":     title,
            "alias":       f"ai-obs-{incident_id}",
            "description": description[:15000],
            "priority":    og_priority,
            "source":      "AI Observability Platform",
            "tags":        [f"namespace:{namespace}", f"severity:{severity.value}"],
            "details": {
                "namespace":   namespace or "N/A",
                "pod":         pod_name or "N/A",
                "incident_id": str(incident_id),
            },
        }
        if settings.OPSGENIE_RESPONDERS:
            payload["responders"] = [
                {"type": "team", "name": t.strip()}
                for t in settings.OPSGENIE_RESPONDERS.split(",") if t.strip()
            ]

        headers = {"Authorization": f"GenieKey {settings.OPSGENIE_API_KEY}"}
        try:
            r = await self._http.post(
                "https://api.opsgenie.com/v2/alerts",
                json=payload, headers=headers
            )
            r.raise_for_status()
            return "sent"
        except Exception as e:
            logger.error("OpsGenie failed: %s", e)
            return f"failed:{e}"

    # ── PagerDuty ─────────────────────────────────────────────────────────────

    async def _send_pagerduty(self, incident_id, title, description, severity,
                               namespace, pod_name) -> str:
        pd_severity = {
            IncidentSeverity.CRITICAL: "critical",
            IncidentSeverity.HIGH:     "error",
            IncidentSeverity.MEDIUM:   "warning",
            IncidentSeverity.LOW:      "info",
        }.get(severity, "warning")

        payload = {
            "routing_key":   settings.PAGERDUTY_ROUTING_KEY,
            "event_action":  "trigger",
            "dedup_key":     f"ai-obs-{incident_id}",
            "payload": {
                "summary":  title,
                "source":   f"ai-observability/{namespace}/{pod_name}",
                "severity": pd_severity,
                "custom_details": {
                    "description":  description[:1000],
                    "namespace":    namespace,
                    "pod":          pod_name,
                    "incident_id":  incident_id,
                },
            },
        }
        try:
            r = await self._http.post(settings.PAGERDUTY_API_URL, json=payload)
            r.raise_for_status()
            return "sent"
        except Exception as e:
            logger.error("PagerDuty failed: %s", e)
            return f"failed:{e}"

    # ── Generic Webhook ───────────────────────────────────────────────────────

    async def _send_generic_webhooks(self, incident_id, title, description, severity,
                                      namespace, pod_name, alert_type, ts_str,
                                      rca_summary, preventive_actions) -> str:
        payload = {
            "incident_id":   incident_id,
            "title":         title,
            "description":   description,
            "severity":      severity.value,
            "alert_type":    alert_type,
            "namespace":     namespace,
            "pod":           pod_name,
            "timestamp":     ts_str,
            "rca_summary":   rca_summary,
            "preventive_actions": preventive_actions or [],
            "dashboard_url": settings.DASHBOARD_URL,
        }
        urls = [u.strip() for u in settings.GENERIC_WEBHOOK_URLS.split(",") if u.strip()]
        results = []
        for url in urls:
            try:
                headers = {}
                if settings.GENERIC_WEBHOOK_SECRET:
                    headers["X-AI-Obs-Secret"] = settings.GENERIC_WEBHOOK_SECRET
                r = await self._http.post(url, json=payload, headers=headers)
                r.raise_for_status()
                results.append(f"{url}:sent")
            except Exception as e:
                logger.error("Webhook %s failed: %s", url, e)
                results.append(f"{url}:failed({e})")
        return "; ".join(results)

    # ── Twilio helper ─────────────────────────────────────────────────────────

    async def _twilio_send_message(self, to: str, body: str,
                                    channel: str = "sms",
                                    from_: str | None = None) -> str:
        from_number = from_ or settings.TWILIO_FROM_NUMBER
        msgs_url = (f"https://api.twilio.com/2010-04-01/Accounts/"
                    f"{settings.TWILIO_ACCOUNT_SID}/Messages.json")
        auth = (settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        try:
            r = await self._http.post(msgs_url, data={
                "To": to, "From": from_number, "Body": body
            }, auth=auth)
            r.raise_for_status()
            sid = r.json().get("sid", "?")
            logger.info("%s sent to %s, SID=%s", channel, to, sid)
            return f"sent({sid})"
        except Exception as e:
            logger.error("%s to %s failed: %s", channel, to, e)
            return f"failed({e})"


# ─── Email builders ───────────────────────────────────────────────────────────

def _build_email_html(title, description, severity, namespace, pod_name,
                      rca_summary, preventive_actions, ts_str) -> str:
    sev_colors = {
        "critical": "#FF0000", "high": "#FF6600",
        "medium": "#FFAA00",   "low": "#0066FF",
    }
    color = sev_colors.get(severity.value, "#888888")

    actions_html = ""
    if preventive_actions:
        items = "".join(
            f"<li><strong>[{a.get('priority','').upper()}]</strong> {a.get('action','')}</li>"
            for a in preventive_actions[:10]
        )
        actions_html = f"""
        <h3 style="color:#2ecc71;">✅ Preventive Actions</h3>
        <ul style="font-size:14px;">{items}</ul>"""

    rca_html = ""
    if rca_summary:
        rca_html = f"""
        <h3 style="color:#3498db;">🔍 Root Cause Analysis</h3>
        <p style="background:#f0f4f8;padding:12px;border-radius:6px;font-size:14px;">{rca_summary}</p>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;max-width:700px;margin:0 auto;background:#f9f9f9;padding:20px;">
  <div style="background:#fff;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);overflow:hidden;">
    <div style="background:{color};padding:20px;">
      <h1 style="color:#fff;margin:0;font-size:20px;">{title}</h1>
      <p style="color:rgba(255,255,255,0.85);margin:8px 0 0;font-size:13px;">{ts_str}</p>
    </div>
    <div style="padding:24px;">
      <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
        <tr>
          <td style="padding:8px;background:#f5f5f5;border:1px solid #eee;font-weight:bold;width:30%;">Severity</td>
          <td style="padding:8px;border:1px solid #eee;">
            <span style="background:{color};color:#fff;padding:3px 10px;border-radius:12px;font-size:13px;">
              {severity.value.upper()}
            </span>
          </td>
        </tr>
        <tr>
          <td style="padding:8px;background:#f5f5f5;border:1px solid #eee;font-weight:bold;">Namespace</td>
          <td style="padding:8px;border:1px solid #eee;font-family:monospace;">{namespace or 'N/A'}</td>
        </tr>
        <tr>
          <td style="padding:8px;background:#f5f5f5;border:1px solid #eee;font-weight:bold;">Pod / App</td>
          <td style="padding:8px;border:1px solid #eee;font-family:monospace;">{pod_name or 'N/A'}</td>
        </tr>
      </table>

      <h3 style="color:#333;">📋 Description</h3>
      <p style="font-size:14px;color:#555;white-space:pre-wrap;">{description}</p>
      {rca_html}
      {actions_html}

      <div style="margin-top:24px;padding-top:16px;border-top:1px solid #eee;text-align:center;">
        <a href="{settings.DASHBOARD_URL}"
           style="background:#3498db;color:#fff;padding:10px 24px;border-radius:6px;
                  text-decoration:none;font-size:14px;font-weight:bold;">
          Open Dashboard →
        </a>
      </div>
    </div>
    <div style="background:#f5f5f5;padding:12px;text-align:center;font-size:12px;color:#999;">
      AI Observability Platform — automated alert
    </div>
  </div>
</body>
</html>"""


def _build_email_plain(title, description, severity, namespace, pod_name,
                       rca_summary, preventive_actions, ts_str) -> str:
    lines = [
        f"{'='*60}",
        f"  AI OBSERVABILITY ALERT: {severity.value.upper()}",
        f"{'='*60}",
        f"",
        f"Title:     {title}",
        f"Severity:  {severity.value.upper()}",
        f"Namespace: {namespace or 'N/A'}",
        f"Pod/App:   {pod_name or 'N/A'}",
        f"Time:      {ts_str}",
        f"",
        f"DESCRIPTION",
        f"-----------",
        description,
    ]
    if rca_summary:
        lines += ["", "ROOT CAUSE ANALYSIS", "-" * 20, rca_summary]
    if preventive_actions:
        lines += ["", "PREVENTIVE ACTIONS", "-" * 18]
        for a in preventive_actions[:10]:
            lines.append(f"  [{a.get('priority','?').upper()}] {a.get('action','')}")
    lines += ["", f"Dashboard: {settings.DASHBOARD_URL}", ""]
    return "\n".join(lines)


def _smtp_send(msg: MIMEMultipart, recipients: list):
    """Synchronous SMTP send — called via run_in_executor."""
    context = ssl.create_default_context()
    if settings.EMAIL_USE_SSL:
        with smtplib.SMTP_SSL(settings.EMAIL_HOST, settings.EMAIL_PORT, context=context) as smtp:
            smtp.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
            smtp.sendmail(settings.EMAIL_FROM_ADDRESS, recipients, msg.as_string())
    else:
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as smtp:
            if settings.EMAIL_USE_TLS:
                smtp.starttls(context=context)
            if settings.EMAIL_USERNAME:
                smtp.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
            smtp.sendmail(settings.EMAIL_FROM_ADDRESS, recipients, msg.as_string())


# ─── Twilio TwiML URL builder ─────────────────────────────────────────────────

def _build_twiml_url(say_text: str) -> str:
    """
    Build a Twilio TwiML Bins URL or fall back to twimlets.com say shortcut.
    In production replace with your own hosted TwiML endpoint.
    """
    import urllib.parse
    encoded = urllib.parse.quote(say_text[:500])
    return f"https://twimlets.com/message?Message%5B0%5D={encoded}"


# ─── Telegram Markdown escaper ────────────────────────────────────────────────

def _esc(text: str) -> str:
    """Escape special MarkdownV2 characters for Telegram."""
    special = r"\_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{c}" if c in special else c for c in (text or ""))
