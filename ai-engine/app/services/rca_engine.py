"""
Root Cause Analysis (RCA) Engine.

When an incident is triggered, this service:
1. Fetches the correlated logs from the lookback window
2. Fetches related Kubernetes events
3. Builds a structured prompt with context
4. Sends to LLM (OpenAI / Anthropic / Ollama)
5. Parses structured RCA output: root causes + preventive actions
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


RCA_SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) and Kubernetes specialist.
You will be given logs, Kubernetes events, and metrics from a cluster incident.
Your job is to:
1. Identify the ROOT CAUSE(s) of the incident
2. Explain what happened step-by-step
3. Provide PREVENTIVE ACTIONS to avoid recurrence

Respond ONLY in the following JSON format (no markdown, no extra text):
{
  "summary": "<1-2 sentence plain-English summary of what happened>",
  "root_causes": [
    {
      "title": "<short title>",
      "description": "<detailed explanation>",
      "confidence": <0.0-1.0>
    }
  ],
  "timeline": [
    {
      "time": "<ISO8601 or relative>",
      "event": "<what happened>"
    }
  ],
  "preventive_actions": [
    {
      "action": "<actionable recommendation>",
      "priority": "<high|medium|low>",
      "category": "<resource-limits|monitoring|code-fix|config|scaling|security>"
    }
  ],
  "affected_components": ["<list of services/pods/nodes affected>"]
}"""


class RCAEngine:
    """Generates root cause analysis using LLM for a given incident."""

    def __init__(self):
        self._llm_client = None
        self._initialized = False

    async def _ensure_client(self):
        if self._initialized:
            return

        provider = settings.LLM_PROVIDER.lower()
        if provider == "openai":
            from openai import AsyncOpenAI
            self._llm_client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            self._model = settings.OPENAI_MODEL
            self._call_fn = self._call_openai
        elif provider == "anthropic":
            import anthropic
            self._llm_client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
            self._model = settings.ANTHROPIC_MODEL
            self._call_fn = self._call_anthropic
        elif provider == "ollama":
            from ollama import AsyncClient
            self._llm_client = AsyncClient(host=settings.OLLAMA_BASE_URL)
            self._model = settings.OLLAMA_MODEL
            self._call_fn = self._call_ollama
        else:
            raise ValueError(f"Unknown LLM provider: {provider}")

        self._initialized = True
        logger.info("RCA engine using LLM provider: %s / %s", provider, self._model)

    async def generate_rca(
        self,
        incident_title: str,
        incident_description: str,
        logs: List[dict],
        events: List[dict],
        metrics_summary: Optional[dict] = None,
    ) -> dict:
        """
        Generate RCA for an incident.

        Returns parsed dict with: summary, root_causes, timeline,
        preventive_actions, affected_components.
        """
        await self._ensure_client()

        user_prompt = self._build_prompt(
            incident_title, incident_description, logs, events, metrics_summary
        )

        try:
            raw_response = await self._call_fn(user_prompt)
            result = self._parse_response(raw_response)
            logger.info("RCA generated for incident: %s", incident_title)
            return result
        except Exception as e:
            logger.error("RCA generation failed: %s", e)
            return {
                "summary": f"RCA generation failed: {e}",
                "root_causes": [],
                "timeline": [],
                "preventive_actions": [],
                "affected_components": [],
            }

    def _build_prompt(self, title: str, description: str,
                      logs: List[dict], events: List[dict],
                      metrics_summary: Optional[dict]) -> str:
        lines = [
            f"## Incident: {title}",
            f"**Description:** {description}",
            "",
        ]

        if metrics_summary:
            lines += [
                "## Resource Metrics at Incident Time",
                json.dumps(metrics_summary, indent=2),
                "",
            ]

        if events:
            lines += ["## Kubernetes Events (most recent first)"]
            for e in events[:30]:
                lines.append(
                    f"[{e.get('timestamp', '')}] {e.get('type', '')} | "
                    f"{e.get('reason', '')} | {e.get('involved_object', '')} | "
                    f"{e.get('message', '')}"
                )
            lines.append("")

        if logs:
            lines += [f"## Log Entries ({len(logs)} lines, truncated to {settings.RCA_MAX_LOG_LINES})"]
            for log in logs[:settings.RCA_MAX_LOG_LINES]:
                lines.append(
                    f"[{log.get('timestamp', '')}] "
                    f"{log.get('namespace', '')}/{log.get('pod_name', '')} "
                    f"[{log.get('container_name', '')}]: {log.get('message', '')}"
                )

        return "\n".join(lines)

    async def _call_openai(self, user_prompt: str) -> str:
        response = await self._llm_client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": RCA_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=2000,
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content

    async def _call_anthropic(self, user_prompt: str) -> str:
        response = await self._llm_client.messages.create(
            model=self._model,
            max_tokens=2000,
            system=RCA_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text

    async def _call_ollama(self, user_prompt: str) -> str:
        response = await self._llm_client.chat(
            model=self._model,
            messages=[
                {"role": "system", "content": RCA_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response["message"]["content"]

    @staticmethod
    def _parse_response(raw: str) -> dict:
        """Parse LLM JSON response, with fallback for malformed output."""
        try:
            # Strip markdown code fences if present
            clean = raw.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            return json.loads(clean)
        except json.JSONDecodeError:
            logger.warning("Could not parse RCA JSON response, returning raw text")
            return {
                "summary": raw[:500],
                "root_causes": [],
                "timeline": [],
                "preventive_actions": [],
                "affected_components": [],
            }
