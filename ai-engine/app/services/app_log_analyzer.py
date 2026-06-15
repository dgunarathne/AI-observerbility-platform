"""
Application Log Analyzer Service.

Receives per-app aggregated health reports (60s windows) from the agent and:
1. Detects abnormal error rates using statistical baselines (mean + 3σ)
2. Detects HTTP 5xx spikes
3. Detects latency degradation (P95 comparison to baseline)
4. Detects exception frequency bursts
5. Detects zero-traffic (dead service) anomalies
6. Creates incidents and dispatches alerts for any anomaly found
"""

import asyncio
import logging
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.core.config import settings
from app.models.incident import IncidentSeverity

logger = logging.getLogger(__name__)

# How many 60s windows to keep per app for baseline calculation
BASELINE_WINDOW = 60   # ~1 hour of data
# Minimum windows before statistical alerting kicks in
MIN_BASELINE_SAMPLES = 10
# Thresholds (absolute, used before baseline is built)
ABSOLUTE_ERROR_RATE_THRESHOLD = 0.15      # >15% error rate = alert
ABSOLUTE_HTTP5XX_RATE_THRESHOLD = 0.10    # >10% 5xx rate = alert
ABSOLUTE_EXCEPTION_PER_WINDOW = 50        # >50 exceptions / 60s = alert
ABSOLUTE_LATENCY_MS_THRESHOLD = 5000.0    # >5 second avg latency = alert


@dataclass
class AppBaseline:
    """Rolling statistics for a single app."""
    error_rates: deque = field(default_factory=lambda: deque(maxlen=BASELINE_WINDOW))
    http5xx_rates: deque = field(default_factory=lambda: deque(maxlen=BASELINE_WINDOW))
    latencies: deque = field(default_factory=lambda: deque(maxlen=BASELINE_WINDOW))
    exception_counts: deque = field(default_factory=lambda: deque(maxlen=BASELINE_WINDOW))
    log_volumes: deque = field(default_factory=lambda: deque(maxlen=BASELINE_WINDOW))
    last_seen: Optional[datetime] = None


@dataclass
class AppAnomalyResult:
    is_anomaly: bool
    anomalies: List[dict]   # list of {type, value, threshold, severity}
    namespace: str
    app_label: str


class AppLogAnalyzer:
    """
    Stateful per-app log health analyzer.
    Builds baselines over time and detects deviations.
    """

    def __init__(self):
        self._baselines: Dict[str, AppBaseline] = defaultdict(AppBaseline)
        self._lock = asyncio.Lock()

    async def analyze_report(self, report: dict) -> AppAnomalyResult:
        """
        Analyze one AppHealthReport dict.  Returns detected anomalies.
        """
        ns = report.get("namespace", "")
        app = report.get("app_label", "")
        key = f"{ns}/{app}"

        error_rate = report.get("error_rate", 0.0)
        http5xx_rate = report.get("http_5xx_rate", 0.0)
        exception_count = report.get("exception_count", 0)
        avg_latency = report.get("avg_latency_ms", 0.0)
        total_lines = report.get("total_log_lines", 0)
        http5xx_count = report.get("http_5xx_count", 0)
        http4xx_count = report.get("http_4xx_count", 0)

        anomalies = []

        async with self._lock:
            baseline = self._baselines[key]

            # ── Absolute thresholds (fast path, no baseline needed) ──────────
            if error_rate > ABSOLUTE_ERROR_RATE_THRESHOLD:
                anomalies.append({
                    "type": "high_error_rate",
                    "value": error_rate,
                    "threshold": ABSOLUTE_ERROR_RATE_THRESHOLD,
                    "severity": "high" if error_rate > 0.3 else "medium",
                    "message": f"Error rate {error_rate:.1%} exceeds threshold {ABSOLUTE_ERROR_RATE_THRESHOLD:.1%}",
                })

            if http5xx_rate > ABSOLUTE_HTTP5XX_RATE_THRESHOLD:
                anomalies.append({
                    "type": "http_5xx_spike",
                    "value": http5xx_count,
                    "threshold": ABSOLUTE_HTTP5XX_RATE_THRESHOLD,
                    "severity": "high",
                    "message": f"HTTP 5xx rate {http5xx_rate:.1%} — {http5xx_count} errors in window",
                })

            if exception_count > ABSOLUTE_EXCEPTION_PER_WINDOW:
                anomalies.append({
                    "type": "exception_burst",
                    "value": exception_count,
                    "threshold": ABSOLUTE_EXCEPTION_PER_WINDOW,
                    "severity": "medium",
                    "message": f"Exception burst: {exception_count} exceptions in 60s",
                })

            if avg_latency > ABSOLUTE_LATENCY_MS_THRESHOLD and report.get("latency_samples", 0) > 5:
                anomalies.append({
                    "type": "high_latency",
                    "value": avg_latency,
                    "threshold": ABSOLUTE_LATENCY_MS_THRESHOLD,
                    "severity": "medium",
                    "message": f"Average latency {avg_latency:.0f}ms exceeds {ABSOLUTE_LATENCY_MS_THRESHOLD:.0f}ms",
                })

            # ── Statistical baseline anomalies (once enough data) ────────────
            if len(baseline.error_rates) >= MIN_BASELINE_SAMPLES:
                # Error rate: mean + 3σ
                er_anomaly = _zscore_check(
                    value=error_rate,
                    history=list(baseline.error_rates),
                    z_threshold=3.0,
                    label="error_rate",
                    unit="%",
                    fmt=lambda v: f"{v:.1%}",
                )
                if er_anomaly:
                    er_anomaly["severity"] = "high"
                    anomalies.append(er_anomaly)

                # Latency: mean + 2.5σ (more sensitive)
                if avg_latency > 0 and report.get("latency_samples", 0) > 5:
                    lat_anomaly = _zscore_check(
                        value=avg_latency,
                        history=[v for v in baseline.latencies if v > 0],
                        z_threshold=2.5,
                        label="latency_degradation",
                        unit="ms",
                        fmt=lambda v: f"{v:.0f}ms",
                    )
                    if lat_anomaly:
                        lat_anomaly["severity"] = "medium"
                        anomalies.append(lat_anomaly)

                # Log volume drop > 90% vs baseline (dead service / crash)
                if total_lines == 0 and _mean(list(baseline.log_volumes)) > 20:
                    anomalies.append({
                        "type": "zero_traffic",
                        "value": 0,
                        "threshold": 1,
                        "severity": "critical",
                        "message": f"No log output from {app} in last 60s — service may be down",
                    })
                elif total_lines > 0 and len(baseline.log_volumes) >= MIN_BASELINE_SAMPLES:
                    vol_mean = _mean(list(baseline.log_volumes))
                    if vol_mean > 50 and total_lines < vol_mean * 0.1:
                        anomalies.append({
                            "type": "log_volume_drop",
                            "value": total_lines,
                            "threshold": int(vol_mean * 0.1),
                            "severity": "medium",
                            "message": f"Log volume dropped to {total_lines} (baseline avg {vol_mean:.0f}) — possible service degradation",
                        })

            # ── Update baseline ───────────────────────────────────────────────
            baseline.error_rates.append(error_rate)
            baseline.http5xx_rates.append(http5xx_rate)
            if avg_latency > 0:
                baseline.latencies.append(avg_latency)
            baseline.exception_counts.append(exception_count)
            baseline.log_volumes.append(total_lines)
            baseline.last_seen = datetime.now(timezone.utc)

        # Deduplicate anomaly types
        seen_types = set()
        unique_anomalies = []
        for a in anomalies:
            if a["type"] not in seen_types:
                seen_types.add(a["type"])
                unique_anomalies.append(a)

        return AppAnomalyResult(
            is_anomaly=len(unique_anomalies) > 0,
            anomalies=unique_anomalies,
            namespace=ns,
            app_label=app,
        )

    def get_baselines_summary(self) -> List[dict]:
        """Return a summary of all tracked app baselines for the dashboard."""
        result = []
        for key, baseline in self._baselines.items():
            ns, app = key.split("/", 1) if "/" in key else (key, "")
            result.append({
                "namespace": ns,
                "app_label": app,
                "samples": len(baseline.error_rates),
                "avg_error_rate": _mean(list(baseline.error_rates)),
                "avg_latency_ms": _mean([v for v in baseline.latencies if v > 0]),
                "last_seen": baseline.last_seen.isoformat() if baseline.last_seen else None,
            })
        return result


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stddev(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((v - m) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _zscore_check(
    value: float,
    history: List[float],
    z_threshold: float,
    label: str,
    unit: str,
    fmt,
) -> Optional[dict]:
    """Returns anomaly dict if value is more than z_threshold standard deviations above mean."""
    if len(history) < MIN_BASELINE_SAMPLES:
        return None
    mean = _mean(history)
    std = _stddev(history)
    if std < 1e-6:
        return None
    zscore = (value - mean) / std
    if zscore >= z_threshold:
        return {
            "type": label,
            "value": value,
            "threshold": mean + z_threshold * std,
            "zscore": round(zscore, 2),
            "message": f"{label}: current={fmt(value)}, baseline={fmt(mean)}±{fmt(std)} (z={zscore:.1f}σ)",
        }
    return None
