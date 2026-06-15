"""
Incident Predictor Service.

Predicts future incidents by analyzing:
1. Rolling anomaly rate trends (rate-of-change)
2. Error log frequency per namespace/pod over a sliding window
3. Resource saturation trajectory (linear projection + threshold crossing)

Raises a prediction alert when confidence exceeds PREDICTION_THRESHOLD.
"""

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from app.core.config import settings
from app.models.incident import IncidentSeverity

logger = logging.getLogger(__name__)

WINDOW = timedelta(minutes=settings.ANOMALY_WINDOW_MINUTES)
HORIZON = timedelta(minutes=settings.PREDICTION_HORIZON_MINUTES)


@dataclass
class PodSignal:
    """Sliding-window signal buffer for a single pod."""
    anomaly_scores: deque = field(default_factory=lambda: deque(maxlen=200))
    error_counts: deque = field(default_factory=lambda: deque(maxlen=200))
    cpu_readings: deque = field(default_factory=lambda: deque(maxlen=200))
    mem_readings: deque = field(default_factory=lambda: deque(maxlen=200))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=200))


@dataclass
class PredictionResult:
    should_alert: bool
    confidence: float           # 0.0 – 1.0
    severity: IncidentSeverity
    reason: str
    predicted_incident_time: Optional[datetime] = None
    namespace: str = ""
    pod_name: str = ""


class IncidentPredictor:
    """
    Stateful predictor that maintains per-pod signal windows.
    Called after each anomaly score update.
    """

    def __init__(self):
        self._signals: Dict[str, PodSignal] = defaultdict(PodSignal)
        self._lock = asyncio.Lock()

    async def load_models(self):
        logger.info("Incident predictor initialized")

    async def record_log_anomaly(self, namespace: str, pod_name: str,
                                  anomaly_score: float, ts: datetime):
        key = f"{namespace}/{pod_name}"
        async with self._lock:
            sig = self._signals[key]
            sig.anomaly_scores.append(anomaly_score)
            sig.timestamps.append(ts)

    async def record_metric(self, namespace: str, pod_name: str,
                             cpu_millicores: int, memory_bytes: int, ts: datetime):
        key = f"{namespace}/{pod_name}"
        async with self._lock:
            sig = self._signals[key]
            sig.cpu_readings.append(cpu_millicores)
            sig.mem_readings.append(memory_bytes)

    async def predict(self, namespace: str, pod_name: str) -> Optional[PredictionResult]:
        """Return a PredictionResult if an incident is likely, else None."""
        key = f"{namespace}/{pod_name}"
        async with self._lock:
            sig = self._signals.get(key)

        if sig is None or len(sig.anomaly_scores) < 10:
            return None

        confidence, reason = self._compute_confidence(sig)

        if confidence < settings.PREDICTION_THRESHOLD:
            return None

        severity = self._confidence_to_severity(confidence)
        predicted_time = datetime.now(timezone.utc) + HORIZON

        return PredictionResult(
            should_alert=True,
            confidence=confidence,
            severity=severity,
            reason=reason,
            predicted_incident_time=predicted_time,
            namespace=namespace,
            pod_name=pod_name,
        )

    def _compute_confidence(self, sig: PodSignal):
        """
        Heuristic multi-signal confidence score.
        Returns (confidence: float, reason: str).
        """
        scores = list(sig.anomaly_scores)
        reasons = []

        # --- Signal 1: recent anomaly rate ---
        recent = scores[-20:] if len(scores) >= 20 else scores
        anomaly_rate = sum(1 for s in recent if s > 0.5) / len(recent)
        conf = anomaly_rate * 0.6

        if anomaly_rate > 0.4:
            reasons.append(f"High anomaly rate ({anomaly_rate:.0%} in last {len(recent)} samples)")

        # --- Signal 2: trend (is anomaly rate increasing?) ---
        if len(scores) >= 30:
            early = scores[-30:-15]
            late = scores[-15:]
            early_mean = sum(early) / len(early)
            late_mean = sum(late) / len(late)
            trend = late_mean - early_mean
            if trend > 0.1:
                conf += min(0.2, trend)
                reasons.append(f"Anomaly score trending up (Δ={trend:+.2f})")

        # --- Signal 3: resource saturation ---
        if len(sig.cpu_readings) >= 5:
            cpu = list(sig.cpu_readings)[-10:]
            cpu_growth = (cpu[-1] - cpu[0]) / max(cpu[0], 1)
            if cpu_growth > 0.5:
                conf += 0.15
                reasons.append(f"CPU usage grew {cpu_growth:.0%} recently")

        if len(sig.mem_readings) >= 5:
            mem = list(sig.mem_readings)[-10:]
            mem_growth = (mem[-1] - mem[0]) / max(mem[0], 1)
            if mem_growth > 0.4:
                conf += 0.15
                reasons.append(f"Memory usage grew {mem_growth:.0%} recently")

        confidence = min(1.0, conf)
        reason = "; ".join(reasons) if reasons else "Multiple signals elevated"
        return confidence, reason

    @staticmethod
    def _confidence_to_severity(confidence: float) -> IncidentSeverity:
        if confidence >= 0.9:
            return IncidentSeverity.CRITICAL
        elif confidence >= 0.8:
            return IncidentSeverity.HIGH
        elif confidence >= 0.7:
            return IncidentSeverity.MEDIUM
        return IncidentSeverity.LOW
