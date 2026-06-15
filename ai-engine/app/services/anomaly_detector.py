"""
Anomaly Detector Service.

Uses two complementary approaches:
1. Isolation Forest  - unsupervised anomaly detection on metric time-series
2. Log-level keyword + TF-IDF vectorization for log anomalies
3. (Optional) LSTM autoencoder for sequential log pattern anomalies
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

from app.core.config import settings

logger = logging.getLogger(__name__)

# Patterns that always indicate an anomaly regardless of ML score
CRITICAL_LOG_PATTERNS = [
    re.compile(r"\b(OOMKill|OutOfMemory|out of memory)\b", re.IGNORECASE),
    re.compile(r"\b(panic|PANIC|fatal|FATAL)\b"),
    re.compile(r"\b(segfault|segmentation fault)\b", re.IGNORECASE),
    re.compile(r"\b(CrashLoopBackOff)\b", re.IGNORECASE),
    re.compile(r"exit status [1-9]\d*"),
    re.compile(r"\b(connection refused|connection reset|broken pipe)\b", re.IGNORECASE),
    re.compile(r"Error rate.*[5-9]\d%", re.IGNORECASE),
    re.compile(r"\b(disk.*full|no space left|ENOSPC)\b", re.IGNORECASE),
]

ERROR_LOG_PATTERNS = [
    re.compile(r"\b(ERROR|ERRO|error)\b"),
    re.compile(r"\b(WARN|WARNING|warn)\b"),
    re.compile(r"\b(exception|Exception|EXCEPTION)\b"),
    re.compile(r"\b(timeout|timed out|deadline exceeded)\b", re.IGNORECASE),
    re.compile(r"5\d\d\s+(Internal|Bad Gateway|Service Unavailable)", re.IGNORECASE),
]


@dataclass
class AnomalyResult:
    is_anomaly: bool
    score: float          # 0.0 (normal) → 1.0 (highly anomalous)
    reason: Optional[str] = None


class AnomalyDetector:
    """
    Detects anomalies in log messages and metric time-series.
    Models are trained incrementally as data arrives.
    """

    def __init__(self):
        self._metric_model: Optional[IsolationForest] = None
        self._metric_scaler = StandardScaler()
        self._log_vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words="english",
        )
        self._log_model: Optional[IsolationForest] = None
        self._metric_buffer: List[List[float]] = []
        self._log_buffer: List[str] = []
        self._min_samples_to_train = 200
        self._lock = asyncio.Lock()

    async def load_models(self):
        """Load persisted models from disk if available, else use untrained models."""
        logger.info("Anomaly detector initialized (models will train on first %d samples)",
                    self._min_samples_to_train)
        # Initialize with default models
        self._metric_model = IsolationForest(
            contamination=settings.ANOMALY_SENSITIVITY,
            n_estimators=100,
            random_state=42,
        )
        self._log_model = IsolationForest(
            contamination=settings.ANOMALY_SENSITIVITY,
            n_estimators=100,
            random_state=42,
        )

    async def analyze_log(self, message: str) -> AnomalyResult:
        """Score a single log message for anomalies."""
        # Rule-based pass first (fast path)
        for pattern in CRITICAL_LOG_PATTERNS:
            if pattern.search(message):
                return AnomalyResult(is_anomaly=True, score=1.0, reason=f"Critical pattern: {pattern.pattern}")

        for pattern in ERROR_LOG_PATTERNS:
            if pattern.search(message):
                return AnomalyResult(is_anomaly=True, score=0.7, reason="Error/warning pattern detected")

        # ML-based scoring
        async with self._lock:
            self._log_buffer.append(message)

            if len(self._log_buffer) >= self._min_samples_to_train:
                await self._retrain_log_model()

            if len(self._log_buffer) < self._min_samples_to_train:
                # Not enough data yet — use heuristic only
                return AnomalyResult(is_anomaly=False, score=0.0)

        # Score against trained model
        try:
            vec = self._log_vectorizer.transform([message])
            score = self._log_model.score_samples(vec)[0]
            # IsolationForest returns negative scores; more negative = more anomalous
            normalized = max(0.0, min(1.0, (-score + 0.5)))
            is_anomaly = self._log_model.predict(vec)[0] == -1
            return AnomalyResult(is_anomaly=is_anomaly, score=normalized)
        except Exception as e:
            logger.warning("Log scoring error: %s", e)
            return AnomalyResult(is_anomaly=False, score=0.0)

    async def analyze_metrics(self, cpu_millicores: int, memory_bytes: int,
                               pod_name: str = "") -> AnomalyResult:
        """Score a metric data point for anomalies."""
        features = [float(cpu_millicores), float(memory_bytes)]

        async with self._lock:
            self._metric_buffer.append(features)

            if len(self._metric_buffer) >= self._min_samples_to_train:
                await self._retrain_metric_model()

            if len(self._metric_buffer) < self._min_samples_to_train:
                return AnomalyResult(is_anomaly=False, score=0.0)

        try:
            X = self._metric_scaler.transform([features])
            score = self._metric_model.score_samples(X)[0]
            normalized = max(0.0, min(1.0, (-score + 0.5)))
            is_anomaly = self._metric_model.predict(X)[0] == -1
            reason = None
            if is_anomaly:
                reason = (
                    f"Unusual resource usage: CPU={cpu_millicores}m, "
                    f"Memory={memory_bytes // (1024 * 1024)}Mi"
                )
            return AnomalyResult(is_anomaly=is_anomaly, score=normalized, reason=reason)
        except Exception as e:
            logger.warning("Metric scoring error: %s", e)
            return AnomalyResult(is_anomaly=False, score=0.0)

    async def _retrain_log_model(self):
        """Retrain log anomaly model on buffered samples."""
        try:
            corpus = self._log_buffer[-5000:]  # Keep last 5000 messages
            X = self._log_vectorizer.fit_transform(corpus)
            self._log_model.fit(X)
            logger.info("Retrained log anomaly model on %d samples", len(corpus))
        except Exception as e:
            logger.error("Log model retrain failed: %s", e)

    async def _retrain_metric_model(self):
        """Retrain metric anomaly model on buffered samples."""
        try:
            data = np.array(self._metric_buffer[-10000:])
            X = self._metric_scaler.fit_transform(data)
            self._metric_model.fit(X)
            logger.info("Retrained metric anomaly model on %d samples", len(data))
        except Exception as e:
            logger.error("Metric model retrain failed: %s", e)
