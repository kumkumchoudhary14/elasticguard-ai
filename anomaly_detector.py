"""
ML-based anomaly detection for ElasticGuard AI.
Uses Z-score and Isolation Forest to detect anomalies in IoT device metrics.
"""
import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np
from dotenv import load_dotenv
from elasticsearch import AsyncElasticsearch
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ES_INDEX = os.getenv("ELASTICSEARCH_INDEX", "iot-security-events")
ANOMALY_INDEX = os.getenv("ANOMALY_INDEX", "security-anomalies")
CHECK_INTERVAL = int(os.getenv("ANOMALY_CHECK_INTERVAL", "30"))

FEATURE_FIELDS = ["cpu_usage", "memory_usage", "temperature", "network_in", "network_out"]
ZSCORE_THRESHOLD = 3.0
ISOLATION_CONTAMINATION = 0.1


def compute_zscore(values: np.ndarray) -> np.ndarray:
    """Compute Z-scores for a 1D array."""
    if len(values) < 3:
        return np.zeros(len(values))
    mean = np.mean(values)
    std = np.std(values)
    if std == 0:
        return np.zeros(len(values))
    return np.abs((values - mean) / std)


def detect_zscore_anomalies(events: list[dict[str, Any]]) -> list[tuple[int, float, str]]:
    """
    Detect anomalies using Z-score on individual metrics.
    Returns list of (event_index, score, metric_name).
    """
    anomalies = []
    for field in FEATURE_FIELDS:
        values = np.array([
            e.get("metrics", {}).get(field, 0.0) for e in events
        ], dtype=float)
        zscores = compute_zscore(values)
        for idx, score in enumerate(zscores):
            if score > ZSCORE_THRESHOLD:
                anomalies.append((idx, float(score), field))
    return anomalies


def detect_isolation_forest_anomalies(events: list[dict[str, Any]]) -> list[tuple[int, float]]:
    """
    Detect anomalies using Isolation Forest on multi-dimensional features.
    Returns list of (event_index, anomaly_score).
    """
    if len(events) < 10:
        return []

    feature_matrix = []
    for e in events:
        metrics = e.get("metrics", {})
        row = [metrics.get(f, 0.0) for f in FEATURE_FIELDS]
        feature_matrix.append(row)

    X = np.array(feature_matrix, dtype=float)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = IsolationForest(
        contamination=ISOLATION_CONTAMINATION,
        random_state=42,
        n_estimators=100
    )
    predictions = clf.fit_predict(X_scaled)
    scores = clf.decision_function(X_scaled)
    # Normalize scores to 0-100 (higher = more anomalous)
    normalized = 100 * (1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-9))

    anomalies = []
    for idx, (pred, score) in enumerate(zip(predictions, normalized)):
        if pred == -1:
            anomalies.append((idx, float(score)))
    return anomalies


def classify_anomaly(event: dict[str, Any], anomaly_score: float, metric: str | None = None) -> dict[str, Any]:
    """Classify an anomaly and generate a recommended action."""
    device_type = event.get("device_type", "unknown")
    event_type = event.get("event_type", "unknown")
    metrics = event.get("metrics", {})

    # Determine threat category
    threat_category = "device_tampering"
    if metrics.get("network_in", 0) > 500:
        threat_category = "ddos"
    elif metrics.get("network_out", 0) > 400:
        threat_category = "data_exfiltration"
    elif device_type == "access_controller":
        threat_category = "unauthorized_access"
    elif event_type in ("port_scan", "port_scan_flood"):
        threat_category = "network_scan"
    elif event_type in ("brute_force_attempt", "credential_stuffing"):
        threat_category = "brute_force"
    elif metrics.get("temperature", 0) > 60:
        threat_category = "device_tampering"

    # Determine severity
    severity = "medium"
    if anomaly_score > 80:
        severity = "critical"
    elif anomaly_score > 60:
        severity = "high"
    elif anomaly_score > 40:
        severity = "medium"
    else:
        severity = "low"

    # Recommended actions
    actions = {
        "ddos": "Activate DDoS mitigation rules, block offending IPs, scale network resources",
        "data_exfiltration": "Isolate device, inspect outbound traffic, review data access logs",
        "unauthorized_access": "Lock down access point, alert security team, review access logs",
        "network_scan": "Block scanning IP, enable IDS alerts, review firewall rules",
        "brute_force": "Temporarily lock account, enforce MFA, notify security team",
        "device_tampering": "Inspect device physically, check firmware integrity, replace if compromised",
    }

    return {
        "threat_category": threat_category,
        "severity": severity,
        "recommended_action": actions.get(threat_category, "Investigate immediately"),
        "anomaly_metric": metric,
        "anomaly_score": round(anomaly_score, 2),
    }


async def fetch_recent_events(es: AsyncElasticsearch, minutes: int = 5) -> list[dict[str, Any]]:
    """Fetch recent events from Elasticsearch."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    query = {
        "query": {
            "range": {"@timestamp": {"gte": since}}
        },
        "size": 1000,
        "_source": True
    }
    response = await es.search(index=ES_INDEX, body=query)
    hits = response.get("hits", {}).get("hits", [])
    return [{"_id": h["_id"], **h["_source"]} for h in hits]


async def write_anomaly(es: AsyncElasticsearch, event: dict[str, Any], classification: dict[str, Any]) -> None:
    """Write a detected anomaly to Elasticsearch."""
    now = datetime.now(timezone.utc)
    anomaly_doc = {
        "@timestamp": now.isoformat(),
        "timestamp": now.isoformat(),
        "device_id": event.get("device_id"),
        "device_type": event.get("device_type"),
        "location": event.get("location"),
        "anomaly_type": classification["threat_category"],
        "anomaly_score": classification["anomaly_score"],
        "severity": classification["severity"],
        "threat_category": classification["threat_category"],
        "description": event.get("message", "Anomaly detected"),
        "recommended_action": classification["recommended_action"],
        "anomaly_metric": classification.get("anomaly_metric"),
        "original_event": {k: v for k, v in event.items() if k != "_id"},
        "resolved": False,
        "event_id": event.get("event_id"),
    }
    await es.index(index=ANOMALY_INDEX, body=anomaly_doc)


async def run_detection_cycle(es: AsyncElasticsearch) -> int:
    """Run a single detection cycle. Returns number of anomalies written."""
    logger.info("Running anomaly detection cycle...")
    events = await fetch_recent_events(es, minutes=5)
    if not events:
        logger.info("No recent events to analyze")
        return 0

    logger.info(f"Analyzing {len(events)} events")

    # Combine results from both methods
    detected: dict[int, dict[str, Any]] = {}

    zscore_anomalies = detect_zscore_anomalies(events)
    for idx, score, metric in zscore_anomalies:
        if idx not in detected or score > detected[idx].get("anomaly_score", 0):
            # Scale Z-score (typically 3-10+) to 0-100 range for consistent scoring
            detected[idx] = classify_anomaly(events[idx], score * 10, metric)

    if_anomalies = detect_isolation_forest_anomalies(events)
    for idx, score in if_anomalies:
        if idx not in detected or score > detected[idx].get("anomaly_score", 0):
            detected[idx] = classify_anomaly(events[idx], score)

    # Write anomalies to Elasticsearch
    written = 0
    for idx, classification in detected.items():
        await write_anomaly(es, events[idx], classification)
        written += 1

    logger.info(f"Wrote {written} anomalies to {ANOMALY_INDEX}")
    return written


async def run_continuous(es: AsyncElasticsearch) -> None:
    """Run anomaly detection continuously."""
    logger.info(f"Starting anomaly detector with interval={CHECK_INTERVAL}s")
    while True:
        try:
            await run_detection_cycle(es)
            await asyncio.sleep(CHECK_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            await asyncio.sleep(10)


async def main() -> None:
    """Main entry point."""
    es = AsyncElasticsearch(ES_URL)
    try:
        await run_continuous(es)
    finally:
        await es.close()


if __name__ == "__main__":
    asyncio.run(main())
