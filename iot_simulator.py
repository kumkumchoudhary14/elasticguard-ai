"""
IoT Device Telemetry Simulator for ElasticGuard AI.
Generates realistic security-relevant logs from simulated IoT devices.
"""
import asyncio
import json
import logging
import os
import random
import uuid
from datetime import datetime, timezone
from typing import Any

import numpy as np
from dotenv import load_dotenv
from elasticsearch import AsyncElasticsearch

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ES_INDEX = os.getenv("ELASTICSEARCH_INDEX", "iot-security-events")
SIMULATOR_INTERVAL = float(os.getenv("SIMULATOR_INTERVAL", "2"))
ANOMALY_PROBABILITY = float(os.getenv("ANOMALY_PROBABILITY", "0.15"))

# Singapore-themed locations
LOCATIONS = [
    "Marina Bay", "Sentosa Island", "Changi Airport", "Orchard Road",
    "Clarke Quay", "Bugis Junction", "Raffles Place", "Toa Payoh",
    "Jurong East", "Woodlands", "Tampines", "Bishan"
]

# IP ranges for simulation
IP_RANGES = ["10.1.", "10.2.", "192.168.1.", "192.168.2.", "172.16.0.", "172.16.1."]

DEVICE_TYPES = ["temperature_sensor", "security_camera", "access_controller", "network_switch"]

DEVICE_IDS: dict[str, list[str]] = {
    "temperature_sensor": [f"TEMP-{i:04d}" for i in range(1, 11)],
    "security_camera": [f"CAM-{i:04d}" for i in range(1, 9)],
    "access_controller": [f"ACC-{i:04d}" for i in range(1, 7)],
    "network_switch": [f"NET-{i:04d}" for i in range(1, 5)],
}

EVENT_TYPES: dict[str, list[str]] = {
    "temperature_sensor": ["temperature_reading", "threshold_alert", "sensor_calibration", "battery_low"],
    "security_camera": ["motion_detected", "recording_started", "recording_stopped", "tamper_alert", "face_detected"],
    "access_controller": ["access_granted", "access_denied", "door_opened", "door_forced", "credential_fail"],
    "access_controller_anomaly": ["brute_force_attempt", "unauthorized_access", "credential_stuffing"],
    "network_switch": ["traffic_spike", "port_scan", "connection_established", "bandwidth_alert", "vlan_change"],
    "network_switch_anomaly": ["ddos_pattern", "data_exfiltration", "port_scan_flood"],
}

GEO_COORDINATES: dict[str, tuple[float, float]] = {
    "Marina Bay": (1.2819, 103.8636),
    "Sentosa Island": (1.2494, 103.8303),
    "Changi Airport": (1.3644, 103.9915),
    "Orchard Road": (1.3048, 103.8318),
    "Clarke Quay": (1.2905, 103.8462),
    "Bugis Junction": (1.2999, 103.8559),
    "Raffles Place": (1.2840, 103.8510),
    "Toa Payoh": (1.3340, 103.8484),
    "Jurong East": (1.3329, 103.7436),
    "Woodlands": (1.4382, 103.7890),
    "Tampines": (1.3540, 103.9450),
    "Bishan": (1.3520, 103.8480),
}


def generate_normal_metrics(device_type: str) -> dict[str, float]:
    """Generate realistic normal metrics based on device type."""
    base: dict[str, float] = {
        "cpu_usage": round(random.uniform(10, 40), 2),
        "memory_usage": round(random.uniform(20, 60), 2),
        "temperature": round(random.uniform(20, 35), 2),
        "network_in": round(random.uniform(0.1, 5.0), 2),
        "network_out": round(random.uniform(0.1, 3.0), 2),
    }
    if device_type == "temperature_sensor":
        base["temperature"] = round(random.uniform(18, 30), 2)
        base["cpu_usage"] = round(random.uniform(5, 20), 2)
    elif device_type == "security_camera":
        base["cpu_usage"] = round(random.uniform(30, 60), 2)
        base["memory_usage"] = round(random.uniform(40, 70), 2)
        base["network_out"] = round(random.uniform(5.0, 15.0), 2)
    elif device_type == "access_controller":
        base["cpu_usage"] = round(random.uniform(10, 30), 2)
    elif device_type == "network_switch":
        base["network_in"] = round(random.uniform(10, 100), 2)
        base["network_out"] = round(random.uniform(10, 100), 2)
    return base


def generate_anomalous_metrics(device_type: str, anomaly_type: str) -> dict[str, float]:
    """Generate anomalous metrics for various attack patterns."""
    metrics = generate_normal_metrics(device_type)
    if anomaly_type == "ddos_pattern":
        metrics["network_in"] = round(random.uniform(800, 1000), 2)
        metrics["cpu_usage"] = round(random.uniform(85, 99), 2)
    elif anomaly_type == "data_exfiltration":
        metrics["network_out"] = round(random.uniform(500, 900), 2)
        metrics["cpu_usage"] = round(random.uniform(70, 90), 2)
    elif anomaly_type == "temperature_anomaly":
        metrics["temperature"] = round(random.uniform(65, 90), 2)
    elif anomaly_type == "brute_force_attempt":
        metrics["cpu_usage"] = round(random.uniform(75, 95), 2)
        metrics["memory_usage"] = round(random.uniform(80, 95), 2)
    elif anomaly_type == "port_scan_flood":
        metrics["network_in"] = round(random.uniform(300, 600), 2)
        metrics["cpu_usage"] = round(random.uniform(60, 80), 2)
    return metrics


def generate_event_message(device_type: str, event_type: str, location: str, is_anomaly: bool) -> str:
    """Generate a contextual event message."""
    messages: dict[str, str] = {
        "temperature_reading": f"Normal temperature reading at {location} facility",
        "threshold_alert": f"Temperature threshold exceeded at {location} — check HVAC system",
        "sensor_calibration": f"Sensor auto-calibration completed at {location}",
        "battery_low": f"Battery level critical on sensor at {location}",
        "motion_detected": f"Motion detected in surveillance zone at {location}",
        "recording_started": f"Video recording initiated at {location} camera",
        "recording_stopped": f"Video recording stopped at {location} camera",
        "tamper_alert": f"ALERT: Camera tamper detected at {location}!",
        "face_detected": f"Unrecognized face detected at {location} entry point",
        "access_granted": f"Authorized access granted at {location} entry",
        "access_denied": f"Access denied — invalid credentials at {location}",
        "door_opened": f"Door opened at {location} checkpoint",
        "door_forced": f"ALERT: Forced door entry detected at {location}!",
        "credential_fail": f"Failed authentication attempt at {location} controller",
        "brute_force_attempt": f"CRITICAL: Brute force attack detected at {location} access controller",
        "unauthorized_access": f"CRITICAL: Unauthorized access attempt at {location}",
        "credential_stuffing": f"CRITICAL: Credential stuffing attack at {location}",
        "traffic_spike": f"Unusual traffic spike detected on network at {location}",
        "port_scan": f"Port scan detected originating from {location} subnet",
        "connection_established": f"New connection established on {location} network switch",
        "bandwidth_alert": f"Bandwidth usage exceeded threshold at {location}",
        "vlan_change": f"VLAN configuration changed at {location} switch",
        "ddos_pattern": f"CRITICAL: DDoS attack pattern detected at {location} network",
        "data_exfiltration": f"CRITICAL: Potential data exfiltration detected at {location}",
        "port_scan_flood": f"CRITICAL: Port scan flood from {location} — possible network reconnaissance",
        "temperature_anomaly": f"CRITICAL: Extreme temperature anomaly at {location} — possible hardware fire risk",
    }
    return messages.get(event_type, f"Security event {event_type} at {location}")


def get_severity(event_type: str, is_anomaly: bool) -> str:
    """Determine event severity."""
    critical_events = {
        "tamper_alert", "door_forced", "brute_force_attempt", "unauthorized_access",
        "credential_stuffing", "ddos_pattern", "data_exfiltration", "port_scan_flood",
        "temperature_anomaly"
    }
    high_events = {
        "threshold_alert", "face_detected", "access_denied", "credential_fail",
        "traffic_spike", "port_scan", "bandwidth_alert"
    }
    if is_anomaly or event_type in critical_events:
        return "critical"
    if event_type in high_events:
        return "high"
    if random.random() < 0.2:
        return "medium"
    return "low"


def generate_device_event(is_anomaly: bool = False) -> dict[str, Any]:
    """Generate a single device event."""
    device_type = random.choice(DEVICE_TYPES)
    device_id = random.choice(DEVICE_IDS[device_type])
    location = random.choice(LOCATIONS)
    ip_suffix = random.randint(1, 254)
    ip_range = random.choice(IP_RANGES)
    ip_address = f"{ip_range}{ip_suffix}"
    geo = GEO_COORDINATES[location]

    # Determine event type
    anomaly_type = None
    if is_anomaly:
        if device_type == "access_controller":
            event_type = random.choice(EVENT_TYPES["access_controller_anomaly"])
            anomaly_type = event_type
        elif device_type == "network_switch":
            event_type = random.choice(EVENT_TYPES["network_switch_anomaly"])
            anomaly_type = event_type
        elif device_type == "temperature_sensor":
            event_type = "threshold_alert"
            anomaly_type = "temperature_anomaly"
        else:
            event_type = random.choice(EVENT_TYPES.get(device_type, ["motion_detected"]))
            anomaly_type = None
    else:
        event_type = random.choice(EVENT_TYPES.get(device_type, ["motion_detected"]))

    metrics = (
        generate_anomalous_metrics(device_type, anomaly_type)
        if anomaly_type
        else generate_normal_metrics(device_type)
    )

    now = datetime.now(timezone.utc)
    return {
        "device_id": device_id,
        "device_type": device_type,
        "location": location,
        "timestamp": now.isoformat(),
        "@timestamp": now.isoformat(),
        "severity": get_severity(event_type, is_anomaly),
        "event_type": event_type,
        "message": generate_event_message(device_type, event_type, location, is_anomaly),
        "metrics": metrics,
        "ip_address": ip_address,
        "geo_location": {"lat": geo[0], "lon": geo[1]},
        "is_anomaly": is_anomaly,
        "event_id": str(uuid.uuid4()),
    }


def generate_batch(size: int = 20, anomaly_probability: float = ANOMALY_PROBABILITY) -> list[dict[str, Any]]:
    """Generate a batch of device events."""
    events = []
    for _ in range(size):
        is_anomaly = random.random() < anomaly_probability
        events.append(generate_device_event(is_anomaly=is_anomaly))
    return events


async def ingest_batch(es: AsyncElasticsearch, events: list[dict[str, Any]]) -> None:
    """Ingest a batch of events into Elasticsearch using bulk API."""
    body = []
    for event in events:
        body.append({"index": {"_index": ES_INDEX}})
        body.append(event)
    response = await es.bulk(body=body)
    if response.get("errors"):
        errors = [item for item in response["items"] if item.get("index", {}).get("error")]
        logger.warning(f"Bulk ingestion had {len(errors)} errors")
    else:
        logger.info(f"Ingested {len(events)} events successfully")


async def run_continuous(es: AsyncElasticsearch) -> None:
    """Run the simulator continuously."""
    logger.info(f"Starting IoT simulator with interval={SIMULATOR_INTERVAL}s, anomaly_prob={ANOMALY_PROBABILITY}")
    while True:
        try:
            events = generate_batch(size=random.randint(5, 15), anomaly_probability=ANOMALY_PROBABILITY)
            await ingest_batch(es, events)
            await asyncio.sleep(SIMULATOR_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Simulator error: {e}")
            await asyncio.sleep(5)


async def main() -> None:
    """Main entry point for the simulator."""
    es = AsyncElasticsearch(ES_URL)
    try:
        logger.info(f"Connecting to Elasticsearch at {ES_URL}")
        await run_continuous(es)
    finally:
        await es.close()


if __name__ == "__main__":
    asyncio.run(main())
