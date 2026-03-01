"""In-memory mock data store for running without Elasticsearch."""
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

_DEVICE_TYPES = ["temperature_sensor", "security_camera", "access_controller", "network_switch"]
_SEVERITIES = ["low", "medium", "high", "critical"]
_LOCATIONS = ["Marina Bay", "Changi Airport", "Sentosa", "Orchard Road", "Jurong East", "Woodlands"]
_EVENT_TYPES = [
    "login_attempt", "firmware_update", "config_change", "port_scan",
    "data_transfer", "auth_failure", "connection_established", "packet_anomaly",
    "cpu_spike", "memory_overflow", "temperature_alert", "access_denied",
]
_THREAT_CATEGORIES = [
    "brute_force", "ddos", "data_exfiltration", "unauthorized_access",
    "network_scan", "device_tampering",
]
_IPS = [
    f"192.168.1.{i}" for i in range(10, 50)
] + [
    f"10.0.0.{i}" for i in range(1, 30)
]


def _rand_ts(hours_ago_max: float = 24.0) -> str:
    offset = random.uniform(0, hours_ago_max * 3600)
    ts = datetime.now(timezone.utc) - timedelta(seconds=offset)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_events(count: int = 120) -> list[dict[str, Any]]:
    events = []
    for _ in range(count):
        severity = random.choices(_SEVERITIES, weights=[40, 30, 20, 10])[0]
        device_type = random.choice(_DEVICE_TYPES)
        device_num = random.randint(1, 20)
        device_id = f"{device_type.replace('_', '-')}-{device_num:03d}"
        is_anomaly = severity in ("high", "critical") and random.random() < 0.5
        events.append({
            "id": str(uuid.uuid4()),
            "@timestamp": _rand_ts(),
            "device_id": device_id,
            "device_type": device_type,
            "event_type": random.choice(_EVENT_TYPES),
            "severity": severity,
            "location": random.choice(_LOCATIONS),
            "source_ip": random.choice(_IPS),
            "message": f"{severity.upper()} event on {device_id}",
            "is_anomaly": is_anomaly,
            "geo_location": {"lat": random.uniform(1.25, 1.45), "lon": random.uniform(103.6, 104.0)},
            "metrics": {
                "cpu_usage": round(random.uniform(10, 95), 1),
                "memory_usage": round(random.uniform(20, 90), 1),
                "temperature": round(random.uniform(25, 85), 1),
                "network_in": round(random.uniform(0, 500), 2),
                "network_out": round(random.uniform(0, 500), 2),
            },
        })
    return events


def _generate_anomalies(count: int = 20) -> list[dict[str, Any]]:
    _actions = {
        "brute_force": "Block source IP and enforce MFA",
        "ddos": "Rate-limit traffic and alert NOC",
        "data_exfiltration": "Isolate device and audit data flows",
        "unauthorized_access": "Revoke credentials and review ACLs",
        "network_scan": "Block scanner and review firewall rules",
        "device_tampering": "Quarantine device and restore firmware",
    }
    anomalies = []
    for _ in range(count):
        category = random.choice(_THREAT_CATEGORIES)
        severity = random.choices(["medium", "high", "critical"], weights=[30, 40, 30])[0]
        device_type = random.choice(_DEVICE_TYPES)
        device_num = random.randint(1, 20)
        device_id = f"{device_type.replace('_', '-')}-{device_num:03d}"
        anomalies.append({
            "id": str(uuid.uuid4()),
            "@timestamp": _rand_ts(),
            "device_id": device_id,
            "device_type": device_type,
            "threat_category": category,
            "severity": severity,
            "threat_score": round(random.uniform(0.6, 1.0), 3),
            "description": f"Detected {category.replace('_', ' ')} activity on {device_id}",
            "recommended_action": _actions[category],
            "source_ip": random.choice(_IPS),
            "location": random.choice(_LOCATIONS),
            "resolved": False,
        })
    return anomalies


class MockDataService:
    """Singleton in-memory data store."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = _generate_events(120)
        self.anomalies: list[dict[str, Any]] = _generate_anomalies(20)

    # ------------------------------------------------------------------ #
    # Search helpers                                                       #
    # ------------------------------------------------------------------ #

    def _time_cutoff(self, time_range: str) -> datetime:
        hours = {"1h": 1, "6h": 6, "12h": 12, "24h": 24, "7d": 168, "30d": 720}
        h = hours.get(time_range, 24)
        return datetime.now(timezone.utc) - timedelta(hours=h)

    def search(
        self,
        query: str = "",
        severity: str | None = None,
        device_type: str | None = None,
        time_range: str = "24h",
        size: int = 20,
        from_: int = 0,
    ) -> dict[str, Any]:
        cutoff = self._time_cutoff(time_range)
        results = []
        for e in self.events:
            ts = datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
            if severity and e["severity"] != severity:
                continue
            if device_type and e["device_type"] != device_type:
                continue
            if query:
                q = query.lower()
                searchable = " ".join([
                    e.get("message", ""), e.get("event_type", ""),
                    e.get("device_id", ""), e.get("location", ""),
                ]).lower()
                if q not in searchable:
                    continue
            results.append(e)
        results.sort(key=lambda x: x["@timestamp"], reverse=True)
        page = results[from_: from_ + size]
        return {"total": len(results), "events": page}

    def get_latest(self, size: int = 20, severity: str | None = None) -> dict[str, Any]:
        results = self.events if not severity else [e for e in self.events if e["severity"] == severity]
        results = sorted(results, key=lambda x: x["@timestamp"], reverse=True)
        return {"total": len(results), "events": results[:size]}

    # ------------------------------------------------------------------ #
    # Analytics helpers                                                    #
    # ------------------------------------------------------------------ #

    def get_overview(self, time_range: str = "24h") -> dict[str, Any]:
        cutoff = self._time_cutoff(time_range)
        events = [
            e for e in self.events
            if datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) >= cutoff
        ]
        severity_counts: dict[str, int] = {}
        anomaly_count = 0
        device_ids: set[str] = set()
        for e in events:
            severity_counts[e["severity"]] = severity_counts.get(e["severity"], 0) + 1
            if e.get("is_anomaly"):
                anomaly_count += 1
            device_ids.add(e["device_id"])
        return {
            "total_events": len(events),
            "total_anomalies": anomaly_count,
            "active_devices": len(device_ids),
            "critical_alerts": severity_counts.get("critical", 0),
            "high_alerts": severity_counts.get("high", 0),
            "medium_alerts": severity_counts.get("medium", 0),
            "low_alerts": severity_counts.get("low", 0),
        }

    def get_timeline(self, time_range: str = "24h", interval: str = "1h") -> dict[str, Any]:
        cutoff = self._time_cutoff(time_range)
        interval_hours = {"1h": 1, "3h": 3, "6h": 6, "12h": 12, "1d": 24}.get(interval, 1)
        buckets: dict[str, int] = {}
        for e in self.events:
            ts = datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
            bucket_ts = ts.replace(
                minute=0, second=0, microsecond=0,
                hour=(ts.hour // interval_hours) * interval_hours,
            )
            key = bucket_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
            buckets[key] = buckets.get(key, 0) + 1
        timeline = [{"timestamp": k, "count": v} for k, v in sorted(buckets.items())]
        return {"timeline": timeline}

    def get_top_threats(self, time_range: str = "24h") -> dict[str, Any]:
        cutoff = self._time_cutoff(time_range)
        counts: dict[str, int] = {}
        for e in self.events:
            ts = datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
            et = e["event_type"]
            counts[et] = counts.get(et, 0) + 1
        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
        return {"top_threats": [{"type": t, "count": c} for t, c in top]}

    def get_device_stats(self, time_range: str = "24h") -> dict[str, Any]:
        cutoff = self._time_cutoff(time_range)
        stats: dict[str, dict[str, Any]] = {}
        for e in self.events:
            ts = datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
            did = e["device_id"]
            if did not in stats:
                stats[did] = {"device_id": did, "device_type": e["device_type"], "event_count": 0, "anomaly_count": 0}
            stats[did]["event_count"] += 1
            if e.get("is_anomaly"):
                stats[did]["anomaly_count"] += 1
        devices = sorted(stats.values(), key=lambda x: x["event_count"], reverse=True)[:20]
        return {"devices": devices}

    def get_severity_distribution(self, time_range: str = "24h") -> dict[str, Any]:
        cutoff = self._time_cutoff(time_range)
        counts: dict[str, int] = {}
        for e in self.events:
            ts = datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
            s = e["severity"]
            counts[s] = counts.get(s, 0) + 1
        distribution = [{"severity": s, "count": c} for s, c in counts.items()]
        return {"distribution": distribution}

    # ------------------------------------------------------------------ #
    # Threat helpers                                                       #
    # ------------------------------------------------------------------ #

    def list_threats(
        self,
        severity: str | None = None,
        resolved: bool = False,
        size: int = 20,
    ) -> dict[str, Any]:
        results = [a for a in self.anomalies if a["resolved"] == resolved]
        if severity:
            results = [a for a in results if a["severity"] == severity]
        results = sorted(results, key=lambda x: x["@timestamp"], reverse=True)
        return {"total": len(results), "threats": results[:size]}

    def get_threat(self, threat_id: str) -> dict[str, Any] | None:
        for a in self.anomalies:
            if a["id"] == threat_id:
                return a
        return None

    def get_landscape_summary(self) -> dict[str, Any]:
        active = [a for a in self.anomalies if not a["resolved"]]
        category_counts: dict[str, int] = {}
        for a in active:
            cat = a["threat_category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1
        top_cat = max(category_counts, key=lambda k: category_counts[k]) if category_counts else "none"
        return {
            "status": "mock",
            "summary": (
                f"Demo mode active. {len(active)} active threats detected. "
                f"Top threat category: {top_cat.replace('_', ' ')}. "
                "Deploy Elasticsearch for live analysis."
            ),
            "active_threats": len(active),
            "top_category": top_cat,
            "category_breakdown": category_counts,
        }


# Module-level singleton
mock_data_service = MockDataService()
