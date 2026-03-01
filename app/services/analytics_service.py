"""Analytics and aggregation logic."""
import logging
from typing import Any
from app.elasticsearch_client import get_es_client, build_time_range_filter
from app.config import settings

logger = logging.getLogger(__name__)


class AnalyticsService:
    async def get_overview(self, time_range: str = "24h") -> dict[str, Any]:
        es = get_es_client()
        time_filter = build_time_range_filter(time_range)
        body = {
            "query": {"bool": {"must": [time_filter]}},
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "severity", "size": 10}},
                "anomalies": {"filter": {"term": {"is_anomaly": True}}},
                "active_devices": {"cardinality": {"field": "device_id"}},
            },
        }
        try:
            resp = await es.search(index=settings.elasticsearch_index, body=body)
            aggs = resp.get("aggregations", {})
            severity_buckets = {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}
            return {
                "total_events": resp.get("hits", {}).get("total", {}).get("value", 0),
                "total_anomalies": aggs.get("anomalies", {}).get("doc_count", 0),
                "active_devices": aggs.get("active_devices", {}).get("value", 0),
                "critical_alerts": severity_buckets.get("critical", 0),
                "high_alerts": severity_buckets.get("high", 0),
                "medium_alerts": severity_buckets.get("medium", 0),
                "low_alerts": severity_buckets.get("low", 0),
            }
        except Exception as e:
            logger.error(f"Overview error: {e}")
            return {"total_events": 0, "total_anomalies": 0, "active_devices": 0,
                    "critical_alerts": 0, "high_alerts": 0, "medium_alerts": 0, "low_alerts": 0, "error": str(e)}

    async def get_timeline(self, time_range: str = "24h", interval: str = "1h") -> dict[str, Any]:
        es = get_es_client()
        time_filter = build_time_range_filter(time_range)
        body = {
            "query": {"bool": {"must": [time_filter]}},
            "size": 0,
            "aggs": {
                "events_over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": interval,
                        "min_doc_count": 0,
                    }
                }
            },
        }
        try:
            resp = await es.search(index=settings.elasticsearch_index, body=body)
            buckets = resp.get("aggregations", {}).get("events_over_time", {}).get("buckets", [])
            return {
                "timeline": [{"timestamp": b["key_as_string"], "count": b["doc_count"]} for b in buckets]
            }
        except Exception as e:
            logger.error(f"Timeline error: {e}")
            return {"timeline": [], "error": str(e)}

    async def get_top_threats(self, time_range: str = "24h") -> dict[str, Any]:
        es = get_es_client()
        time_filter = build_time_range_filter(time_range)
        body = {
            "query": {"bool": {"must": [time_filter]}},
            "size": 0,
            "aggs": {
                "by_event_type": {"terms": {"field": "event_type", "size": 10}}
            },
        }
        try:
            resp = await es.search(index=settings.elasticsearch_index, body=body)
            buckets = resp.get("aggregations", {}).get("by_event_type", {}).get("buckets", [])
            return {"top_threats": [{"type": b["key"], "count": b["doc_count"]} for b in buckets]}
        except Exception as e:
            logger.error(f"Top threats error: {e}")
            return {"top_threats": [], "error": str(e)}

    async def get_device_stats(self, time_range: str = "24h") -> dict[str, Any]:
        es = get_es_client()
        time_filter = build_time_range_filter(time_range)
        body = {
            "query": {"bool": {"must": [time_filter]}},
            "size": 0,
            "aggs": {
                "by_device": {
                    "terms": {"field": "device_id", "size": 20},
                    "aggs": {
                        "by_type": {"terms": {"field": "device_type", "size": 5}},
                        "anomaly_count": {"filter": {"term": {"is_anomaly": True}}},
                    },
                }
            },
        }
        try:
            resp = await es.search(index=settings.elasticsearch_index, body=body)
            buckets = resp.get("aggregations", {}).get("by_device", {}).get("buckets", [])
            devices = []
            for b in buckets:
                device_type_buckets = b.get("by_type", {}).get("buckets", [])
                device_type = device_type_buckets[0]["key"] if device_type_buckets else "unknown"
                devices.append({
                    "device_id": b["key"],
                    "device_type": device_type,
                    "event_count": b["doc_count"],
                    "anomaly_count": b.get("anomaly_count", {}).get("doc_count", 0),
                })
            return {"devices": devices}
        except Exception as e:
            logger.error(f"Device stats error: {e}")
            return {"devices": [], "error": str(e)}

    async def get_severity_distribution(self, time_range: str = "24h") -> dict[str, Any]:
        es = get_es_client()
        time_filter = build_time_range_filter(time_range)
        body = {
            "query": {"bool": {"must": [time_filter]}},
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "severity", "size": 10}}
            },
        }
        try:
            resp = await es.search(index=settings.elasticsearch_index, body=body)
            buckets = resp.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
            return {"distribution": [{"severity": b["key"], "count": b["doc_count"]} for b in buckets]}
        except Exception as e:
            logger.error(f"Severity distribution error: {e}")
            return {"distribution": [], "error": str(e)}
