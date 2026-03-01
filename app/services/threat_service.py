"""Threat detection service logic."""
import logging
from typing import Any, Optional
from app.elasticsearch_client import get_es_client
from app.config import settings
from threat_intelligence import generate_threat_summary, generate_landscape_summary

logger = logging.getLogger(__name__)


class ThreatService:
    async def list_threats(
        self,
        severity: Optional[str] = None,
        resolved: bool = False,
        size: int = 20,
    ) -> dict[str, Any]:
        es = get_es_client()
        must: list[Any] = [{"term": {"resolved": resolved}}]
        if severity:
            must.append({"term": {"severity": severity}})
        body = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": size,
        }
        try:
            resp = await es.search(index=settings.anomaly_index, body=body)
            hits = resp.get("hits", {})
            threats = [{"id": h["_id"], **h["_source"]} for h in hits.get("hits", [])]
            return {
                "total": hits.get("total", {}).get("value", 0),
                "threats": threats,
            }
        except Exception as e:
            logger.error(f"List threats error: {e}")
            return {"total": 0, "threats": [], "error": str(e)}

    async def get_threat(self, threat_id: str) -> Optional[dict[str, Any]]:
        es = get_es_client()
        try:
            resp = await es.get(index=settings.anomaly_index, id=threat_id)
            if not resp.get("found"):
                return None
            anomaly = {"_id": threat_id, **resp["_source"]}
            summary = generate_threat_summary(anomaly)
            return {**anomaly, "ai_summary": summary}
        except Exception as e:
            logger.error(f"Get threat error: {e}")
            return None

    async def get_landscape_summary(self) -> dict[str, Any]:
        es = get_es_client()
        body = {
            "query": {"term": {"resolved": False}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 100,
        }
        try:
            resp = await es.search(index=settings.anomaly_index, body=body)
            anomalies = [h["_source"] for h in resp.get("hits", {}).get("hits", [])]
            return generate_landscape_summary(anomalies)
        except Exception as e:
            logger.error(f"Landscape summary error: {e}")
            return generate_landscape_summary([])

    async def trigger_analysis(self) -> dict[str, Any]:
        """Trigger a fresh anomaly detection cycle."""
        try:
            from anomaly_detector import run_detection_cycle
            es = get_es_client()
            count = await run_detection_cycle(es)
            return {"status": "completed", "anomalies_detected": count}
        except Exception as e:
            logger.error(f"Trigger analysis error: {e}")
            return {"status": "error", "message": str(e)}
