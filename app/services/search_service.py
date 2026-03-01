"""Elasticsearch search logic."""
import logging
from typing import Any, Optional
from app.elasticsearch_client import get_es_client, build_time_range_filter
from app.config import settings

logger = logging.getLogger(__name__)


class SearchService:
    def _format_hits(self, hits: list[dict]) -> list[dict[str, Any]]:
        return [{"id": h["_id"], **h["_source"]} for h in hits]

    async def search(
        self,
        query: str = "",
        severity: Optional[str] = None,
        device_type: Optional[str] = None,
        time_range: str = "24h",
        size: int = 20,
    ) -> dict[str, Any]:
        es = get_es_client()
        must = [build_time_range_filter(time_range)]
        if query:
            must.append({"multi_match": {"query": query, "fields": ["message", "event_type", "device_id", "location"]}})
        if severity:
            must.append({"term": {"severity": severity}})
        if device_type:
            must.append({"term": {"device_type": device_type}})

        body = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": size,
        }
        try:
            resp = await es.search(index=settings.elasticsearch_index, body=body)
            hits = resp.get("hits", {})
            return {
                "total": hits.get("total", {}).get("value", 0),
                "events": self._format_hits(hits.get("hits", [])),
            }
        except Exception as e:
            logger.error(f"Search error: {e}")
            return {"total": 0, "events": [], "error": str(e)}

    async def advanced_search(self, query: str = "*", time_range: str = "24h", size: int = 20) -> dict[str, Any]:
        es = get_es_client()
        body = {
            "query": {
                "bool": {
                    "must": [
                        build_time_range_filter(time_range),
                        {"query_string": {"query": query, "default_field": "message"}},
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": size,
        }
        try:
            resp = await es.search(index=settings.elasticsearch_index, body=body)
            hits = resp.get("hits", {})
            return {
                "total": hits.get("total", {}).get("value", 0),
                "events": self._format_hits(hits.get("hits", [])),
            }
        except Exception as e:
            logger.error(f"Advanced search error: {e}")
            return {"total": 0, "events": [], "error": str(e)}

    async def get_latest(self, size: int = 20, severity: Optional[str] = None) -> dict[str, Any]:
        es = get_es_client()
        must: list[Any] = []
        if severity:
            must.append({"term": {"severity": severity}})
        body = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": size,
        }
        try:
            resp = await es.search(index=settings.elasticsearch_index, body=body)
            hits = resp.get("hits", {})
            return {
                "total": hits.get("total", {}).get("value", 0),
                "events": self._format_hits(hits.get("hits", [])),
            }
        except Exception as e:
            logger.error(f"Latest events error: {e}")
            return {"total": 0, "events": [], "error": str(e)}
