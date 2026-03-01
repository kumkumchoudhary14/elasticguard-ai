"""Elasticsearch connection and helper functions."""
import logging
from typing import Any, Optional
from elasticsearch import AsyncElasticsearch
from app.config import settings

logger = logging.getLogger(__name__)

_es_client: Optional[AsyncElasticsearch] = None

# Set to True when Elasticsearch is not reachable
MOCK_MODE: bool = False


def get_es_client() -> AsyncElasticsearch:
    """Get or create Elasticsearch client."""
    global _es_client
    if _es_client is None:
        _es_client = AsyncElasticsearch(
            settings.elasticsearch_url,
            request_timeout=30,
            retry_on_timeout=True,
            max_retries=3,
        )
    return _es_client


async def close_es_client() -> None:
    """Close the Elasticsearch client."""
    global _es_client
    if _es_client is not None:
        await _es_client.close()
        _es_client = None


async def check_es_connectivity() -> bool:
    """Return True if Elasticsearch is reachable, False otherwise."""
    global MOCK_MODE
    es = get_es_client()
    try:
        await es.cluster.health(request_timeout=5)
        MOCK_MODE = False
        return True
    except Exception as e:
        logger.warning(f"Elasticsearch not available — running in mock data mode ({e})")
        MOCK_MODE = True
        return False


async def check_es_health() -> dict[str, Any]:
    """Check Elasticsearch cluster health."""
    es = get_es_client()
    try:
        health = await es.cluster.health()
        return {
            "status": health.get("status", "unknown"),
            "cluster_name": health.get("cluster_name", "unknown"),
            "number_of_nodes": health.get("number_of_nodes", 0),
            "active_shards": health.get("active_shards", 0),
        }
    except Exception as e:
        logger.error(f"Elasticsearch health check failed: {e}")
        return {"status": "red", "error": str(e)}


def build_time_range_filter(time_range: str) -> dict[str, Any]:
    """Build an Elasticsearch time range filter."""
    ranges = {
        "1h": "now-1h",
        "6h": "now-6h",
        "12h": "now-12h",
        "24h": "now-24h",
        "7d": "now-7d",
        "30d": "now-30d",
    }
    gte = ranges.get(time_range, "now-24h")
    return {"range": {"@timestamp": {"gte": gte, "lte": "now"}}}
