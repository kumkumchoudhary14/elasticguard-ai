"""Health check endpoints."""
import logging
from fastapi import APIRouter
from app.elasticsearch_client import check_es_health

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/api/health")
async def health_check():
    """Check application and Elasticsearch health."""
    es_health = await check_es_health()
    app_status = "healthy" if es_health.get("status") in ("green", "yellow") else "degraded"
    return {
        "status": app_status,
        "elasticsearch": es_health,
        "service": "ElasticGuard AI",
    }
