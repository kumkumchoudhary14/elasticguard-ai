"""Search API endpoints."""
import logging
from typing import Optional
from fastapi import APIRouter, Query
from app.services.search_service import SearchService

router = APIRouter()
logger = logging.getLogger(__name__)
search_service = SearchService()


@router.get("/api/search")
async def search_events(
    q: str = Query(default="", description="Search query"),
    severity: Optional[str] = Query(default=None),
    device_type: Optional[str] = Query(default=None),
    time_range: str = Query(default="24h"),
    size: int = Query(default=20, ge=1, le=100),
):
    """Full-text search across security events with filters."""
    return await search_service.search(
        query=q, severity=severity, device_type=device_type,
        time_range=time_range, size=size
    )


@router.get("/api/search/advanced")
async def advanced_search(
    q: str = Query(default="*"),
    time_range: str = Query(default="24h"),
    size: int = Query(default=20, ge=1, le=100),
):
    """Advanced search with Elasticsearch DSL query support."""
    return await search_service.advanced_search(query=q, time_range=time_range, size=size)


@router.get("/api/events/latest")
async def get_latest_events(
    size: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = Query(default=None),
):
    """Get the latest N security events."""
    return await search_service.get_latest(size=size, severity=severity)
