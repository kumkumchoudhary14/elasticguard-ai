"""Analytics endpoints."""
import logging
from fastapi import APIRouter, Query
from app.services.analytics_service import AnalyticsService

router = APIRouter()
logger = logging.getLogger(__name__)
analytics_service = AnalyticsService()


@router.get("/api/analytics/overview")
async def get_overview(time_range: str = Query(default="24h")):
    """Dashboard overview stats."""
    return await analytics_service.get_overview(time_range=time_range)


@router.get("/api/analytics/timeline")
async def get_timeline(
    time_range: str = Query(default="24h"),
    interval: str = Query(default="1h"),
):
    """Event timeline aggregation."""
    return await analytics_service.get_timeline(time_range=time_range, interval=interval)


@router.get("/api/analytics/top-threats")
async def get_top_threats(time_range: str = Query(default="24h")):
    """Top threat categories."""
    return await analytics_service.get_top_threats(time_range=time_range)


@router.get("/api/analytics/device-stats")
async def get_device_stats(time_range: str = Query(default="24h")):
    """Per-device statistics."""
    return await analytics_service.get_device_stats(time_range=time_range)


@router.get("/api/analytics/severity-distribution")
async def get_severity_distribution(time_range: str = Query(default="24h")):
    """Severity breakdown."""
    return await analytics_service.get_severity_distribution(time_range=time_range)
