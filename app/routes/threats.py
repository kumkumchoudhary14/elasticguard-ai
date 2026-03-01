"""Threat detection and management endpoints."""
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from app.services.threat_service import ThreatService

router = APIRouter()
logger = logging.getLogger(__name__)
threat_service = ThreatService()


@router.get("/api/threats")
async def list_threats(
    severity: Optional[str] = Query(default=None),
    resolved: bool = Query(default=False),
    size: int = Query(default=20, ge=1, le=100),
):
    """List detected threats/anomalies."""
    return await threat_service.list_threats(severity=severity, resolved=resolved, size=size)


@router.get("/api/threats/summary")
async def get_threat_summary():
    """AI-generated threat landscape summary."""
    return await threat_service.get_landscape_summary()


@router.get("/api/threats/{threat_id}")
async def get_threat(threat_id: str):
    """Get threat details with AI summary."""
    result = await threat_service.get_threat(threat_id=threat_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    return result


@router.post("/api/threats/analyze")
async def trigger_analysis():
    """Trigger anomaly detection on recent data."""
    return await threat_service.trigger_analysis()
