"""Pydantic models for ElasticGuard AI."""
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class GeoLocation(BaseModel):
    lat: float
    lon: float


class DeviceMetrics(BaseModel):
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    temperature: float = 0.0
    network_in: float = 0.0
    network_out: float = 0.0


class SecurityEvent(BaseModel):
    event_id: Optional[str] = None
    device_id: str
    device_type: str
    location: str
    timestamp: str
    severity: str
    event_type: str
    message: str
    metrics: DeviceMetrics
    ip_address: str
    geo_location: Optional[GeoLocation] = None
    is_anomaly: bool = False


class AnomalyAlert(BaseModel):
    id: Optional[str] = None
    timestamp: str
    device_id: str
    device_type: str
    location: Optional[str] = None
    anomaly_type: str
    anomaly_score: float
    severity: str
    threat_category: str
    description: str
    recommended_action: str
    resolved: bool = False


class ThreatSummary(BaseModel):
    threat_id: str
    category: str
    severity: str
    threat_score: int
    device_id: str
    device_type: str
    location: str
    timestamp: str
    description: str
    summary: str
    remediation_steps: list[str]
    anomaly_score: float


class SearchQuery(BaseModel):
    query: str = ""
    severity: Optional[str] = None
    device_type: Optional[str] = None
    time_range: Optional[str] = "24h"
    size: int = Field(default=20, ge=1, le=100)


class AnalyticsResponse(BaseModel):
    total_events: int
    total_anomalies: int
    active_devices: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int


class DashboardStats(BaseModel):
    total_events: int = 0
    active_threats: int = 0
    critical_alerts: int = 0
    active_devices: int = 0
    events_per_minute: float = 0.0
    threat_trend: str = "stable"
