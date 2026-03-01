"""Tests for FastAPI endpoints."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def mock_es_client():
    """Mock Elasticsearch client."""
    mock = AsyncMock()
    mock.cluster.health.return_value = {
        "status": "green",
        "cluster_name": "test-cluster",
        "number_of_nodes": 1,
        "active_shards": 5,
    }
    mock.search.return_value = {
        "hits": {
            "total": {"value": 0},
            "hits": [],
        },
        "aggregations": {},
    }
    mock.get.return_value = {"found": False}
    return mock


@pytest.fixture
def client(mock_es_client):
    """Create test client with mocked Elasticsearch."""
    with patch("app.elasticsearch_client._es_client", mock_es_client):
        with patch("app.elasticsearch_client.get_es_client", return_value=mock_es_client):
            from app.main import app
            with TestClient(app) as c:
                yield c


def test_health_endpoint(client, mock_es_client):
    """Test /api/health endpoint."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "elasticsearch" in data


def test_search_endpoint(client, mock_es_client):
    """Test /api/search endpoint."""
    response = client.get("/api/search")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "events" in data


def test_search_with_query(client, mock_es_client):
    """Test /api/search with query parameters."""
    response = client.get("/api/search?q=anomaly&severity=critical")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "events" in data


def test_latest_events_endpoint(client, mock_es_client):
    """Test /api/events/latest endpoint."""
    response = client.get("/api/events/latest")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "events" in data


def test_analytics_overview(client, mock_es_client):
    """Test /api/analytics/overview endpoint."""
    mock_es_client.search.return_value = {
        "hits": {"total": {"value": 100}, "hits": []},
        "aggregations": {
            "by_severity": {"buckets": [
                {"key": "critical", "doc_count": 5},
                {"key": "high", "doc_count": 15},
            ]},
            "anomalies": {"doc_count": 10},
            "active_devices": {"value": 25},
        },
    }
    response = client.get("/api/analytics/overview")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "total_anomalies" in data
    assert "active_devices" in data


def test_analytics_timeline(client, mock_es_client):
    """Test /api/analytics/timeline endpoint."""
    mock_es_client.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {
            "events_over_time": {
                "buckets": [
                    {"key_as_string": "2024-01-01T00:00:00Z", "doc_count": 10},
                ]
            }
        },
    }
    response = client.get("/api/analytics/timeline")
    assert response.status_code == 200
    data = response.json()
    assert "timeline" in data


def test_analytics_severity_distribution(client, mock_es_client):
    """Test /api/analytics/severity-distribution endpoint."""
    mock_es_client.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {
            "by_severity": {"buckets": [
                {"key": "low", "doc_count": 50},
                {"key": "medium", "doc_count": 30},
                {"key": "high", "doc_count": 15},
                {"key": "critical", "doc_count": 5},
            ]}
        },
    }
    response = client.get("/api/analytics/severity-distribution")
    assert response.status_code == 200
    data = response.json()
    assert "distribution" in data


def test_threats_list(client, mock_es_client):
    """Test /api/threats endpoint."""
    mock_es_client.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
    }
    response = client.get("/api/threats")
    assert response.status_code == 200
    data = response.json()
    assert "threats" in data
    assert "total" in data


def test_threat_not_found(client, mock_es_client):
    """Test /api/threats/{id} returns 404 for missing threat."""
    mock_es_client.get.return_value = {"found": False}
    response = client.get("/api/threats/nonexistent-id")
    assert response.status_code == 404


def test_threat_summary(client, mock_es_client):
    """Test /api/threats/summary endpoint."""
    mock_es_client.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
    }
    response = client.get("/api/threats/summary")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "summary" in data


def test_advanced_search(client, mock_es_client):
    """Test /api/search/advanced endpoint."""
    response = client.get("/api/search/advanced?q=*")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "events" in data
