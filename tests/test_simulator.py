"""Tests for IoT simulator."""
import pytest
from iot_simulator import (
    generate_device_event,
    generate_batch,
    generate_normal_metrics,
    generate_anomalous_metrics,
    get_severity,
    generate_event_message,
    DEVICE_TYPES,
    LOCATIONS,
)


def test_generate_device_event_normal():
    """Test generating a normal device event."""
    event = generate_device_event(is_anomaly=False)
    assert "device_id" in event
    assert "device_type" in event
    assert event["device_type"] in DEVICE_TYPES
    assert "location" in event
    assert event["location"] in LOCATIONS
    assert "timestamp" in event
    assert "severity" in event
    assert event["severity"] in ("low", "medium", "high", "critical")
    assert "event_type" in event
    assert "message" in event
    assert "metrics" in event
    assert "ip_address" in event
    assert "geo_location" in event
    assert "event_id" in event
    assert isinstance(event["is_anomaly"], bool)


def test_generate_device_event_anomaly():
    """Test generating an anomalous device event."""
    event = generate_device_event(is_anomaly=True)
    assert event["is_anomaly"] is True
    assert event["severity"] in ("high", "critical")


def test_generate_batch_size():
    """Test that batch generation returns correct size."""
    batch = generate_batch(size=10)
    assert len(batch) == 10


def test_generate_batch_anomaly_probability():
    """Test that anomaly probability roughly works."""
    # With probability=1.0 all should be anomalies
    batch = generate_batch(size=50, anomaly_probability=1.0)
    assert all(e["is_anomaly"] for e in batch)

    # With probability=0.0 none should be anomalies
    batch = generate_batch(size=50, anomaly_probability=0.0)
    assert all(not e["is_anomaly"] for e in batch)


def test_generate_normal_metrics():
    """Test normal metrics generation for each device type."""
    for device_type in DEVICE_TYPES:
        metrics = generate_normal_metrics(device_type)
        assert "cpu_usage" in metrics
        assert "memory_usage" in metrics
        assert "temperature" in metrics
        assert "network_in" in metrics
        assert "network_out" in metrics
        assert 0 <= metrics["cpu_usage"] <= 100
        assert 0 <= metrics["memory_usage"] <= 100


def test_generate_anomalous_metrics_ddos():
    """Test DDoS anomaly metrics are elevated."""
    metrics = generate_anomalous_metrics("network_switch", "ddos_pattern")
    assert metrics["network_in"] > 500
    assert metrics["cpu_usage"] > 80


def test_generate_anomalous_metrics_exfiltration():
    """Test data exfiltration metrics are elevated."""
    metrics = generate_anomalous_metrics("network_switch", "data_exfiltration")
    assert metrics["network_out"] > 400


def test_generate_anomalous_metrics_temperature():
    """Test temperature anomaly metrics."""
    metrics = generate_anomalous_metrics("temperature_sensor", "temperature_anomaly")
    assert metrics["temperature"] > 60


def test_get_severity_critical():
    """Test that critical event types return critical severity."""
    assert get_severity("ddos_pattern", True) == "critical"
    assert get_severity("brute_force_attempt", True) == "critical"
    assert get_severity("door_forced", True) == "critical"


def test_get_severity_normal():
    """Test severity for non-anomaly normal events."""
    sev = get_severity("temperature_reading", False)
    assert sev in ("low", "medium")


def test_generate_event_message():
    """Test that messages are generated correctly."""
    msg = generate_event_message("network_switch", "ddos_pattern", "Marina Bay", True)
    assert "Marina Bay" in msg
    assert len(msg) > 0

    msg = generate_event_message("temperature_sensor", "temperature_reading", "Sentosa Island", False)
    assert "Sentosa Island" in msg


def test_event_has_valid_geo_location():
    """Test that geo_location has valid lat/lon."""
    event = generate_device_event(is_anomaly=False)
    geo = event["geo_location"]
    assert "lat" in geo
    assert "lon" in geo
    assert 1.0 <= geo["lat"] <= 1.5  # Singapore latitude range
    assert 103.0 <= geo["lon"] <= 104.5  # Singapore longitude range


def test_event_ip_address_format():
    """Test that IP addresses are valid."""
    event = generate_device_event(is_anomaly=False)
    parts = event["ip_address"].split(".")
    assert len(parts) == 4
