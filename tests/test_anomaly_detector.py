"""Tests for anomaly detection."""
import numpy as np
import pytest
from anomaly_detector import (
    compute_zscore,
    detect_zscore_anomalies,
    detect_isolation_forest_anomalies,
    classify_anomaly,
)


def make_event(cpu=20.0, memory=30.0, temp=25.0, net_in=1.0, net_out=1.0, device_type="network_switch", event_type="connection_established"):
    return {
        "device_id": "TEST-001",
        "device_type": device_type,
        "event_type": event_type,
        "location": "Marina Bay",
        "message": "Test event",
        "metrics": {
            "cpu_usage": cpu,
            "memory_usage": memory,
            "temperature": temp,
            "network_in": net_in,
            "network_out": net_out,
        },
        "severity": "low",
        "is_anomaly": False,
    }


def test_compute_zscore_normal():
    """Test Z-score computation for normal data."""
    values = np.array([10.0, 12.0, 11.0, 10.5, 11.5])
    zscores = compute_zscore(values)
    assert len(zscores) == 5
    assert all(z < 3.0 for z in zscores)


def test_compute_zscore_outlier():
    """Test Z-score detection of outlier."""
    # Need enough normal values so the outlier stands out (z-score > 3)
    values = np.array([10.0] * 19 + [100.0])
    zscores = compute_zscore(values)
    assert zscores[-1] > 3.0  # Last value is outlier


def test_compute_zscore_zero_std():
    """Test Z-score with constant values (zero std)."""
    values = np.array([5.0, 5.0, 5.0, 5.0])
    zscores = compute_zscore(values)
    assert all(z == 0.0 for z in zscores)


def test_compute_zscore_too_few():
    """Test Z-score with fewer than 3 values."""
    values = np.array([1.0, 2.0])
    zscores = compute_zscore(values)
    assert all(z == 0.0 for z in zscores)


def test_detect_zscore_anomalies_normal():
    """Test that normal events produce no Z-score anomalies."""
    events = [make_event() for _ in range(10)]
    anomalies = detect_zscore_anomalies(events)
    assert len(anomalies) == 0


def test_detect_zscore_anomalies_spike():
    """Test that a metric spike is detected."""
    events = [make_event(cpu=20.0) for _ in range(19)]
    events.append(make_event(cpu=990.0))  # Massive spike
    anomalies = detect_zscore_anomalies(events)
    assert len(anomalies) > 0
    # The spike should be at index 19
    spiked_indices = [idx for idx, _, metric in anomalies if metric == "cpu_usage"]
    assert 19 in spiked_indices


def test_detect_isolation_forest_too_few():
    """Test that Isolation Forest returns empty for too few events."""
    events = [make_event() for _ in range(5)]
    anomalies = detect_isolation_forest_anomalies(events)
    assert anomalies == []


def test_detect_isolation_forest_with_anomaly():
    """Test Isolation Forest detection with injected anomaly."""
    # Normal events
    events = [make_event(cpu=20.0, memory=30.0, net_in=1.0, net_out=1.0) for _ in range(20)]
    # Inject clear outlier
    events.append(make_event(cpu=99.0, memory=99.0, net_in=999.0, net_out=999.0))
    anomalies = detect_isolation_forest_anomalies(events)
    # Should detect at least one anomaly
    assert len(anomalies) > 0


def test_classify_anomaly_ddos():
    """Test that DDoS metrics are correctly classified."""
    event = make_event(net_in=900.0)
    classification = classify_anomaly(event, 85.0, "network_in")
    assert classification["threat_category"] == "ddos"
    assert classification["severity"] == "critical"
    assert "DDoS" in classification["recommended_action"] or "ddos" in classification["recommended_action"].lower()


def test_classify_anomaly_exfiltration():
    """Test data exfiltration classification."""
    event = make_event(net_out=600.0)
    classification = classify_anomaly(event, 70.0, "network_out")
    assert classification["threat_category"] == "data_exfiltration"
    assert classification["severity"] == "high"


def test_classify_anomaly_unauthorized_access():
    """Test unauthorized access classification."""
    event = make_event(device_type="access_controller", event_type="brute_force_attempt")
    classification = classify_anomaly(event, 60.0)
    assert classification["threat_category"] == "unauthorized_access"


def test_classify_anomaly_severity_levels():
    """Test that anomaly scores map to correct severity levels."""
    event = make_event()
    assert classify_anomaly(event, 90.0)["severity"] == "critical"
    assert classify_anomaly(event, 70.0)["severity"] == "high"
    assert classify_anomaly(event, 50.0)["severity"] == "medium"
    assert classify_anomaly(event, 10.0)["severity"] == "low"
