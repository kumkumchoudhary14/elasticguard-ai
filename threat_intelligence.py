"""
AI-powered threat intelligence and summarization for ElasticGuard AI.
Uses rule-based and template approaches (no external LLM API required).
"""
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

THREAT_CATEGORIES = [
    "brute_force", "ddos", "data_exfiltration",
    "unauthorized_access", "device_tampering", "network_scan"
]

SEVERITY_SCORES = {"low": 10, "medium": 35, "high": 65, "critical": 90}

THREAT_DESCRIPTIONS = {
    "brute_force": (
        "A brute force attack involves systematically checking all possible passwords or passphrases "
        "until the correct one is found. This is often automated and can target authentication systems."
    ),
    "ddos": (
        "A Distributed Denial of Service (DDoS) attack floods the target with traffic from multiple "
        "sources, overwhelming the system and causing service disruption."
    ),
    "data_exfiltration": (
        "Data exfiltration refers to unauthorized data transfer from an organization. "
        "This can involve sensitive information being copied or moved to an external destination."
    ),
    "unauthorized_access": (
        "Unauthorized access occurs when a person or system gains access to resources without "
        "proper authorization, potentially leading to data theft or system compromise."
    ),
    "device_tampering": (
        "Device tampering involves physically or digitally interfering with IoT devices to "
        "compromise their functionality, integrity, or the data they collect."
    ),
    "network_scan": (
        "Network scanning is a reconnaissance technique used to identify active hosts, open ports, "
        "and services on a network, often the first step in a targeted attack."
    ),
}

REMEDIATION_STEPS = {
    "brute_force": [
        "Immediately lock affected accounts",
        "Enable multi-factor authentication (MFA)",
        "Implement IP-based rate limiting",
        "Review authentication logs for compromised accounts",
        "Alert security team and notify affected users",
    ],
    "ddos": [
        "Activate DDoS mitigation measures (rate limiting, traffic scrubbing)",
        "Block identified attacking IP ranges at perimeter firewall",
        "Scale infrastructure to absorb traffic spike if possible",
        "Notify ISP and upstream providers",
        "Document attack patterns for future prevention",
    ],
    "data_exfiltration": [
        "Immediately isolate affected device from network",
        "Capture network traffic for forensic analysis",
        "Identify and block destination IP addresses",
        "Review data access logs to determine what was exfiltrated",
        "Notify data protection officer and legal team",
    ],
    "unauthorized_access": [
        "Lock down compromised access point immediately",
        "Revoke and reissue access credentials",
        "Review and strengthen access control policies",
        "Conduct full audit of recent access logs",
        "Increase monitoring on affected resources",
    ],
    "device_tampering": [
        "Physically inspect the device for signs of tampering",
        "Verify firmware integrity and update if needed",
        "Replace device if compromise is confirmed",
        "Review supply chain security procedures",
        "Enable tamper detection alerts on all similar devices",
    ],
    "network_scan": [
        "Block scanning source IP at perimeter firewall",
        "Enable IDS/IPS rules for scan detection",
        "Audit exposed services and close unnecessary ports",
        "Review and update network segmentation",
        "Increase logging verbosity on network devices",
    ],
}


def score_threat(
    anomaly_score: float,
    severity: str,
    affected_devices: int = 1,
    is_repeat: bool = False
) -> int:
    """
    Score a threat on a 0-100 scale based on multiple factors.
    """
    base = SEVERITY_SCORES.get(severity, 35)
    score = base + (anomaly_score / 100) * 20
    if affected_devices > 3:
        score = min(100, score + 10)
    if is_repeat:
        score = min(100, score + 15)
    return int(min(100, max(0, score)))


def classify_threat(anomaly: dict[str, Any]) -> str:
    """Classify a threat based on anomaly attributes."""
    return anomaly.get("threat_category", "device_tampering")


def generate_threat_summary(anomaly: dict[str, Any]) -> dict[str, Any]:
    """
    Generate a comprehensive threat summary for an anomaly.
    Returns a dict with category, description, score, and remediation steps.
    """
    category = classify_threat(anomaly)
    severity = anomaly.get("severity", "medium")
    anomaly_score = anomaly.get("anomaly_score", 50.0)
    device_id = anomaly.get("device_id", "unknown")
    device_type = anomaly.get("device_type", "unknown")
    location = anomaly.get("location", "unknown")
    timestamp = anomaly.get("timestamp", datetime.now(timezone.utc).isoformat())

    threat_score = score_threat(anomaly_score, severity)

    description = THREAT_DESCRIPTIONS.get(category, "Unknown threat pattern detected.")
    steps = REMEDIATION_STEPS.get(category, ["Investigate the incident immediately"])

    summary_text = (
        f"[{severity.upper()}] {category.replace('_', ' ').title()} detected on "
        f"{device_type} '{device_id}' at {location}. "
        f"Threat score: {threat_score}/100. "
        f"{description[:100]}..."
    )

    return {
        "threat_id": anomaly.get("_id", "unknown"),
        "category": category,
        "severity": severity,
        "threat_score": threat_score,
        "device_id": device_id,
        "device_type": device_type,
        "location": location,
        "timestamp": timestamp,
        "description": description,
        "summary": summary_text,
        "remediation_steps": steps,
        "anomaly_score": round(anomaly_score, 2),
    }


def generate_landscape_summary(anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Generate an overall threat landscape summary from a list of anomalies.
    """
    if not anomalies:
        return {
            "status": "clean",
            "summary": "No active threats detected. All systems operating normally.",
            "total_threats": 0,
            "critical_count": 0,
            "high_count": 0,
            "top_categories": [],
            "most_affected_locations": [],
            "recommended_priority": "Continue regular monitoring",
        }

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_counts: dict[str, int] = {}
    location_counts: dict[str, int] = {}

    for a in anomalies:
        sev = a.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        cat = a.get("threat_category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        loc = a.get("location", "unknown")
        location_counts[loc] = location_counts.get(loc, 0) + 1

    top_cats = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_locs = sorted(location_counts.items(), key=lambda x: x[1], reverse=True)[:3]

    # Determine overall status
    if severity_counts["critical"] > 0:
        status = "critical"
    elif severity_counts["high"] > 0:
        status = "elevated"
    elif severity_counts["medium"] > 0:
        status = "moderate"
    else:
        status = "low"

    if status == "critical":
        priority = "CRITICAL: Immediate response required"
    elif status == "elevated":
        priority = "HIGH: Escalate to security team"
    elif status == "moderate":
        priority = "MODERATE: Monitor and investigate"
    else:
        priority = "LOW: Standard monitoring"

    summary_text = (
        f"Threat landscape status: {status.upper()}. "
        f"Detected {len(anomalies)} active threats — "
        f"{severity_counts['critical']} critical, {severity_counts['high']} high, "
        f"{severity_counts['medium']} medium, {severity_counts['low']} low severity. "
        f"Primary threat category: {top_cats[0][0].replace('_', ' ').title() if top_cats else 'Unknown'}. "
        f"Most affected location: {top_locs[0][0] if top_locs else 'Unknown'}."
    )

    return {
        "status": status,
        "summary": summary_text,
        "total_threats": len(anomalies),
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"],
        "medium_count": severity_counts["medium"],
        "low_count": severity_counts["low"],
        "top_categories": [{"category": c, "count": n} for c, n in top_cats],
        "most_affected_locations": [{"location": l, "count": n} for l, n in top_locs],
        "recommended_priority": priority,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
