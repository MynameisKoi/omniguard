"""OCSF (Open Cybersecurity Schema Framework) mapping module for OmniGuard SOC.

Inspired by enterprise SIEM/data lake interoperability standards (e.g. AiSOC / AWS Security Lake / Splunk):
Normalizes proprietary OmniGuard alerts (VerifyEye phishing, SpectraC2 beaconing) into
OCSF Class 2001: Security Finding (Category 2: Findings).
Enables seamless streaming and export into enterprise security platforms without custom ingestion parsers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


SEVERITY_MAP: Dict[str, int] = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

STATUS_MAP: Dict[str, int] = {
    "new": 1,
    "triaged": 2,
    "resolved": 4,
}

MITRE_TECHNIQUE_NAMES: Dict[str, Dict[str, str]] = {
    "T1566": {"tactic": "Initial Access", "name": "Phishing"},
    "T1566.002": {"tactic": "Initial Access", "name": "Spearphishing Link"},
    "T1071": {"tactic": "Command and Control", "name": "Application Layer Protocol"},
    "T1071.001": {"tactic": "Command and Control", "name": "Web Protocols"},
    "T1041": {"tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel"},
}


def _iso_to_epoch_ms(timestamp_val: Any) -> int:
    """Converts ISO datetime string or datetime object to Unix epoch milliseconds."""
    if isinstance(timestamp_val, datetime):
        return int(timestamp_val.timestamp() * 1000)
    if isinstance(timestamp_val, str):
        try:
            # Parse ISO format
            dt = datetime.fromisoformat(timestamp_val.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            pass
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def alert_to_ocsf(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms an OmniGuard Alert dictionary into an OCSF v1.2.0 Class 2001 (Security Finding).
    """
    epoch_ms = _iso_to_epoch_ms(alert.get("timestamp"))
    severity_str = (alert.get("severity") or "medium").lower()
    severity_id = SEVERITY_MAP.get(severity_str, 3)

    status_str = (alert.get("status") or "new").lower()
    status_id = STATUS_MAP.get(status_str, 1)

    # MITRE mapping
    attacks: List[Dict[str, Any]] = []
    technique_id = alert.get("mitre_technique")
    if technique_id:
        tech_meta = MITRE_TECHNIQUE_NAMES.get(technique_id, {"tactic": "Unknown", "name": technique_id})
        attacks.append({
            "tactic": {"name": tech_meta["tactic"]},
            "technique": {"uid": technique_id, "name": tech_meta["name"]},
            "version": "v14.1",
        })

    # Device entity
    device: Dict[str, Any] = {
        "hostname": alert.get("host") or "UNKNOWN",
        "type_id": 1,  # Server / Workstation
    }
    if alert.get("src_ip"):
        device["ip"] = alert["src_ip"]

    # Target resources
    resources: List[Dict[str, Any]] = []
    if alert.get("domain"):
        resources.append({
            "name": alert["domain"],
            "type": "Domain",
            "url_string": alert.get("target_url"),
        })

    # Source specific enrichment
    source = alert.get("source") or "omniguard"
    finding_types: List[str] = [alert.get("event_type") or "security_finding"]
    if alert.get("brand_target"):
        finding_types.append(f"brand_impersonation:{alert['brand_target']}")

    confidence = alert.get("confidence")
    confidence_score = int(confidence * 100) if confidence is not None else 80

    return {
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2001,
        "class_name": "Security Finding",
        "type_uid": 200101,
        "type_name": "Security Finding: Create",
        "activity_id": 1,
        "activity_name": "Create",
        "severity_id": severity_id,
        "severity": severity_str.capitalize(),
        "status_id": status_id,
        "status": status_str.capitalize(),
        "time": epoch_ms,
        "confidence_score": confidence_score,
        "finding_info": {
            "uid": alert.get("alert_id") or "unknown",
            "title": alert.get("event_type", "Security Finding").replace("_", " ").title(),
            "desc": alert.get("description", ""),
            "created_time": epoch_ms,
            "types": finding_types,
        },
        "attacks": attacks,
        "device": device,
        "resources": resources,
        "metadata": {
            "version": "1.2.0",
            "product": {
                "name": "OmniGuard SOC",
                "vendor_name": "OmniGuard",
                "feature": {"name": source},
            },
        },
        "unmapped": {
            "occurrence_count": alert.get("occurrence_count", 1),
            "beacon_interval": alert.get("beacon_interval"),
            "mean_jitter": alert.get("mean_jitter"),
            "action_endpoint": alert.get("action_endpoint"),
        },
    }


def export_alerts_to_ocsf(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Wraps multiple alerts into an OCSF batch stream envelope."""
    findings = [alert_to_ocsf(a) for a in alerts]
    return {
        "ocsf_version": "1.2.0",
        "count": len(findings),
        "findings": findings,
    }

