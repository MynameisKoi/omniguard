"""Unit and integration tests for OCSF (Open Cybersecurity Schema Framework) compatibility."""

import os
import sys
from unittest.mock import patch, MagicMock
import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from ocsf import alert_to_ocsf, export_alerts_to_ocsf, SEVERITY_MAP, STATUS_MAP


@pytest.fixture
def sample_verifyeye_alert():
    return {
        "alert_id": "test-ve-uuid-1",
        "source": "verifyeye",
        "event_type": "phishing_page_detected",
        "severity": "critical",
        "host": "WORKSTATION-CORP-01",
        "src_ip": "10.0.0.15",
        "domain": "fake-microsoft-sso.com",
        "target_url": "https://fake-microsoft-sso.com/login",
        "action_endpoint": "https://fake-microsoft-sso.com/harvest",
        "brand_target": "Microsoft 365",
        "mitre_technique": "T1566.002",
        "confidence": 0.95,
        "description": "Credential harvesting form frozen by VerifyEye",
        "status": "new",
        "timestamp": "2026-11-03T12:00:00Z",
    }


@pytest.fixture
def sample_spectrac2_alert():
    return {
        "alert_id": "test-c2-uuid-2",
        "source": "spectrac2",
        "event_type": "c2_beacon_detected",
        "severity": "high",
        "host": "LAPTOP-10",
        "src_ip": "10.0.0.42",
        "dst_ip": "198.51.100.22",
        "domain": "stealth-beacon-c2.net",
        "mitre_technique": "T1071",
        "confidence": 0.88,
        "beacon_interval": 10.0,
        "mean_jitter": 0.25,
        "description": "Encrypted C2 beacon detected via FFT period 10.0s",
        "status": "triaged",
        "timestamp": "2026-11-03T12:05:00Z",
    }


def test_ocsf_verifyeye_mapping(sample_verifyeye_alert):
    finding = alert_to_ocsf(sample_verifyeye_alert)

    # Validate OCSF Class 2001 specification
    assert finding["category_uid"] == 2
    assert finding["class_uid"] == 2001
    assert finding["type_uid"] == 200101
    assert finding["severity_id"] == 5  # Critical
    assert finding["status_id"] == 1    # New

    # Validate Finding info
    info = finding["finding_info"]
    assert info["uid"] == "test-ve-uuid-1"
    assert "Phishing Page Detected" in info["title"]
    assert "brand_impersonation:Microsoft 365" in info["types"]

    # Validate MITRE ATT&CK
    assert len(finding["attacks"]) == 1
    attack = finding["attacks"][0]
    assert attack["technique"]["uid"] == "T1566.002"
    assert attack["technique"]["name"] == "Spearphishing Link"
    assert attack["tactic"]["name"] == "Initial Access"

    # Validate Device & Resource
    assert finding["device"]["hostname"] == "WORKSTATION-CORP-01"
    assert finding["device"]["ip"] == "10.0.0.15"
    assert finding["resources"][0]["name"] == "fake-microsoft-sso.com"


def test_ocsf_spectrac2_mapping(sample_spectrac2_alert):
    finding = alert_to_ocsf(sample_spectrac2_alert)

    assert finding["severity_id"] == 4  # High
    assert finding["status_id"] == 2    # In Progress / Triaged
    assert finding["device"]["hostname"] == "LAPTOP-10"

    assert len(finding["attacks"]) == 1
    assert finding["attacks"][0]["technique"]["uid"] == "T1071"

    # Unmapped domain-specific telemetry
    assert finding["unmapped"]["beacon_interval"] == 10.0
    assert finding["unmapped"]["mean_jitter"] == 0.25


def test_export_alerts_to_ocsf(sample_verifyeye_alert, sample_spectrac2_alert):
    envelope = export_alerts_to_ocsf([sample_verifyeye_alert, sample_spectrac2_alert])
    assert envelope["ocsf_version"] == "1.2.0"
    assert envelope["count"] == 2
    assert len(envelope["findings"]) == 2


def test_api_ocsf_endpoints(sample_verifyeye_alert):
    os.environ.setdefault("NEO4J_PASSWORD", "test_pass")

    with patch("neo4j.GraphDatabase.driver"), \
         patch("pymongo.MongoClient"):
        import main as backend_main
        from main import app
        from fastapi.testclient import TestClient

        client = TestClient(app)

        with patch.object(backend_main.alerts_collection, "find_one", return_value=sample_verifyeye_alert), \
             patch.object(backend_main.alerts_collection, "find") as mock_find:

            mock_cursor = MagicMock()
            mock_cursor.sort.return_value = mock_cursor
            mock_cursor.limit.return_value = [sample_verifyeye_alert]
            mock_find.return_value = mock_cursor

            # GET /alerts/{id}/ocsf
            res1 = client.get("/alerts/test-ve-uuid-1/ocsf")
            assert res1.status_code == 200
            data1 = res1.json()
            assert data1["class_uid"] == 2001
            assert data1["finding_info"]["uid"] == "test-ve-uuid-1"

            # GET /alerts/export/ocsf
            res2 = client.get("/alerts/export/ocsf")
            assert res2.status_code == 200
            data2 = res2.json()
            assert data2["count"] == 1
            assert data2["ocsf_version"] == "1.2.0"

