"""Unit and integration tests for Multi-Agent Threat Triage Pipeline."""

import os
import sys
from unittest.mock import patch, MagicMock
import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from agents import (
    CorrelatorAgent,
    TriageAgent,
    ContainmentAgent,
    MultiAgentInvestigationPipeline,
)


@pytest.fixture
def sample_telemetry():
    return [
        {
            "alert_id": "a-1",
            "source": "verifyeye",
            "event_type": "phishing_page_detected",
            "severity": "high",
            "host": "WORKSTATION-CORP-01",
            "user": "maharjan",
            "domain": "fake-portal.com",
            "mitre_technique": "T1566",
        },
        {
            "alert_id": "a-2",
            "source": "spectrac2",
            "event_type": "c2_beacon_detected",
            "severity": "critical",
            "host": "WORKSTATION-CORP-01",
            "dst_ip": "198.51.100.42",
            "mitre_technique": "T1071",
        },
        {
            "alert_id": "a-3",
            "source": "verifyeye",
            "host": "OTHER-LAPTOP-99",
            "domain": "other.com",
        },
    ]


def test_correlator_agent(sample_telemetry):
    correlator = CorrelatorAgent()
    res = correlator.run("WORKSTATION-CORP-01", sample_telemetry)

    assert res["target_host"] == "WORKSTATION-CORP-01"
    assert res["alert_count"] == 2
    assert "verifyeye" in res["sources"]
    assert "spectrac2" in res["sources"]
    assert res["is_multi_vector"] is True
    assert "maharjan" in res["users"]
    assert "fake-portal.com" in res["domains"]
    assert "198.51.100.42" in res["c2_ips"]
    assert res["blast_radius"] == "MULTI_HOST_CAMPAIGN"


def test_triage_agent_high_risk():
    triage = TriageAgent()
    correlation = {
        "alert_count": 3,
        "is_multi_vector": True,
        "sources": ["verifyeye", "spectrac2"],
        "mitre_techniques": ["T1566", "T1071"],
    }
    res = triage.run(correlation)

    assert res["risk_score"] >= 80
    assert res["classification"] == "TRUE_POSITIVE_ACTIVE_COMPROMISE"
    assert res["confidence"] >= 0.9
    assert "Initial Access (TA0001)" in res["mitre_summary"]["tactics"]
    assert "Command and Control (TA0011)" in res["mitre_summary"]["tactics"]


def test_containment_agent():
    containment = ContainmentAgent()
    correlation = {
        "target_host": "WORKSTATION-CORP-01",
        "domains": ["malicious-c2.net"],
        "users": ["compromised_user"],
    }
    triage = {"risk_score": 90}
    res = containment.run(correlation, triage)

    assert res["containment_priority"] == "CRITICAL"
    assert res["requires_human_approval"] is True

    actions = [a["action"] for a in res["recommended_actions"]]
    assert "NETWORK_ISOLATION" in actions
    assert "BLOCK_DOMAIN_EGRESS" in actions
    assert "REVOKE_SESSION_CREDENTIALS" in actions


def test_pipeline_orchestration(sample_telemetry):
    pipeline = MultiAgentInvestigationPipeline()
    verdict = pipeline.investigate("WORKSTATION-CORP-01", sample_telemetry)

    assert verdict["host"] == "WORKSTATION-CORP-01"
    assert "correlation" in verdict
    assert "triage" in verdict
    assert "containment" in verdict
    assert verdict["triage"]["risk_score"] >= 80


def test_api_pipeline_endpoint():
    os.environ.setdefault("NEO4J_PASSWORD", "test_pass")

    with patch("neo4j.GraphDatabase.driver"), \
         patch("pymongo.MongoClient"):
        import main as backend_main
        from main import app
        from fastapi.testclient import TestClient

        app.dependency_overrides[backend_main.current_user] = lambda: {
            "email": "analyst@omniguard.io",
            "name": "SOC Analyst",
            "role": "analyst",
        }

        client = TestClient(app)
        # endpoints need a signed-in analyst (session tokens): sign the test client in
        app.dependency_overrides[backend_main.current_user] = lambda: {"email": "test@omniguard.io", "name": "Test"}

        with patch.object(backend_main.alerts_collection, "find") as mock_find:
            mock_find.return_value = [
                {
                    "host": "TARGET-PC",
                    "source": "spectrac2",
                    "mitre_technique": "T1071",
                }
            ]

            res = client.post("/ai/investigate/pipeline", json={"hostname": "TARGET-PC"})
            assert res.status_code == 200
            data = res.json()
            assert data["host"] == "TARGET-PC"
            assert "triage" in data
            assert "containment" in data

