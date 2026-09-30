"""Unit and integration tests for OmniGuard Backend API endpoints."""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Ensure NEO4J_PASSWORD is set before importing backend modules
os.environ.setdefault("NEO4J_PASSWORD", "test_password_secret")

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Mock graph and database before importing app to isolate unit test
with patch("neo4j.GraphDatabase.driver") as mock_driver, \
     patch("pymongo.MongoClient") as mock_mongo:
    from models import AlertCreate, AlertStatusUpdate, Alert
    import main as backend_main
    from main import app

from fastapi.testclient import TestClient

client = TestClient(app)


def test_backend_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_isolate_host():
    response = client.post("/hosts/WORKSTATION-CORP-99/isolate")
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "isolated"
    assert data["host"] == "WORKSTATION-CORP-99"
    assert data["action"] == "network_isolation"
    assert "isolated from the corporate network" in data["message"]


def test_create_and_patch_alert():
    # Mock alerts_collection and graph update
    fake_alert_id = "test-alert-uuid-1234"
    mock_doc = {
        "alert_id": fake_alert_id,
        "source": "verifyeye",
        "event_type": "phishing_page_detected",
        "severity": "critical",
        "host": "WORKSTATION-CORP-99",
        "status": "new",
        "description": "Suspicious login form detected",
        "timestamp": "2026-09-30T12:00:00Z",
    }

    with patch.object(backend_main.alerts_collection, "insert_one") as mock_insert, \
         patch("main.ingest_alert") as mock_ingest, \
         patch.object(backend_main.alerts_collection, "find_one_and_update") as mock_update, \
         patch("main.update_alert_status") as mock_update_status:

        mock_update.return_value = {**mock_doc, "status": "triaged"}

        # Test POST /alerts
        payload = {
            "source": "verifyeye",
            "event_type": "phishing_page_detected",
            "severity": "critical",
            "host": "WORKSTATION-CORP-99",
            "description": "Suspicious login form detected",
        }
        res_post = client.post("/alerts", json=payload)
        assert res_post.status_code == 201
        created = res_post.json()
        assert created["source"] == "verifyeye"
        assert created["host"] == "WORKSTATION-CORP-99"
        assert "alert_id" in created
        assert "timestamp" in created

        # Test PATCH /alerts/{id}
        res_patch = client.patch(
            f"/alerts/{fake_alert_id}",
            json={"status": "triaged"},
        )
        assert res_patch.status_code == 200
        patched = res_patch.json()
        assert patched["alert_id"] == fake_alert_id
        assert patched["status"] == "triaged"
        mock_update_status.assert_called_with(fake_alert_id, "triaged")


def test_patch_alert_not_found():
    with patch.object(backend_main.alerts_collection, "find_one_and_update") as mock_update:
        mock_update.return_value = None
        res_patch = client.patch(
            "/alerts/non-existent-alert-id",
            json={"status": "triaged"},
        )
        assert res_patch.status_code == 404
        assert "not found" in res_patch.json()["detail"]


def test_websocket_alerts_feed():
    with client.websocket_connect("/ws/alerts") as websocket:
        # Verify connection succeeds and manager registered connection
        assert len(backend_main.ws_manager.active_connections) >= 1
