"""Unit and integration tests for Simhash alert deduplication and fusion."""

import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from dedup import (
    simhash,
    hamming_distance,
    compute_alert_simhash,
    find_matching_alert,
    tokenize,
)
from models import AlertCreate, Alert


def test_tokenize():
    tokens = tokenize("Phishing page detected on test-domain.com!")
    assert "phishing" in tokens
    assert "detected" in tokens
    assert "com" in tokens


def test_simhash_properties():
    # Identical features yield identical hash
    h1 = simhash(["c2", "beacon", "host1"])
    h2 = simhash(["c2", "beacon", "host1"])
    assert h1 == h2

    # Different features yield different hashes
    h3 = simhash(["phishing", "google", "login"])
    assert h1 != h3

    # Small permutation yields small Hamming distance
    h4 = simhash(["c2", "beacon", "host1", "jitter"])
    dist = hamming_distance(h1, h4)
    assert dist <= 16
    assert hamming_distance(h1, h3) > dist


def test_hamming_distance():
    assert hamming_distance(0b1011, 0b1011) == 0
    assert hamming_distance(0b1011, 0b1001) == 1
    assert hamming_distance(0b0000, 0b1111) == 4


def test_compute_alert_simhash():
    alert_dict = {
        "source": "spectrac2",
        "event_type": "c2_beacon_detected",
        "severity": "critical",
        "host": "WORKSTATION-CORP-01",
        "domain": "stealth-c2.internal",
        "mitre_technique": "T1071",
        "description": "Encrypted C2 beacon detected via FFT period 10.0s",
    }
    val, hex_str = compute_alert_simhash(alert_dict)
    assert isinstance(val, int)
    assert len(hex_str) == 16


def test_find_matching_alert_fusion():
    base_alert = {
        "source": "spectrac2",
        "event_type": "c2_beacon_detected",
        "host": "WORKSTATION-CORP-01",
        "domain": "stealth-c2.internal",
        "mitre_technique": "T1071",
    }
    val1, hex1 = compute_alert_simhash(base_alert)

    # Identical alert
    candidate = {
        "alert_id": "existing-alert-uuid",
        "simhash": hex1,
        "occurrence_count": 1,
    }
    match = find_matching_alert(val1, [candidate], max_hamming_distance=3)
    assert match is not None
    assert match["alert_id"] == "existing-alert-uuid"

    # Completely different alert
    different_alert = {
        "source": "verifyeye",
        "event_type": "phishing_page_detected",
        "host": "LAPTOP-OTHER-99",
        "domain": "fake-login.com",
    }
    val2, hex2 = compute_alert_simhash(different_alert)
    no_match = find_matching_alert(val2, [candidate], max_hamming_distance=3)
    assert no_match is None


def test_api_alert_fusion_flow():
    # Ensure NEO4J_PASSWORD is set
    os.environ.setdefault("NEO4J_PASSWORD", "test_pass")

    with patch("neo4j.GraphDatabase.driver"), \
         patch("pymongo.MongoClient"):
        import main as backend_main
        from main import app
        from fastapi.testclient import TestClient

        client = TestClient(app)
        # endpoints need a signed-in analyst (session tokens): sign the test client in
        app.dependency_overrides[backend_main.current_user] = lambda: {"email": "test@omniguard.io", "name": "Test"}

        alert_payload = {
            "source": "spectrac2",
            "event_type": "c2_beacon_detected",
            "severity": "high",
            "host": "WORKSTATION-CORP-42",
            "domain": "c2-burst.net",
            "description": "Beacon pulse 1",
        }

        # Simulate first alert insertion
        with patch.object(backend_main.alerts_collection, "find") as mock_find, \
             patch.object(backend_main.alerts_collection, "insert_one") as mock_insert, \
             patch("main.ingest_alert"):
            
            mock_cursor = MagicMock()
            mock_cursor.limit.return_value = []
            mock_find.return_value = mock_cursor

            res = client.post("/alerts", json=alert_payload)
            assert res.status_code == 201
            data = res.json()
            assert data["occurrence_count"] == 1
            assert "simhash" in data

        # Simulate second near-duplicate alert -> should fuse
        sim_val, sim_hex = compute_alert_simhash(alert_payload)
        existing_doc = {
            "alert_id": "fused-incident-1234",
            "source": "spectrac2",
            "event_type": "c2_beacon_detected",
            "severity": "high",
            "host": "WORKSTATION-CORP-42",
            "domain": "c2-burst.net",
            "description": "Beacon pulse 1",
            "status": "new",
            "simhash": sim_hex,
            "occurrence_count": 1,
            "timestamp": "2026-11-03T12:00:00Z",
            "last_seen": "2026-11-03T12:00:00Z",
        }

        with patch.object(backend_main.alerts_collection, "find") as mock_find, \
             patch.object(backend_main.alerts_collection, "find_one_and_update") as mock_update:
            
            mock_cursor = MagicMock()
            mock_cursor.limit.return_value = [existing_doc]
            mock_find.return_value = mock_cursor
            mock_update.return_value = {**existing_doc, "occurrence_count": 2}

            # Send second alert
            res2 = client.post("/alerts", json=alert_payload)
            assert res2.status_code in (200, 201)
            data2 = res2.json()
            assert data2["alert_id"] == "fused-incident-1234"
            assert data2["occurrence_count"] == 2
