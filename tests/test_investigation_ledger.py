"""Unit and integration tests for the Replayable Investigation Decision Ledger."""

import os
import sys
from unittest.mock import patch, MagicMock
import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from ledger import (
    compute_entry_hash,
    append_ledger_entry,
    verify_ledger_integrity,
    get_ledger_for_entity,
    GENESIS_HASH,
    ledger_collection,
)


def test_compute_entry_hash_determinism():
    h1 = compute_entry_hash(GENESIS_HASH, "2026-11-03T12:00:00Z", "LAPTOP-10", "AI_TRIAGE", "High risk", "ISOLATE")
    h2 = compute_entry_hash(GENESIS_HASH, "2026-11-03T12:00:00Z", "LAPTOP-10", "AI_TRIAGE", "High risk", "ISOLATE")
    assert h1 == h2
    assert len(h1) == 64

    # Any modification alters the hash
    h3 = compute_entry_hash(GENESIS_HASH, "2026-11-03T12:00:00Z", "LAPTOP-10", "AI_TRIAGE", "Low risk", "ISOLATE")
    assert h1 != h3


def test_ledger_append_and_chaining():
    records = []

    def mock_find_one(sort=None):
        return records[-1] if records else None

    def mock_insert_one(doc):
        records.append(dict(doc))
        return MagicMock()

    def mock_find(query=None, sort=None):
        return list(records)

    with patch.object(ledger_collection, "find_one", side_effect=mock_find_one), \
         patch.object(ledger_collection, "insert_one", side_effect=mock_insert_one), \
         patch.object(ledger_collection, "find", side_effect=mock_find):

        # Block 1
        e1 = append_ledger_entry(
            entity_type="HOST",
            entity_id="WORKSTATION-01",
            stage="AI_TRIAGE",
            action_taken="ESCALATE",
            reasoning_output="C2 beacon detected",
        )
        assert e1["prev_hash"] == GENESIS_HASH

        # Block 2
        e2 = append_ledger_entry(
            entity_type="HOST",
            entity_id="WORKSTATION-01",
            stage="EDR_CONTAINMENT",
            action_taken="NETWORK_ISOLATION",
            reasoning_output="Quarantine confirmed",
        )
        assert e2["prev_hash"] == e1["entry_hash"]

        # Verify integrity succeeds
        is_valid, failing_id, count = verify_ledger_integrity()
        assert is_valid is True
        assert count == 2
        assert failing_id is None

        # Simulate tampering with block 1 reasoning output
        records[0]["reasoning_output"] = "TAMPERED REASONING"
        is_valid_tampered, failing_id_tampered, count = verify_ledger_integrity()
        assert is_valid_tampered is False
        assert failing_id_tampered == records[0]["ledger_id"]


def test_api_ledger_endpoints():
    os.environ.setdefault("NEO4J_PASSWORD", "test_pass")

    with patch("neo4j.GraphDatabase.driver"), \
         patch("pymongo.MongoClient"):
        import main as backend_main
        from main import app
        from fastapi.testclient import TestClient

        client = TestClient(app)

        mock_entries = [
            {
                "ledger_id": "test-id-1",
                "entity_type": "HOST",
                "entity_id": "LAPTOP-42",
                "stage": "EDR_CONTAINMENT",
                "action_taken": "NETWORK_ISOLATION",
                "reasoning_output": "Host isolated",
                "analyst_user": "analyst@omniguard.io",
                "timestamp": "2026-11-03T12:00:00Z",
                "prev_hash": "0" * 64,
                "entry_hash": "a" * 64,
            }
        ]

        with patch("main.get_recent_ledger", return_value=mock_entries), \
             patch("main.get_ledger_for_entity", return_value=mock_entries), \
             patch("main.verify_ledger_integrity", return_value=(True, None, 1)):

            # Test GET /investigations/ledger
            res1 = client.get("/investigations/ledger")
            assert res1.status_code == 200
            assert res1.json()["count"] == 1

            # Test GET /investigations/ledger/host/LAPTOP-42
            res2 = client.get("/investigations/ledger/host/LAPTOP-42")
            assert res2.status_code == 200
            assert res2.json()["host"] == "LAPTOP-42"

            # Test GET /investigations/ledger/verify
            res3 = client.get("/investigations/ledger/verify")
            assert res3.status_code == 200
            assert res3.json()["valid"] is True
            assert res3.json()["status"] == "verified"
