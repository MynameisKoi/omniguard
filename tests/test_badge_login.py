"""Unit and integration tests for Flipper Zero / NFC Badge Login and Decision Ledger audit."""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import auth
from auth import normalize_badge_uid, check_badge_login, DEFAULT_BADGE_UID


def test_normalize_badge_uid():
    assert normalize_badge_uid("  flipper-soc-7a39b1  ") == "FLIPPER-SOC-7A39B1"
    assert normalize_badge_uid("7a:39:b1:04") == "7A:39:B1:04"
    assert normalize_badge_uid("") == ""
    assert normalize_badge_uid(None) == ""


def test_check_badge_login_success():
    with patch.object(auth.users_collection, "find_one") as mock_find:
        mock_find.return_value = {
            "email": "analyst@omniguard.io",
            "name": "SOC Lead",
            "badge_uid": "FLIPPER-SOC-7A39B1",
        }
        user = check_badge_login("FLIPPER-SOC-7A39B1")
        assert user is not None
        assert user["email"] == "analyst@omniguard.io"
        assert user["badge_uid"] == "FLIPPER-SOC-7A39B1"


def test_check_badge_login_not_found():
    with patch.object(auth.users_collection, "find_one", return_value=None):
        user = check_badge_login("UNKNOWN-CARD-999")
        assert user is None


def test_api_badge_login_endpoint():
    os.environ.setdefault("NEO4J_PASSWORD", "test_pass")

    with patch("neo4j.GraphDatabase.driver"), \
         patch("pymongo.MongoClient"):
        import main as backend_main
        from main import app
        from fastapi.testclient import TestClient

        client = TestClient(app)

        # 1. Successful badge tap login
        with patch("main.check_badge_login", return_value={"email": "analyst@omniguard.io", "name": "SOC Lead"}), \
             patch("main.create_session", return_value=("mock-token-xyz", "2026-11-10T12:00:00Z")), \
             patch("main.append_ledger_entry") as mock_ledger:

            res = client.post("/auth/badge-login", json={"badge_uid": "FLIPPER-SOC-7A39B1"})
            assert res.status_code == 200
            data = res.json()
            assert data["email"] == "analyst@omniguard.io"
            assert data["token"] == "mock-token-xyz"
            assert "expires_at" in data

            # Verify cryptographic audit record logged to ledger
            mock_ledger.assert_called_once()
            call_kwargs = mock_ledger.call_args[1]
            assert call_kwargs["stage"] == "PHYSICAL_AUTHENTICATION"
            assert call_kwargs["action_taken"] == "BADGE_TAP_LOGIN"

        # 2. Failed badge tap login (unrecognized badge)
        with patch("main.check_badge_login", return_value=None):
            res_fail = client.post("/auth/badge-login", json={"badge_uid": "UNKNOWN-CARD"})
            assert res_fail.status_code == 401
            assert "Unrecognized RFID/NFC badge UID" in res_fail.json()["detail"]


def test_check_badge_login_strips_spaces_for_hid_hex():
    with patch.object(auth.users_collection, "find_one") as mock_find:
        mock_find.return_value = {
            "email": "analyst@omniguard.io",
            "name": "SOC Analyst",
            "badge_uid": "2EB776",
        }
        user = check_badge_login("2E B7 76")
        assert user is not None
        query = mock_find.call_args[0][0]["$or"]
        assert {"badge_uid": "2EB776"} in query


def test_api_live_badge_tap_queue():
    os.environ.setdefault("NEO4J_PASSWORD", "test_pass")
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import main as backend_main
        from fastapi.testclient import TestClient

        backend_main._pending_badge_tap = None
        client = TestClient(backend_main.app)

        # No pending tap initially
        assert client.get("/auth/badge-tap/pending").json() == {"pending": False}

        # Physical tap queued from USB bridge
        with patch("main.check_badge_login", return_value={"email": "analyst@omniguard.io", "name": "SOC Analyst", "badge_uid": "2EB776"}):
            tap_res = client.post("/auth/badge-tap", json={"badge_uid": "2EB776"})
            assert tap_res.status_code == 200
            assert tap_res.json()["status"] == "queued"

        # Pending poll consumes the tap once and issues a session
        with patch("main.create_session", return_value=("tap-token-123", "2026-11-14T18:30:00Z")), \
             patch("main.append_ledger_entry") as mock_ledger:
            pending_res = client.get("/auth/badge-tap/pending")
            assert pending_res.status_code == 200
            body = pending_res.json()
            assert body["pending"] is True
            assert body["token"] == "tap-token-123"
            mock_ledger.assert_called_once()

        # Second poll sees nothing pending
        assert client.get("/auth/badge-tap/pending").json() == {"pending": False}


def test_flipper_bridge_fc_card_to_hex():
    demo_dir = os.path.join(repo_root, "demo")
    if demo_dir not in sys.path:
        sys.path.insert(0, demo_dir)
    import flipper_badge_bridge

    assert flipper_badge_bridge.hid_fc_card_to_hex(46, 46966) == "2EB776"

