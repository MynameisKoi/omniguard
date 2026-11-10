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
