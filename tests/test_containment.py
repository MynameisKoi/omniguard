import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

os.environ.setdefault("NEO4J_PASSWORD", "test_pass")


class _FakeCollection:
    def __init__(self):
        self.docs = {}

    def find_one(self, query, projection=None):
        doc = self.docs.get(query.get("_id"))
        if not doc:
            return None
        out = dict(doc)
        if projection and projection.get("_id") == 0:
            out.pop("_id", None)
        return out

    def find(self, query=None, projection=None):
        return [{"_id": k} for k in self.docs]

    def update_one(self, query, update, upsert=False):
        k = query["_id"]
        doc = self.docs.get(k)
        if doc is None:
            if not upsert:
                return
            doc = {"_id": k}
            self.docs[k] = doc
        doc.update(update.get("$set", {}))

    def delete_one(self, query):
        self.docs.pop(query["_id"], None)


@pytest.fixture
def containment_env():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import containment
        fake_col = _FakeCollection()
        ledger = []
        broadcasts = []

        with patch.object(containment, "containment_collection", fake_col), \
             patch.object(containment, "append_ledger_entry", side_effect=lambda **kw: ledger.append(kw)), \
             patch.object(containment.manager, "broadcast_from_thread", side_effect=lambda msg: broadcasts.append(msg)):
            yield containment, fake_col, ledger, broadcasts


def test_isolation_lifecycle_and_case_insensitivity(containment_env):
    containment, _, ledger, broadcasts = containment_env

    # Initially released & offline
    st0 = containment.get_state("Lenovo-10")
    assert st0["state"] == "released"
    assert st0["agent_online"] is False

    # Agent polls with lowercase hostname -> marks online, no action
    assert containment.agent_poll("lenovo-10") == {"action": None}
    assert containment.get_state("Lenovo-10")["agent_online"] is True

    # Analyst requests isolation with mixed case
    req = containment.request_isolation("Lenovo-10", by="analyst@omniguard.io")
    assert req["state"] == "isolating"
    assert req["agent_online"] is True
    assert ledger[-1]["action_taken"] == "NETWORK_ISOLATION_REQUESTED"
    assert broadcasts[-1] == {"type": "containment_updated", "host": "Lenovo-10", "state": "isolating"}

    # Agent polls -> gets isolate command
    assert containment.agent_poll("lenovo-10") == {"action": "isolate"}

    # Agent acks isolation applied
    acked = containment.agent_ack("lenovo-10", "isolate", ok=True, message="internet cut")
    assert acked["state"] == "isolated"
    assert ledger[-1]["action_taken"] == "NETWORK_ISOLATION_APPLIED"
    assert broadcasts[-1] == {"type": "containment_updated", "host": "lenovo-10", "state": "isolated"}

    # Subsequent poll returns no pending action
    assert containment.agent_poll("Lenovo-10") == {"action": None}

    # Analyst requests release -> agent receives release -> acks released
    rel_req = containment.request_release("Lenovo-10", by="analyst@omniguard.io")
    assert rel_req["state"] == "releasing"
    assert containment.agent_poll("lenovo-10") == {"action": "release"}
    rel_ack = containment.agent_ack("lenovo-10", "release", ok=True, message="internet restored")
    assert rel_ack["state"] == "released"
    assert ledger[-1]["action_taken"] == "NETWORK_ISOLATION_RELEASED"


def test_stalled_detection_and_reset(containment_env):
    containment, fake_col, ledger, broadcasts = containment_env

    containment.request_isolation("PC-404", by="analyst@omniguard.io")
    # Simulate request aging past STALL_SECONDS with no agent online
    fake_col.docs["pc-404"]["requested_at"] = datetime.now(timezone.utc) - timedelta(
        seconds=containment.STALL_SECONDS + 10
    )
    st = containment.get_state("PC-404")
    assert st["state"] == "isolating"
    assert st["agent_online"] is False
    assert st["stalled"] is True

    # Reset clears pending request back to released
    reset_st = containment.reset("PC-404", by="analyst@omniguard.io")
    assert reset_st["state"] == "released"
    assert reset_st["stalled"] is False
    assert ledger[-1]["action_taken"] == "NETWORK_ISOLATION_RESET"
    assert broadcasts[-1] == {"type": "containment_updated", "host": "PC-404", "state": "released"}


def test_agent_ack_failure_sets_error_state(containment_env):
    containment, _, ledger, _ = containment_env
    containment.request_isolation("HOST-ERR", by="analyst@omniguard.io")

    err_st = containment.agent_ack("HOST-ERR", "isolate", ok=False, message="not running as admin")
    assert err_st["state"] == "error"
    assert err_st["message"] == "not running as admin"
    assert ledger[-1]["action_taken"] == "NETWORK_ISOLATION_FAILED"

    containment.request_release("HOST-ERR", by="analyst@omniguard.io")
    err_rel = containment.agent_ack("HOST-ERR", "release", ok=False, message="route restore failed")
    assert err_rel["state"] == "error"
    assert ledger[-1]["action_taken"] == "NETWORK_ISOLATION_RELEASE_FAILED"


def test_empty_hostname_rejected(containment_env):
    containment, _, _, _ = containment_env
    with pytest.raises(ValueError):
        containment.request_isolation("   ", by="analyst@omniguard.io")
    with pytest.raises(ValueError):
        containment.agent_poll("")


def test_agent_channel_optional_key_enforcement():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import auth
        import main as backend_main
        from fastapi.testclient import TestClient

        client = TestClient(backend_main.app)

        # When CONTAINMENT_AGENT_KEYS is set, missing/invalid key -> 401
        with patch.object(auth, "CONTAINMENT_AGENT_KEYS", {"secret-lan-key"}), \
             patch("main.containment.agent_poll", return_value={"action": None}), \
             patch("main.containment.agent_ack", return_value={"host": "PC-1", "state": "isolated"}):
            assert client.get("/agent/containment/poll?host=PC-1").status_code == 401
            assert client.get("/agent/containment/poll?host=PC-1", headers={"X-Agent-Key": "wrong"}).status_code == 401
            assert client.get("/agent/containment/poll?host=PC-1", headers={"X-Agent-Key": "secret-lan-key"}).status_code == 200

            assert client.post("/agent/containment/ack", json={"host": "PC-1", "action": "isolate", "ok": True}).status_code == 401
            assert client.post(
                "/agent/containment/ack",
                json={"host": "PC-1", "action": "isolate", "ok": True},
                headers={"X-Agent-Key": "secret-lan-key"},
            ).status_code == 200


def test_triage_isolated_respects_released_host():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import triage

        # Host was isolated, then released -> _isolated must be False
        with patch.object(triage, "get_ledger_for_entity", return_value=[
            {"action_taken": "NETWORK_ISOLATION_RELEASED"},
            {"action_taken": "NETWORK_ISOLATION_APPLIED"},
        ]):
            assert triage._isolated("PC-1") is False

        # Host's latest entry is isolation -> _isolated must be True
        with patch.object(triage, "get_ledger_for_entity", return_value=[
            {"action_taken": "NETWORK_ISOLATION_APPLIED"},
        ]):
            assert triage._isolated("PC-1") is True

