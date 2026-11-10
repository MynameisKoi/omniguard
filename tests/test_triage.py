"""Alert triage (backend/triage.py): by hand, or proposed by the AI and only
applied once an analyst approves. Runs against an in-memory alert store and
ledger, so nothing touches the real (append-only) audit ledger."""
import os
import sys

import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import triage  # noqa: E402


class FakeAlerts:
    """Just enough of a Mongo collection for triage.py."""
    def __init__(self, docs):
        self.docs = {d["alert_id"]: dict(d) for d in docs}

    def _match(self, d, q):
        for k, v in q.items():
            if k == "$or":
                if not any(self._match(d, x) for x in v):
                    return False
            elif d.get(k) != v:
                return False
        return True

    def find_one(self, q, projection=None):
        return next((dict(d) for d in self.docs.values() if self._match(d, q)), None)

    def find(self, q, projection=None):
        return [dict(d) for d in self.docs.values() if self._match(d, q)]

    def distinct(self, field, q):
        return sorted({d.get(field) for d in self.docs.values() if self._match(d, q) and d.get(field)})

    def update_one(self, q, update):
        d = self.docs[q["alert_id"]]
        d.update(update.get("$set", {}))
        for k in update.get("$unset", {}):
            d.pop(k, None)


ALERTS = [
    {"alert_id": "p1", "event_type": "phishing_page_detected", "source": "verifyeye", "severity": "medium",
     "host": "BUILD-SRV-02", "user": "ci-runner", "domain": "github-sso-verify.com", "confidence": 0.83, "status": "new"},
    {"alert_id": "c1", "event_type": "c2_beacon_detected", "source": "spectrac2", "severity": "critical",
     "host": "LAPTOP-10", "user": "maharjan", "domain": "cdn-telemetry-sync.net", "confidence": 0.9, "status": "new"},
    {"alert_id": "p2", "event_type": "phishing_page_detected", "source": "verifyeye", "severity": "high",
     "host": "LAPTOP-10", "user": "maharjan", "domain": "evil-microsoft-login.com", "confidence": 0.9, "status": "new"},
    {"alert_id": "t1", "event_type": "phishing_page_detected", "source": "verifyeye", "severity": "critical",
     "host": "LAPTOP-10", "domain": "localhost", "confidence": 0.9, "status": "new"},
]


@pytest.fixture
def world(monkeypatch):
    alerts, ledger = FakeAlerts(ALERTS), []
    monkeypatch.setattr(triage, "alerts_collection", alerts)
    monkeypatch.setattr(triage, "append_ledger_entry", lambda **kw: ledger.append(kw))
    monkeypatch.setattr(triage, "get_ledger_for_entity", lambda e: [])
    monkeypatch.setattr(triage, "list_evidence", lambda **kw: [])
    monkeypatch.setattr(triage, "_explain", lambda a, v, r: "")      # no model in tests
    return alerts, ledger


def test_manual_triage_is_saved_and_every_step_ledgered(world):
    alerts, ledger = world
    out = triage.apply_triage("p1", "true_positive", "high", "user typed it in", ["reset_password", "block_domain"],
                              "triaged", "analyst@x")
    assert out["status"] == "triaged" and out["severity"] == "high"
    assert out["triage"]["via"] == "manual" and out["triage"]["by"] == "analyst@x"
    assert [e["action_taken"] for e in ledger] == ["TRIAGE_TRUE_POSITIVE", "PASSWORD_RESET_SIMULATED", "DOMAIN_BLOCK_SIMULATED"]
    assert "severity medium -> high" in ledger[0]["reasoning_output"]


def test_actions_that_dont_fit_the_alert_are_refused(world):
    alerts, ledger = world
    with pytest.raises(triage.TriageError):
        triage.apply_triage("t1", "benign", "low", "", ["block_domain"], "resolved", "a")   # localhost can't be blocked
    with pytest.raises(triage.TriageError):
        triage.apply_triage("p1", "maybe", "low", "", [], "triaged", "a")
    assert ledger == []


def test_the_ai_only_proposes_and_nothing_changes_until_approved(world):
    alerts, ledger = world
    out = triage.propose_triage("p1", "analyst@x")
    p = out["triage_proposal"]
    assert p["verdict"] == "true_positive" and p["severity"] == "high"          # medium raised for a confirmed phish
    assert p["actions"] == ["reset_password", "block_domain"]                   # phishing only: no isolation
    assert out["status"] == "new" and out["severity"] == "medium" and ledger == []

    done = triage.approve_proposal("p1", "boss@x", verdict="escalate")         # approved with an edit
    assert done["triage"]["via"] == "ai" and done["triage"]["proposed_verdict"] == "true_positive"
    assert done["triage"]["verdict"] == "escalate" and "triage_proposal" not in done
    assert "AI proposed, approved by boss@x" in ledger[0]["reasoning_output"]
    assert "AI suggested True positive" in ledger[0]["reasoning_output"]
    with pytest.raises(triage.TriageError):
        triage.approve_proposal("p1", "boss@x")                                 # already used


def test_rejecting_a_proposal_changes_nothing_but_is_recorded(world):
    alerts, ledger = world
    triage.propose_triage("c1", "a")
    out = triage.reject_proposal("c1", "a", "I want to look first")
    assert out["status"] == "new" and "triage_proposal" not in out
    assert [e["action_taken"] for e in ledger] == ["AI_TRIAGE_REJECTED"]


def test_ai_verdicts_follow_the_data(world):
    # both engines on the host: compromise, isolate + reset + block
    v, sev, status, actions, reasons = triage._decide(triage._alert("c1"))
    assert (v, sev) == ("true_positive", "critical") and actions == ["isolate_host", "reset_password", "block_domain"]
    assert any("two separate engines agree" in r for r in reasons)
    # a localhost test page: benign, resolved, nothing to do
    v, sev, status, actions, _ = triage._decide(triage._alert("t1"))
    assert (v, status, actions) == ("benign", "resolved", [])


def test_isolation_already_recorded_isnt_proposed_again(world, monkeypatch):
    monkeypatch.setattr(triage, "get_ledger_for_entity",
                        lambda e: [{"action_taken": "NETWORK_ISOLATION_SIMULATED"}] if e == "LAPTOP-10" else [])
    _, _, _, actions, reasons = triage._decide(triage._alert("c1"))
    assert "isolate_host" not in actions and any("already has an isolation" in r for r in reasons)
