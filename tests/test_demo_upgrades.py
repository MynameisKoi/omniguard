"""Comprehensive tests for OmniGuard Friday Demo & Architecture Upgrades:
- Same-subnet C2 quarantine directives & reverse-shell cleanup
- Live Host DFIR snapshots (collection, risk analysis, agent reporting, API, Ask AI tool)
- Phone push notifications (ntfy, Telegram, Webhook, severity gating, API)
- CISA KEV security patch & news analyzer (live/offline fallback, AI brief, API)
- Pluggable 3rd-party EDR & Threat Intel connectors (status & enrichment, API)
- Fake CAPTCHA (ClickFix) & artifact download demo portal routes
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(REPO_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

os.environ.setdefault("NEO4J_PASSWORD", "test_pass")


class _FakeCol:
    def __init__(self):
        self.docs = {}
        self.rows = []

    def find_one(self, q, projection=None):
        doc = self.docs.get(q.get("_id"))
        if not doc:
            return None
        out = dict(doc)
        if projection and projection.get("_id") == 0:
            out.pop("_id", None)
        return out

    def update_one(self, q, u, upsert=False):
        k = q["_id"]
        doc = self.docs.get(k)
        if doc is None:
            if not upsert:
                return
            doc = {"_id": k}
            self.docs[k] = doc
        doc.update(u.get("$set", {}))

    def insert_one(self, doc):
        self.rows.append(dict(doc))

    def find(self, q=None, projection=None):
        q = q or {}
        matched = []
        for r in self.rows:
            if "host_key" in q and r.get("host_key") != q["host_key"]:
                continue
            matched.append(dict(r))

        class _Cursor(list):
            def sort(self, field, direction):
                self[:] = sorted(self, key=lambda x: str(x.get(field, "")), reverse=(direction < 0))
                return self

            def limit(self, n):
                return self[:n]

        return _Cursor(matched)


# ── 1. C2 Quarantine Directives & DFIR Snapshot Tests ────────────────────────

def test_containment_quarantine_directives_delivered_to_agent():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import containment

        fake_col = _FakeCol()
        with patch.object(containment, "containment_collection", fake_col), \
             patch.object(containment, "append_ledger_entry"), \
             patch.object(containment.manager, "broadcast_from_thread"):
            req = containment.request_isolation(
                "kali-victim",
                by="analyst@omniguard.io",
                c2_ip="192.168.137.1",
                c2_ports=[4444, 9000],
                kill_pids=[4242],
                kill_patterns=["beacon_sim.py"],
            )
            assert req["quarantine"]["c2_ip"] == "192.168.137.1"
            assert req["quarantine"]["c2_ports"] == [4444, 9000]
            assert req["quarantine"]["kill_pids"] == [4242]

            poll_resp = containment.agent_poll("KALI-VICTIM")
            assert poll_resp["action"] == "isolate"
            assert poll_resp["quarantine"]["c2_ip"] == "192.168.137.1"
            assert poll_resp["quarantine"]["kill_pids"] == [4242]


def test_dfir_risk_analysis_and_roundtrip():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import containment
        import dfir

        fake_cont = _FakeCol()
        fake_dfir = _FakeCol()
        ledger = []
        broadcasts = []

        with patch.object(containment, "containment_collection", fake_cont), \
             patch.object(dfir, "containment_collection", fake_cont), \
             patch.object(dfir, "dfir_collection", fake_dfir), \
             patch.object(dfir, "append_ledger_entry", side_effect=lambda **kw: ledger.append(kw)), \
             patch.object(dfir.manager, "broadcast_from_thread", side_effect=lambda m: broadcasts.append(m)):

            req = dfir.request_snapshot("kali-victim", by="analyst@omniguard.io")
            assert req["status"] == "dfir_requested"

            # Agent poll sees dfir_requested=True
            poll_resp = containment.agent_poll("kali-victim")
            assert poll_resp["dfir_requested"] is True

            # Agent submits snapshot with a suspicious beacon process & C2 port 4444
            stored = dfir.store_snapshot("kali-victim", {
                "os": "Linux 6.1",
                "hostname": "kali-victim",
                "is_admin": True,
                "processes": [
                    {"pid": 100, "name": "systemd", "cmdline": "/sbin/init", "user": "root"},
                    {"pid": 4242, "name": "python3", "cmdline": "python3 demo/beacon_sim.py --host kali-victim", "user": "kali"},
                ],
                "connections": [
                    {"proto": "tcp", "local": "192.168.137.10:51234", "remote_ip": "192.168.137.1", "remote_port": 4444, "state": "ESTAB", "process": "python3"},
                ],
                "hosts_entries": ["127.0.0.1 localhost"],
            })

            assert stored["analysis"]["risk_level"] == "critical"
            assert len(stored["analysis"]["suspicious_processes"]) == 1
            assert stored["analysis"]["suspicious_processes"][0]["pid"] == 4242
            assert len(stored["analysis"]["suspicious_connections"]) == 1
            assert ledger[-1]["action_taken"] == "DFIR_SNAPSHOT_COLLECTED"
            assert broadcasts[-1]["type"] == "dfir_updated"

            # dfir_requested cleared after upload
            assert containment.agent_poll("kali-victim").get("dfir_requested") is None
            latest = dfir.get_latest_snapshot("KALI-VICTIM")
            assert latest is not None and latest["analysis"]["risk_level"] == "critical"


# ── 2. Phone Push Notification Tests ─────────────────────────────────────────

def test_phone_notifications_dispatch_and_severity_gate():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import notifications

        notifications.configure_notifications(
            enabled=True,
            min_severity="high",
            ntfy_topic="omniguard-test-topic",
            telegram_bot_token="123:fake-token",
            telegram_chat_id="99999",
            webhook_url="https://example.invalid/hook",
            dashboard_url="http://192.168.137.50:5173",
        )

        # Low severity is gated out unless forced
        assert notifications.dispatch_alert_notification({"severity": "low", "host": "PC-1"}) == []

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None

        with patch.object(notifications.httpx, "post", return_value=mock_resp) as mock_post:
            results = notifications.dispatch_alert_notification(
                {"alert_id": "a-99", "host": "kali-victim", "severity": "critical", "event_type": "c2_beacon_detected", "source": "spectrac2"},
                proposal={"verdict": "true_positive", "severity": "critical", "actions": ["isolate_host"], "summary": "C2 confirmed."},
            )
            assert len(results) == 3
            assert all(r["ok"] for r in results)
            assert {r["channel"] for r in results} == {"ntfy", "telegram", "webhook"}
            assert mock_post.call_count == 3

        status = notifications.get_notification_status()
        assert "ntfy" in status["active_channels"]
        assert "telegram" in status["active_channels"]
        assert "123:fake-token" not in str(status)  # secrets never leaked

        # Reset config so other tests don't make external calls
        notifications.configure_notifications(ntfy_topic="", telegram_bot_token="", telegram_chat_id="", webhook_url="")


# ── 3. CISA KEV Patch & News Analyzer Tests ──────────────────────────────────

def test_cisa_kev_offline_fallback_and_analysis():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import threat_intel

        threat_intel._kev_cache.update({"fetched_at": 0.0, "source": "fallback", "vulnerabilities": []})

        with patch.object(threat_intel.httpx, "get", side_effect=RuntimeError("offline hotspot")), \
             patch.object(threat_intel.httpx, "post", side_effect=RuntimeError("ollama offline")):
            feed = threat_intel.fetch_cisa_kev(limit=10, query="microsoft", force_refresh=True)
            assert feed["source"] == "offline_cached_kev"
            assert feed["count"] >= 2
            assert all("microsoft" in v["vendorProject"].lower() for v in feed["vulnerabilities"])

            brief = threat_intel.analyze_security_patches(query="microsoft", limit=5, host_os_hints=["Windows 11"])
            assert brief["used_llm"] is False
            assert "Top Priority Patches" in brief["analysis"]
            assert "Windows 11" in brief["analysis"]


# ── 4. Pluggable 3rd-Party Connectors & API Tests ────────────────────────────

def test_connectors_status_and_enrichment_api():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import main as backend_main
        import connectors
        from fastapi.testclient import TestClient

        backend_main.app.dependency_overrides[backend_main.current_user] = lambda: {
            "email": "analyst@omniguard.io",
            "name": "SOC Analyst",
        }
        client = TestClient(backend_main.app)

        with patch("connectors.containment.list_states", return_value=[{"host": "kali-victim", "agent_online": True}]):
            res = client.get("/connectors/status")
            assert res.status_code == 200
            data = res.json()
            names = {p["name"] for p in data["containment_providers"]}
            assert {"omniguard_local_agent", "action1", "crowdstrike_falcon", "paloalto_cortex"}.issubset(names)

        # Enrich an IP against mocked local DB
        mock_cursor = MagicMock()
        mock_cursor.limit.return_value = [{"alert_id": "a1", "host": "kali-victim", "severity": "critical"}]
        with patch.dict(connectors.database, {"alerts": MagicMock(find=MagicMock(return_value=mock_cursor))}) if isinstance(connectors.database, dict) else patch.object(connectors, "database") as mock_db:
            if not isinstance(connectors.database, dict):
                mock_db.__getitem__.return_value.find.return_value = mock_cursor
            res2 = client.post("/connectors/enrich", json={"indicator": "198.51.100.44"})
            assert res2.status_code == 200
            body = res2.json()
            assert body["type"] == "ip"
            assert body["local_soc"]["alert_count"] == 1
            assert "kali-victim" in body["local_soc"]["affected_hosts"]


# ── 5. Ask AI Tool Registration & Mock Portal ClickFix Test ──────────────────

def test_new_ask_ai_tools_registered():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import tools

        for tool_name in ("get_host_dfir", "check_security_patches", "enrich_indicator"):
            assert tool_name in tools.TOOLS
            assert tools.TOOLS[tool_name]["kind"] == "read"


def test_mock_portal_captcha_and_download_fixture():
    portal_dir = os.path.join(REPO_ROOT, "adversary-simulation", "portal")
    if portal_dir not in sys.path:
        sys.path.insert(0, portal_dir)
    import mock_portal

    assert "I am not a robot" in mock_portal.CAPTCHA_HTML_TEMPLATE
    assert "__DEMO_CMD__" in mock_portal.CAPTCHA_HTML_TEMPLATE
    assert "/captcha" in mock_portal.HTML_PAYLOAD
    assert "/download/OmniGuardDemoClient.txt" in mock_portal.HTML_PAYLOAD


def test_containment_agent_dfir_snapshot_safe():
    demo_dir = os.path.join(REPO_ROOT, "demo")
    if demo_dir not in sys.path:
        sys.path.insert(0, demo_dir)
    import containment_agent

    snap = containment_agent.collect_dfir_snapshot()
    assert snap["host"] == containment_agent.HOST
    assert isinstance(snap["processes"], list)
    assert isinstance(snap["connections"], list)
    # Never kills own PID or PID 1
    assert containment_agent.kill_suspicious_processes(kill_pids=[1, os.getpid()], kill_patterns=[]) == []


def test_dfir_flags_rmm_watchdog_and_listener_supports_telegram_c2():
    with patch("neo4j.GraphDatabase.driver"), patch("pymongo.MongoClient"):
        import dfir

        res = dfir.analyze_snapshot_risk({
            "processes": [
                {"pid": 777, "name": "powershell.exe", "cmdline": "powershell -WindowStyle Hidden -File ScreenConnectWatchdog.ps1 Unblock-File"},
            ],
            "connections": [
                {"proto": "tcp", "local": "192.168.137.10:50123", "remote_ip": "192.168.137.1", "remote_port": 9000, "state": "ESTAB", "process": "powershell.exe"},
            ],
        })
        assert res["risk_level"] == "critical"
        assert len(res["suspicious_processes"]) == 1
        assert len(res["suspicious_connections"]) == 1

    c2_dir = os.path.join(REPO_ROOT, "adversary-simulation", "c2")
    if c2_dir not in sys.path:
        sys.path.insert(0, c2_dir)
    import listener
    assert listener.MAX_BODY_BYTES == 65536
