"""The SOC tool registry's safety rules (backend/tools.py): action tools never
run without approval, the model's sloppy arguments are cleaned up, and its
mistakes come back as readable errors instead of crashing the chat.

Real tools are swapped for stubs, so no database is needed.
"""

import os
import sys

import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import tools  # noqa: E402

REAL_CORRECT_NAMES = tools._correct_names   # before the fixture stubs it

CALLS = []


def read_stub(name, severity=None):
    CALLS.append(("read", name, severity))
    return {"summary": f"found {name}", "data": {"name": name}}


def action_stub(hostname, analyst="unknown"):
    CALLS.append(("action", hostname, analyst))
    return {"summary": f"isolated {hostname}", "data": {"host": hostname}}


def broken_stub():
    raise tools.ToolError("no such thing — answer from your own knowledge")


class ServiceUnavailable(Exception):
    pass


def offline_stub():
    raise ServiceUnavailable("neo4j down")


@pytest.fixture(autouse=True)
def stub_registry(monkeypatch):
    CALLS.clear()
    S = {"type": "string"}
    monkeypatch.setattr(tools, "TOOLS", {
        "lookup": dict(fn=read_stub, kind="read", render="entity", description="d",
                       parameters={"name": S, "severity": S}, required=["name"]),
        "isolate": dict(fn=action_stub, kind="action", render="action", description="d",
                        parameters={"hostname": S}, required=["hostname"]),
        "broken": dict(fn=broken_stub, kind="read", render="text", description="d", parameters={}, required=[]),
        "offline": dict(fn=offline_stub, kind="read", render="graph", description="d", parameters={}, required=[]),
    })
    monkeypatch.setattr(tools, "_correct_names", lambda name, args: (args, []))   # no database


def test_read_tool_runs_and_reports_how_to_draw_it():
    r = tools.run_tool("lookup", {"name": "LAPTOP-10"})
    assert r == {"ok": True, "render": "entity", "args": {"name": "LAPTOP-10"},
                 "summary": "found LAPTOP-10", "data": {"name": "LAPTOP-10"}}


def test_action_never_runs_without_approval():
    r = tools.run_tool("isolate", {"hostname": "LAPTOP-10"}, analyst="a@x.io")
    assert r["ok"] is False and r["needs_approval"] is True
    assert r["data"] == {"tool": "isolate", "args": {"hostname": "LAPTOP-10"}}
    assert CALLS == []   # nothing happened


def test_approved_action_runs_as_the_analyst():
    r = tools.run_tool("isolate", {"hostname": "LAPTOP-10"}, analyst="a@x.io", approved=True)
    assert r["ok"] is True
    assert CALLS == [("action", "LAPTOP-10", "a@x.io")]


def test_model_cannot_pick_who_the_analyst_is():
    # a model passing analyst= in its arguments is ignored; the session decides
    tools.run_tool("isolate", {"hostname": "H", "analyst": "ceo@x.io"}, analyst="a@x.io", approved=True)
    assert CALLS == [("action", "H", "a@x.io")]


def test_empty_and_unknown_arguments_are_dropped():
    tools.run_tool("lookup", {"name": "H", "severity": "", "made_up": 1})
    assert CALLS == [("read", "H", None)]


def test_missing_required_argument_is_named():
    r = tools.run_tool("lookup", {"severity": "high"})
    assert r["ok"] is False and r["summary"] == "lookup needs name."
    assert CALLS == []


def test_unknown_tool():
    assert tools.run_tool("make_coffee", {})["summary"] == "There is no tool called make_coffee."


def test_tool_error_reaches_the_model():
    r = tools.run_tool("broken", {})
    assert r["ok"] is False and "answer from your own knowledge" in r["summary"]


def test_infrastructure_failure_does_not_crash():
    r = tools.run_tool("offline", {})
    assert r["ok"] is False and r["summary"] == "offline failed: the graph database is offline."


def test_specs_split_read_and_action():
    specs = {s["name"]: s for s in tools.tool_specs()}
    assert specs["isolate"]["kind"] == "action"
    assert specs["lookup"]["inputSchema"]["required"] == ["name"]
    assert [s["name"] for s in tools.tool_specs(kinds=("read",))] == ["lookup", "broken", "offline"]



REAL_TOOLS = dict(tools.TOOLS)   # captured at import, before the stubs go in


def test_view_tools_are_read_only_and_drawn_as_views():
    for name, render in [("show_dashboard", "dashboard"), ("show_graph", "graph_explorer"),
                         ("show_screenshots", "screenshots"), ("show_ledger", "ledger_view"),
                         ("compare_entities", "compare")]:
        assert REAL_TOOLS[name]["kind"] == "read"
        assert REAL_TOOLS[name]["render"] == render


def test_compare_needs_two_names():
    with pytest.raises(tools.ToolError, match="at least two"):
        tools.compare_entities("LAPTOP-10")


def test_screenshots_read_a_verdict_word_as_the_verdict(monkeypatch):
    seen = {}
    def fake_list(verdict=None, limit=50, **_):
        seen["verdict"] = verdict
        return [{"evidence_id": "e1", "url": "https://x.test", "domain": "x.test", "phishing": True, "confidence": 0.9}]
    monkeypatch.setattr(tools, "list_evidence", fake_list)
    r = tools.show_screenshots(query="phishing")
    assert seen["verdict"] == "phishing" and "1 phishing" in r["reply"].replace("*", "")


def test_misspelt_names_are_corrected(monkeypatch):
    monkeypatch.setattr(tools, "_entity_values", lambda: {"maharjan", "LAPTOP-10", "cdn-telemetry-sync.net"})
    assert tools.closest_entity("mahirjan") == "maharjan"
    assert tools.closest_entity("laptop-10") == "LAPTOP-10"
    assert tools.closest_entity("cdn-telemetry-sync.com") is None   # a different (lookalike) domain
    assert tools.closest_entity("phishing") is None
    args, fixed = REAL_CORRECT_NAMES("entity_summary", {"name": "mahirjan"})
    assert args == {"name": "maharjan"} and fixed == [("mahirjan", "maharjan", [])]
