"""Guardrails around the SOC agent's small local model (backend/agent.py):
tool calls written as text are recovered, tables and role-name junk are
stripped, and the agent can never claim an action happened on its own.
"""

import os
import sys

import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import agent  # noqa: E402


def test_tool_call_written_as_text_is_recovered():
    calls = agent._text_tool_call('{"name": "search_alerts", "parameters": {"severity": "critical"}}')
    assert calls == [{"function": {"name": "search_alerts", "arguments": {"severity": "critical"}}}]


def test_json_that_is_not_a_tool_is_left_alone():
    # llama3.2 answered "what is a C2 beacon" with this; it isn't a tool
    assert agent._text_tool_call('{"name": "C2", "parameters": {"description": "..."}}') is None
    assert agent._text_tool_call("C2 means command and control.") is None


def test_tidy_drops_tables_and_role_names():
    text = "assistant\n\nHere's what I found.\n| Alert | Host |\n| --- | --- |\n| a1 | LAPTOP-10 |\nNext, triage it."
    assert agent._tidy(text) == "Here's what I found.\nNext, triage it."


@pytest.mark.parametrize("answer, claims", [
    ("LAPTOP-10 has been isolated from the network.", True),
    ("The alert has been resolved.", True),
    ("The host is now quarantined.", True),
    ("I've proposed isolating LAPTOP-10 — approve the card to go ahead.", False),
    ("LAPTOP-10 should be isolated.", False),
    # what llama3.2 actually wrote after "contain it" with no approval
    ("The host LAPTOP-10 is fully contained after network isolation was applied.", True),
    ("The compromised user's session credentials have been revoked to limit damage.", True),
    ("I've isolated the host.", True),
    ("I recommend isolating LAPTOP-10.", False),
])
def test_claimed_action_detection(answer, claims):
    assert bool(agent.CLAIMED_ACTION.search(answer)) is claims


def test_contain_intent_needs_a_real_host(monkeypatch):
    monkeypatch.setattr(agent, "mentioned_entities",
                        lambda text: [("LAPTOP-10", "host"), ("cdn-telemetry-sync.net", "domain")])
    assert agent._contain_intent("LAPTOP-10 looks compromised, contain it") == ["LAPTOP-10"]
    assert agent._contain_intent("tell me about LAPTOP-10") == []


def test_contain_it_means_the_host_we_were_talking_about(monkeypatch):
    monkeypatch.setattr(agent, "mentioned_entities", lambda text: [("LAPTOP-10", "host")] if "LAPTOP-10" in text else [])
    convo = {"messages": [
        {"role": "user", "content": "what happened on LAPTOP-10?"},
        {"role": "assistant", "content": "...", "steps": [{"tool": "investigate_host", "args": {"hostname": "LAPTOP-10"}}]},
    ]}
    assert agent._contain_intent("it looks compromised, contain it", convo) == ["LAPTOP-10"]
    assert agent._contain_intent("contain it", {"messages": []}) == []


def test_get_alert_only_offered_with_a_real_id(monkeypatch):
    monkeypatch.setattr(agent, "tool_specs", lambda: [
        {"name": "search_alerts", "description": "d", "inputSchema": {}},
        {"name": "get_alert", "description": "d", "inputSchema": {}}])
    names = lambda tools: [t["function"]["name"] for t in tools]
    assert names(agent._ollama_tools("which hosts had phishing?", None)) == ["search_alerts"]
    assert names(agent._ollama_tools("explain this", "alert 60197cfe-ca50-4bfb-9467-25d72cb9d6a0")) == ["search_alerts", "get_alert"]
