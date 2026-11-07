"""Guardrails around the SOC agent's small local model (backend/agent.py):
tool calls written as text are recovered, tables and role-name junk are
stripped, and the agent can never claim an action happened on its own.
"""

import os
import re
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


@pytest.mark.parametrize("text, view", [
    ("show me everything about phishing this week", "show_dashboard"),
    ("show me the network graph around LAPTOP-10", "show_graph"),
    ("what did the phishing pages look like?", "show_screenshots"),
    ("show me the audit trail for LAPTOP-10", "show_ledger"),
    ("compare BUILD-SRV-02 and DEV-BOX-11", "compare_entities"),
    ("isolate LAPTOP-10 from the network", None),
    ("which hosts had phishing?", None),
])
def test_view_requests_pick_the_right_view(text, view):
    views = agent._views(text)
    assert (views[0] if views else None) == view


def test_view_tools_only_offered_when_asked_to_see_something(monkeypatch):
    monkeypatch.setattr(agent, "tool_specs", lambda: [
        {"name": "search_alerts", "description": "d", "inputSchema": {}, "render": "alerts"},
        {"name": "show_graph", "description": "d", "inputSchema": {}, "render": "graph_explorer"},
        {"name": "show_dashboard", "description": "d", "inputSchema": {}, "render": "dashboard"}])
    names = lambda tools: [t["function"]["name"] for t in tools]
    assert names(agent._ollama_tools("which hosts had phishing?", None)) == ["search_alerts"]
    assert names(agent._ollama_tools("show me the graph around LAPTOP-10", None)) == ["search_alerts", "show_graph", "show_dashboard"]


def test_follow_up_on_results_answers_without_tools(monkeypatch):
    monkeypatch.setattr(agent, "mentioned_entities", lambda text: [("LAPTOP-10", "host")] if "LAPTOP-10" in text else [])
    history = [{"role": "user", "content": "show me phishing this week"},
               {"role": "tool", "content": "Dashboard ... Hosts: LAPTOP-10 (2) ...", "tool_name": "show_dashboard"}]
    assert agent._from_history("which of those hosts got hit the most?", history)
    assert not agent._from_history("which of those hosts got hit the most?", [])           # nothing to answer from
    assert not agent._from_history("show me the graph for those", history)                   # a new view
    assert not agent._from_history("tell me about LAPTOP-10 and those users", history)       # a new name
    assert not agent._from_history("isolate those hosts", history)                           # an action


def test_sentences_naming_things_the_results_never_mention_are_dropped(monkeypatch):
    known = {"LAPTOP-10": "host", "maharjan": "user", "FINANCE-PC-07": "host"}
    monkeypatch.setattr(agent, "mentioned_entities",
                        lambda text, limit=5: [(k, v) for k, v in known.items() if k.lower() in text.lower()])
    reference = "Everything linked to LAPTOP-10 is lit up. Users: maharjan."
    answer = "LAPTOP-10 looks compromised. FINANCE-PC-07 was also hit. Isolate it next."
    assert agent._grounded(answer, reference) == "LAPTOP-10 looks compromised. Isolate it next."


def test_interpretation_is_kept_short():
    assert agent._first_sentences("One. Two. Three. Four.", 3) == "One. Two. Three."


def test_restated_facts_are_dropped_and_the_rest_kept():
    facts = "**LAPTOP-10** is a host in **10 alerts** (9 critical, 1 high). It has both phishing and C2 alerts."
    answer = ("LAPTOP-10 is a host in 10 alerts (9 critical, 1 high). "
              "Treat it as compromised and isolate it before checking maharjan's other logins.")
    assert agent._new_only(answer, facts) == "Treat it as compromised and isolate it before checking maharjan's other logins."


def test_internal_action_names_become_words():
    assert agent._plain("Next, propose **NETWORK_ISOLATION** now.") == "Next, propose network isolation now."
    assert agent._plain("LAPTOP-10 and T1566 stay as they are.") == "LAPTOP-10 and T1566 stay as they are."


def test_sentences_from_earlier_replies_are_not_repeated():
    convo = {"messages": [{"role": "assistant", "content": "Facts. This means it's compromised. Isolate it."}]}
    assert agent._not_repeated("This means it's compromised. Check the ledger next.", convo) == "Check the ledger next."


KNOWN = {"LAPTOP-10": "host", "maharjan": "user", "BUILD-SRV-02": "host", "DEV-BOX-11": "host",
         "cdn-telemetry-sync.net": "domain", "spectrac2": "detection engine"}


@pytest.fixture
def known_names(monkeypatch):
    monkeypatch.setattr(agent, "mentioned_entities", lambda text, limit=5: [
        (k, v) for k, v in KNOWN.items() if re.search(rf"(?<![\w.-]){re.escape(k.lower())}(?![\w-])", (text or "").lower())])


@pytest.mark.parametrize("text, plan", [
    ("what about the user maharjan", [("entity_summary", {"name": "maharjan"})]),
    ("maharjan", [("entity_summary", {"name": "maharjan"})]),
    ("show me everything about phishing this week", [("show_dashboard", {"since_hours": 168, "engine": "verifyeye"})]),
    ("show me critical alerts on LAPTOP-10", [("show_dashboard", {"severity": "critical", "host": "LAPTOP-10"})]),
    ("compare BUILD-SRV-02 and DEV-BOX-11", [("compare_entities", {"names": "BUILD-SRV-02, DEV-BOX-11"})]),
    ("show me the graph for cdn-telemetry-sync.net", [("show_graph", {"entity": "cdn-telemetry-sync.net"})]),
    ("what needs attention?", [("attention_findings", {})]),
    ("investigate LAPTOP-10", [("investigate_host", {"hostname": "LAPTOP-10"})]),
    ("isolate LAPTOP-10", None),              # actions: model + approval card
    ("what is a C2 beacon?", None),           # general knowledge
    ("what is spectrac2?", None),             # an engine, not something to look up
    ("show me powershell alerts", None),      # filters the router can't read
])
def test_plain_requests_are_routed_with_exact_names(known_names, text, plan):
    assert agent._route(text) == plan


def test_it_means_what_the_conversation_is_about(known_names):
    convo = {"messages": [
        {"role": "user", "content": "tell me about maharjan"},
        {"role": "assistant", "content": "...", "steps": [{"tool": "entity_summary", "args": {"name": "maharjan"}}]},
    ]}
    assert agent._focus(convo) == ("maharjan", "user")
    assert agent._route("how bad is it?", convo) == [("entity_summary", {"name": "maharjan"})]
    assert agent._route("show me its graph", convo) == [("show_graph", {"entity": "maharjan"})]
    assert agent._route("what does it mean?", convo) is None    # about the last answer, not a lookup


def test_contain_it_skips_to_the_last_host(known_names):
    convo = {"messages": [
        {"role": "user", "content": "what happened on LAPTOP-10?"},
        {"role": "user", "content": "and the user maharjan?"},
    ]}
    assert agent._contain_intent("contain it", convo) == ["LAPTOP-10"]


def test_nothing_found_is_said_plainly():
    out = agent._not_found([{"args": {"name": "zzz"}, "summary":
                             "'zzz' is not a host, user, domain, IP, brand or technique in the alerts. If it's a general term..."}])
    assert out.startswith("'zzz' is not a host") and "general term" not in out and "spelling" in out


def test_misspelt_name_in_the_message_is_still_routed(known_names, monkeypatch):
    monkeypatch.setattr(agent, "closest_entity", lambda w: "maharjan" if w.lower() in ("mahirjan", "maharjan") else None)
    # the typed name goes through; run_tool corrects it and notes the correction
    assert agent._route("what about the user mahirjan") == [("entity_summary", {"name": "mahirjan"})]
    assert agent._route("mahirjan") == [("entity_summary", {"name": "mahirjan"})]
    assert agent._route("what about the weather") is None


def test_tool_talk_is_dropped():
    assert agent._plain("Isolate LAPTOP-10 (call the isolation tool).") == "Isolate LAPTOP-10."


@pytest.mark.parametrize("text, general", [
    ("what is a C2 beacon?", True),
    ("explain credential phishing", True),
    ("what is LAPTOP-10?", False),
    ("what happened today?", False),
    ("what are our riskiest hosts?", False),
    ("what does it mean?", False),
])
def test_general_questions_skip_the_tools(known_names, text, general):
    assert agent._general(text) is general


def test_did_you_mean_offers_the_question_with_each_name():
    text, options = agent._did_you_mean([{"typed": "mahirjan", "matches": ["maharjan"]}], "what about the user mahirjan")
    assert text == "I don't have any **mahirjan** in the alerts. Closest match: **maharjan**. Did you mean that one?"
    assert options == [{"name": "maharjan", "ask": "what about the user maharjan"}]
    text, options = agent._did_you_mean([{"typed": "FINANCE-PC-1", "matches": ["FINANCE-PC-11", "FINANCE-PC-07"]}],
                                        "show the graph for finance-pc-1")
    assert text.endswith("Closest matches: **FINANCE-PC-11**, **FINANCE-PC-07**. Did you mean one of these?")
    assert [o["ask"] for o in options] == ["show the graph for FINANCE-PC-11", "show the graph for FINANCE-PC-07"]


def test_cleaner_shows_only_finished_clean_sentences(known_names):
    facts = "**LAPTOP-10** is a host in **10 alerts** (9 critical, 1 high)."
    c = agent._Cleaner(facts=facts, reference=facts, convo={"messages": []}, acting=True, limit=2)
    out = ""
    for tok in ["LAPTOP-10 is a host in 10 ", "alerts (9 critical, 1 high). Treat it ",
                "as compromised. BUILD-SRV-02 was hit too. ", "It has been isolated. Propose ",
                "NETWORK_ISOLATION next. Never shown."]:
        out += c.feed(tok)
    out += c.finish()
    # restated fact, unknown host and the claimed action are never shown; stops after 2
    assert out.strip() == "Treat it as compromised. Propose network isolation next."
    assert c.claimed and c.done


def test_cleaner_holds_a_sentence_until_it_ends():
    c = agent._Cleaner()
    assert c.feed("C2 means command ") == ""
    assert c.feed("and control. It") == "C2 means command and control. "
    assert c.finish() == "It"
