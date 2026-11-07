"""The SOC agent: plain-English requests in, tool calls and answers out.

One turn:
  1. the analyst's message is saved to the conversation
  2. the model (local Ollama) sees recent history + the tool registry, and
     either answers or calls tools. Read tools run straight away; action
     tools become an approval card and are NOT run
  3. every step is streamed to the page as it happens, then the answer
     token by token, then the whole turn is saved so the chat can be
     reopened exactly as it was

The model only ever reads short tool summaries. What the analyst sees (the
graph, the alerts, the screenshot) is drawn from the tool's real data.
"""
from __future__ import annotations

import json
import re
import uuid

import httpx

from config import OLLAMA_URL, OLLAMA_MODEL
from conversations import append_message, get_conversation, update_message
from tools import TOOLS, mentioned_entities, run_tool, tool_specs

MAX_ROUNDS = 5        # tool rounds per message, so a small model can't loop forever
HISTORY = 12          # past messages the model sees (older ones still show on the page)

SYSTEM = """You are OmniGuard's SOC agent, working alongside a security analyst in their dashboard.

How you work:
- For anything about THIS organisation (its alerts, hosts, users, domains, IPs, screenshots, the ledger), call a tool. Never guess or invent names, numbers or results.
- For general security questions (what is phishing, C2, MITRE...), answer directly from your knowledge.
- Whatever a tool returns is already drawn for the analyst below your reply (tables, graphs, screenshots), so don't repeat it line by line: say what it means and what to do next, in 2 to 5 short sentences.
- To change something (isolate a host, mark an alert triaged/resolved) call the action tool. It is NOT done until the analyst approves the card they see, so say you've proposed it — never say it's done.
- If a tool fails or returns an error, try search_alerts with the name as the query before concluding anything. Never say there is no data because a tool errored.
- Never mention tool names or invent tools. Never draw tables or list raw records: they are already on screen.
Be concise and practical. No preamble.

About OmniGuard (the system you're part of):
- VerifyEye is OmniGuard's own browser extension: it detects phishing login pages, and its sandboxed agent screenshots them.
- SpectraC2 is OmniGuard's own network engine: it detects command-and-control (C2) beaconing from infected hosts. It is NOT an attacker or threat group.
- A host is a machine (e.g. LAPTOP-10); a user is a person's account."""

RETRY = ("A tool above failed. If another tool (usually search_alerts) can answer the question, call it now; "
         "otherwise tell the analyst plainly what you couldn't find.")

# after tools have run: keep the reply short and about meaning, not data
AFTER_TOOLS = ("Now reply to the analyst in 2-4 short sentences, using only the tool results above: "
               "what it means and the next step. No tables, no raw lists, don't mention tool names.")


PRIORITY = re.compile(r"(look at|start|focus on|work on) first|where (do|should) i start|priorit|needs? attention"
                      r"|what('s| is) urgent|most important|what('s| is) going on", re.I)


# "which of THOSE hosts...", "what about THEM": a follow-up on the last results
FOLLOW_UP = re.compile(r"\b(those|these|them|they|that one|the same|of it|about it)\b", re.I)


def _hints(text, history=()):
    hints = ""
    known = mentioned_entities(text)
    if known:
        hints += "\n\nNames in this message that exist in the alerts: " + "; ".join(
            f"{v} is a {label}" for v, label in known) + ". Use entity_summary or search_alerts for them."
    if PRIORITY.search(text or ""):
        hints += "\n\nThis is a question about priorities: call attention_findings."
    if FOLLOW_UP.search(text or "") and any(m.get("role") == "tool" for m in history):
        hints += ("\n\nThis follows up on earlier results. The answer is probably already in the tool results "
                  "above (look for lines like 'also had phishing'): answer from them, word for word, "
                  "and only call a tool if they really don't cover it.")
    return hints


def _text_tool_call(content):
    """llama3.2 sometimes writes a tool call as text ({"name": ..., "parameters": ...})
    instead of calling it. Recover it as a real call, or None."""
    m = re.search(r"\{.*\}", content or "", re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except ValueError:
        return None
    name = obj.get("name") or obj.get("function")
    if isinstance(name, str) and name in TOOLS:
        args = obj.get("parameters") or obj.get("arguments") or {}
        return [{"function": {"name": name, "arguments": args if isinstance(args, dict) else {}}}]
    return None


# "contain / isolate / quarantine LAPTOP-10", with a host that exists
CONTAIN = re.compile(r"\b(contain|isolate|quarantine|cut (it|them) off|take (it|them) offline)\b", re.I)
ACTION_ASK = re.compile(r"\b(contain|isolate|quarantine|block|resolve|close|triage|mark|cut (it|them) off)\b", re.I)
# a sentence saying an action already happened: "has been isolated", "is fully
# contained", "credentials have been revoked", "isolation was applied"...
CLAIMED_ACTION = re.compile(
    r"\b(has|have|had) (now )?been (fully |successfully |now )?"
    r"(isolated|contained|quarantined|resolved|blocked|triaged|revoked|disabled|removed|cut off|taken offline)\b"
    r"|\b(is|are|was|were) (now |fully |successfully )+(isolated|contained|quarantined|offline|blocked|revoked)\b"
    r"|\b(isolation|containment|quarantine|revocation) (was|has been) (applied|completed|performed|done|executed)\b"
    r"|\bI('ve| have) (isolated|contained|quarantined|blocked|revoked|resolved)\b", re.I)


def _contain_intent(text, convo=None):
    """Hosts the analyst asked to contain. "contain it" names none: then it's
    the host the conversation was last about (a host named in an earlier
    message, or one an earlier tool looked up)."""
    if not CONTAIN.search(text or ""):
        return []
    hosts = [v for v, label in mentioned_entities(text) if label == "host"]
    if hosts or not convo:
        return hosts
    for m in reversed(convo["messages"]):
        for st in reversed(m.get("steps") or []):
            h = (st.get("args") or {}).get("hostname")
            if h:
                return [h]
            if st.get("tool") == "entity_summary" and " is a host " in (st.get("summary") or ""):
                return [st["args"].get("name")]
        if m["role"] == "user":
            named = [v for v, label in mentioned_entities(m["content"]) if label == "host"]
            if named:
                return named[-1:]
    return []


def _tidy(answer):
    """Drop any markdown table the model wrote anyway (the real data is drawn)."""
    lines = [l for l in answer.splitlines()
             if not re.match(r"^\s*\|.*\|\s*$", l) and l.strip().lower() != "assistant"]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _ollama_tools(text, context):
    """The tools the model may call this turn. get_alert needs a real alert id:
    offered only when the message or context has one, or a small model makes
    ids up instead of searching."""
    has_id = UUID.search(f"{text} {context or ''}")
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                              "parameters": t["inputSchema"]}}
            for t in tool_specs() if t["name"] != "get_alert" or has_id]


def _history(convo):
    """Recent messages for the model. Tool results were summaries already; an
    assistant turn that used tools carries a one-line note of what it found."""
    out = []
    for m in convo["messages"][-HISTORY:]:
        if m["role"] == "user":
            out.append({"role": "user", "content": m["content"]})
        elif m["role"] == "assistant":
            steps = m.get("steps") or []
            if steps:
                out.append({"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": s["tool"], "arguments": s.get("args") or {}}} for s in steps]})
                out += [{"role": "tool", "content": s.get("summary", "")[:600], "tool_name": s["tool"]} for s in steps]
            out.append({"role": "assistant", "content": m.get("content") or ""})
    return out


def _chat(messages, tools):
    """Stream one model call. Yields ("token", text) and finally ("done", message).
    Text that starts like JSON is held back: it's usually a tool call written as
    text, which gets recovered as a real call instead of shown to the analyst."""
    content, calls, held = "", [], None
    with httpx.stream("POST", f"{OLLAMA_URL}/api/chat", timeout=120.0, json={
        "model": OLLAMA_MODEL, "messages": messages, "tools": tools, "stream": True, "keep_alive": "30m",
        "options": {"temperature": 0.2, "num_ctx": 8192, "num_predict": 500, "repeat_penalty": 1.15},
    }) as r:
        r.raise_for_status()
        for line in r.iter_lines():
            if not line:
                continue
            chunk = json.loads(line)
            msg = chunk.get("message") or {}
            if msg.get("tool_calls"):
                calls.extend(msg["tool_calls"])
            if msg.get("content"):
                content += msg["content"]
                if held is None and content.strip():
                    held = content.lstrip().startswith("{")
                if not calls and held is False:
                    yield "token", msg["content"]
            if chunk.get("done"):
                break
    if held and not calls:
        recovered = _text_tool_call(content)
        if recovered:
            calls, content = recovered, ""
        else:
            yield "token", content
    yield "done", {"role": "assistant", "content": content, "tool_calls": calls}


def _event(kind, **data):
    return json.dumps({"type": kind, **data}, default=str) + "\n"


def run_turn(owner, conversation_id, text, context=None):
    """One analyst message -> a stream of newline-delimited JSON events."""
    convo = get_conversation(owner, conversation_id)
    if not convo:
        yield _event("error", message="Conversation not found")
        return
    append_message(owner, conversation_id, "user", text)

    history = _history(convo)
    messages = [{"role": "system", "content": SYSTEM + _hints(text, history)
                 + (f"\n\nThe analyst is looking at: {context}" if context else "")}]
    messages += history
    messages.append({"role": "user", "content": text})
    tools = _ollama_tools(text, context)

    steps, blocks, approvals, answer = [], [], [], ""
    try:
        for _ in range(MAX_ROUNDS):
            reply = None
            for kind, payload in _chat(messages, tools):
                if kind == "token":
                    answer += payload
                    yield _event("token", text=payload)
                else:
                    reply = payload
            if not reply["tool_calls"]:
                break

            messages.append({"role": "assistant", "content": reply["content"], "tool_calls": reply["tool_calls"]})
            proposed = False
            for call in reply["tool_calls"]:
                name = call["function"]["name"]
                args = call["function"].get("arguments") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except ValueError:
                        args = {}
                yield _event("step", tool=name, args=args, status="running")
                result = run_tool(name, args, analyst=owner)
                step = {"tool": name, "args": args, "ok": result["ok"], "summary": result["summary"]}
                steps.append(step)
                yield _event("step", **step, status="done")

                if result.get("needs_approval"):
                    proposed = True
                    approval = {"approval_id": str(uuid.uuid4()), "tool": name, "args": result["data"]["args"],
                                "description": TOOLS[name]["description"], "status": "pending"}
                    approvals.append(approval)
                    yield _event("approval", **approval)
                elif result["ok"] and result.get("data") is not None and result["render"] != "text":
                    block = {"render": result["render"], "tool": name, "data": result["data"]}
                    blocks.append(block)
                    yield _event("block", **block)
                messages.append({"role": "tool", "content": result["summary"], "tool_name": name})
            # all good: answer now. something failed: let it try another tool first
            failed = [st for st in steps[-len(reply["tool_calls"]):] if not st["ok"] and "approval" not in st["summary"]]
            messages[-1]["content"] += "\n\n" + (RETRY if failed else AFTER_TOOLS)

            if proposed:
                # an action waits for the analyst: let the model say so, without more tools
                for kind, payload in _chat(messages, []):
                    if kind == "token":
                        answer += payload
                        yield _event("token", text=payload)
                break
        else:
            note = "\n\n(I stopped after several steps — ask me to continue if you need more.)"
            answer += note
            yield _event("token", text=note)
    except httpx.HTTPError as e:
        note = f"I couldn't reach the local AI model ({type(e).__name__}). Is Ollama running?"
        answer = (answer + "\n\n" + note).strip()
        yield _event("token", text=note)

    # asked to contain a known host but the model didn't propose it: propose it
    for host in _contain_intent(text, convo):
        if not any(a["tool"] == "isolate_host" and a["args"].get("hostname", "").lower() == host.lower() for a in approvals):
            approval = {"approval_id": str(uuid.uuid4()), "tool": "isolate_host", "args": {"hostname": host},
                        "description": TOOLS["isolate_host"]["description"], "status": "pending"}
            approvals.append(approval)
            yield _event("approval", **approval)
    # the model must never claim an action happened: only an approved card does that
    # only when an action was asked for or proposed this turn: describing past,
    # real actions from the ledger ("it has been isolated twice") is fine
    acting = bool(approvals) or bool(ACTION_ASK.search(text or ""))
    if acting and CLAIMED_ACTION.search(answer):
        # drop the sentences that claim it (the page swaps in this cleaned answer)
        answer = " ".join(x for x in re.split(r"(?<=[.!?])\s+", answer) if not CLAIMED_ACTION.search(x))
        answer += "\n\nNothing has been changed yet — " + ("approve the card below to go ahead." if approvals
                                                            else "I can only act through an approval card.")

    answer = _tidy(answer)
    message = append_message(owner, conversation_id, "assistant", answer,
                             steps=steps, blocks=blocks, approvals=approvals)
    yield _event("done", message_id=message["message_id"] if message else None, content=answer)


def decide_approval(owner, conversation_id, approval_id, approve):
    """Approve (run, as this analyst) or reject a proposed action."""
    convo = get_conversation(owner, conversation_id)
    if not convo:
        return None
    for m in convo["messages"]:
        for a in m.get("approvals", []):
            if a["approval_id"] != approval_id:
                continue
            if a["status"] != "pending":
                return {"approval": a, "already": True}
            if approve:
                result = run_tool(a["tool"], a["args"], analyst=owner, approved=True)
                a.update(status="approved" if result["ok"] else "failed", result=result["summary"], decided_by=owner)
            else:
                a.update(status="rejected", decided_by=owner)
            update_message(owner, conversation_id, m["message_id"], {"approvals": m["approvals"]})
            return {"approval": a, "already": False}
    return None
