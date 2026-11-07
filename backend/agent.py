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
from tools import TOOLS, closest_entity, mentioned_entities, run_tool, tool_specs

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

# after a whole view was drawn: the analyst is looking at it, so point out
# what stands out instead of restating it, and stick to what the result says
AFTER_VIEW = ("The view is drawn above your reply and the analyst is looking at it. In 2-3 short sentences, "
              "point out what stands out in it and the next step. Only state facts that appear in the tool "
              "result above: don't guess at causes, compromises or actions that it doesn't mention.")

# the facts are already written (from the data) and shown: the model only adds
# meaning. A 3B model gets counts and names wrong when it restates them
INTERPRET = ("The analyst already sees this, written from the data:\n{facts}\n\n"
             "Add ONE or TWO short sentences after it: what it means and the next step. Don't repeat its "
             "numbers or names, don't add new facts, no lists.")

RETRY = ("A tool above failed. If another tool (usually search_alerts) can answer the question, call it now; "
         "otherwise tell the analyst plainly what you couldn't find.")

# after tools have run: keep the reply short and about meaning, not data
AFTER_TOOLS = ("Now reply to the analyst in 2-4 short sentences, using only the tool results above: "
               "what it means and the next step. No tables, no raw lists, don't mention tool names.")


PRIORITY = re.compile(r"(look at|start|focus on|work on) first|where (do|should) i start|priorit|needs? attention"
                      r"|what('s| is) urgent|most important|what('s| is) going on", re.I)


# "which of THOSE hosts...", "what about THEM": a follow-up on the last results
FOLLOW_UP = re.compile(r"\b(those|these|them|they|that one|the same|of it|about it)\b", re.I)


# "show me / draw / visualise ...": which whole dashboard view fits. View tools
# are only offered when one of these matches, so a 3B model isn't choosing
# between 16 tools on every question.
VIEWS = [
    ("compare_entities", re.compile(r"\bcompare\b|\bvs\.?\b|\bversus\b|side by side|difference between", re.I)),
    ("show_graph", re.compile(r"\bgraph\b|network (graph|map|view)|connections?|linked to|connected to|\bmap\b", re.I)),
    ("show_screenshots", re.compile(r"screenshots?|look(ed)? like|\bpages? (it |they )?(saw|visited)|captures?", re.I)),
    ("show_ledger", re.compile(r"\bledger\b|audit|\btrail\b|hash chain|\bchain\b|tamper", re.I)),
    ("show_dashboard", re.compile(r"\bshow\b|dashboard|visuali[sz]e|\bdraw\b|overview|break ?down|everything about|\bdisplay\b", re.I)),
]


def _views(text):
    """The view tools this message asks for, best match first."""
    return [name for name, rx in VIEWS if rx.search(text or "")]


def _hints(text, history=()):
    hints = ""
    views = _views(text)
    if views:
        hints += (f"\n\nThe analyst wants to SEE something: call {views[0]} so the whole view is drawn in your reply"
                  + (" (names comma separated)" if views[0] == "compare_entities" else "") + ".")
    known = mentioned_entities(text)
    if known:
        hints += "\n\nNames in this message that exist in the alerts: " + "; ".join(
            f"{v} is a {label}" for v, label in known) + (
            f". Pass them to {_views(text)[0]}." if _views(text) else ". Use entity_summary or search_alerts for them.")
    if PRIORITY.search(text or ""):
        hints += "\n\nThis is a question about priorities: call attention_findings."
    if FOLLOW_UP.search(text or "") and any(m.get("role") == "tool" for m in history):
        hints += ("\n\nThis follows up on earlier results. The answer is probably already in the tool results "
                  "above (look for lines like 'also had phishing'): answer from them, word for word, "
                  "and only call a tool if they really don't cover it.")
    return hints


def _from_history(text, history):
    """A follow-up about results already on screen ("which of those hosts got hit
    most?") with no new name and no new view: answer from them, with no tools.
    Left to choose, a 3B model looks up the word "hosts" instead."""
    if not FOLLOW_UP.search(text or "") or _views(text) or ACTION_ASK.search(text or ""):
        return False
    if mentioned_entities(text):
        return False
    return any(m.get("role") == "tool" and m.get("content") for m in history[-6:])


# ── the router: obvious requests skip the model's tool choice ──────────────
# A 3B model picks the wrong tool, retypes names with a letter wrong, or adds
# filters that don't fit. When the request is plain ("tell me about maharjan",
# "show the graph for LAPTOP-10", "what needs attention?"), the backend makes the
# call itself with the exact names, and the model only explains the result.

# "it", "this host", "the user": the thing the conversation is about
REFERS = re.compile(r"\b(it|its|it's|this (host|user|domain|machine|account|one|ip|brand)"
                    r"|that (host|user|domain|machine|account|one|ip|brand)|the (host|user|domain|machine|account))\b", re.I)
# a question about one thing ("how bad is it?"), when the name comes from the focus
ABOUT = re.compile(r"tell me|what happened|how bad|compromised|\bsafe\b|risk|status of|details|summar|who is"
                   r"|what about|anything (on|about)|look into|\bcheck\b|info", re.I)
INVESTIGATE = re.compile(r"\binvestigate\b|verdict|is (it|\S+) (compromised|infected|hacked)", re.I)
STATUS = re.compile(r"(system|service)s? (status|health|up|online)|is (everything|the system|ollama|neo4j|mongo)\b.*\b(up|online|running|working)", re.I)

SINCE = [(re.compile(r"\btoday\b|last 24 ?h|past day|last day", re.I), 24),
         (re.compile(r"this week|last 7 days|past week|last week", re.I), 168),
         (re.compile(r"this month|last 30 days|past month", re.I), 720)]
LAST_N = re.compile(r"(?:last|past) (\d+) ?(hours?|h|days?|d)\b", re.I)
ENGINE = [(re.compile(r"phish", re.I), "verifyeye"), (re.compile(r"\bc2\b|beacon|command.and.control", re.I), "spectrac2")]
STATUS_WORD = [(re.compile(r"untriaged|\bnew\b|\bopen\b", re.I), "new"),
               (re.compile(r"\bresolved\b|\bclosed\b", re.I), "resolved"), (re.compile(r"\btriaged\b", re.I), "triaged")]
SEVERITY_WORD = re.compile(r"\b(critical|high|medium|low)\b", re.I)
WHOLE_VIEW = re.compile(r"dashboard|overview|everything|all (the )?alerts|break ?down", re.I)


def _focus(convo, kind=None):
    """The host / user / domain the conversation was last about, as (name, kind):
    the newest name a tool looked up, or the newest one the analyst typed.
    kind="host" skips past users and domains to the last host."""
    fits = lambda e: e[1] != "detection engine" and (kind is None or e[1] == kind)
    for m in reversed((convo or {}).get("messages") or []):
        for st in reversed(m.get("steps") or []):
            args = st.get("args") or {}
            for k in ("hostname", "name", "entity", "host", "domain"):
                if args.get(k):
                    hit = [e for e in mentioned_entities(str(args[k])) if fits(e)]
                    if hit:
                        return hit[0]
        if m["role"] == "user":
            named = [e for e in mentioned_entities(m["content"]) if fits(e)]
            if named:
                return named[-1]
    return None


def _filters(text):
    """Dashboard filters written in plain words ("critical phishing this week")."""
    f = {}
    for rx, hours in SINCE:
        if rx.search(text):
            f["since_hours"] = hours
    m = LAST_N.search(text)
    if m:
        f["since_hours"] = int(m.group(1)) * (24 if m.group(2).lower().startswith("d") else 1)
    for rx, engine in ENGINE:
        if rx.search(text):
            f["engine"] = engine
    for rx, status in STATUS_WORD:
        if rx.search(text):
            f["status"] = status
            break
    m = SEVERITY_WORD.search(text)
    if m:
        f["severity"] = m.group(1).lower()
    return f


NAMED_AFTER = re.compile(r"\b(?:user|host|machine|account|domain|laptop|server)\s+([\w.@-]{3,})", re.I)


def _misspelt(text):
    """A name typed with a letter wrong ("the user mahirjan"): the word after
    "user"/"host", or a message that is just the name."""
    words = re.findall(r"[\w.@-]{3,}", text)
    candidates = NAMED_AFTER.findall(text) or (words if 0 < len(words) <= 2 else [])
    out = []
    for w in candidates:
        meant = closest_entity(w)
        if meant:
            # keep what was typed: run_tool corrects it and says so in the reply
            out += [(w, k) for v, k in mentioned_entities(meant) if v == meant and k != "detection engine"][:1]
    return out


# "what is a C2 beacon?": general knowledge, nothing to look up
KNOWLEDGE = re.compile(r"^\s*(what('s| is| are| does)|explain|define|how (does|do)|why (does|do|is)|what do you mean)\b", re.I)
OUR_DATA = re.compile(r"\b(our|we|any|alerts?|hosts?|users?|today|this week|seen|detected|attention|happened|ledger|screenshots?)\b", re.I)


def _general(text, convo=None):
    """A general security question that names nothing in the alerts."""
    return bool(KNOWLEDGE.search(text or "") and not OUR_DATA.search(text or "")
                and not mentioned_entities(text) and not REFERS.search(text or ""))


GENERAL = ("This is a general security question: answer it from your own knowledge in 2-4 short sentences. "
           "Don't describe this organisation's alerts, hosts or engines.")


def _route(text, convo=None):
    """The tool calls a plain request obviously needs, as [(tool, args)], or None
    to let the model choose (actions, open questions, general knowledge)."""
    text = text or ""
    if ACTION_ASK.search(text):
        return None          # actions go through the model + the approval card
    named = [(v, k) for v, k in mentioned_entities(text, limit=6) if k != "detection engine"]
    if not named:
        named = _misspelt(text)
    from_focus = False
    if not named and REFERS.search(text):
        focus = _focus(convo)
        if focus:
            named, from_focus = [focus], True
    names = [v for v, _ in named]
    views = _views(text)
    view = views[0] if views else None

    if view == "compare_entities":
        return [("compare_entities", {"names": ", ".join(names[:4])})] if len(names) >= 2 else None
    if view == "show_graph":
        return [("show_graph", {"entity": names[0]})] if names else None
    if view == "show_ledger":
        return [("show_ledger", {"entity": names[0]} if names else {})]
    if view == "show_screenshots":
        args = {}
        for v, kind in named:
            if kind == "domain":
                args.setdefault("domain", v)
            elif kind == "impersonated brand":
                args.setdefault("query", v)
        verdict = next((w for w in ("phishing", "cleared", "blocked") if re.search(w[:5], text, re.I)), None)
        verdict = verdict or next((VERDICT[w] for w in VERDICT if re.search(rf"\b{w}\b", text, re.I)), None)
        if verdict:
            args["verdict"] = verdict
        return [("show_screenshots", args)]
    if view == "show_dashboard":
        args = _filters(text)
        for v, kind in named[:1]:
            args["host" if kind == "host" else "query"] = v
        if args or WHOLE_VIEW.search(text):
            return [("show_dashboard", args)]
        return None          # "show me powershell alerts": the model picks the filters
    if PRIORITY.search(text):
        return [("attention_findings", {})]
    if STATUS.search(text):
        return [("system_status", {})]
    if names and (not from_focus or ABOUT.search(text) or INVESTIGATE.search(text)):
        hosts = [v for v, k in named if k == "host"]
        if INVESTIGATE.search(text) and hosts:
            return [("investigate_host", {"hostname": hosts[0]})]
        return [("entity_summary", {"name": v}) for v in names[:3]]
    return None


# words for a screenshot verdict, as the analyst says them
VERDICT = {"fake": "phishing", "malicious": "phishing", "safe": "cleared", "genuine": "cleared",
           "legit": "cleared", "captcha": "blocked", "bot check": "blocked"}


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
    focus = _focus(convo, kind="host")
    return [focus[0]] if focus else []


def _grounded(answer, reference):
    """Drop sentences naming a host / user / domain / IP that none of this turn's
    results mention: the model made that link up."""
    ref = (reference or "").lower()
    keep = []
    for sentence in re.split(r"(?<=[.!?])\s+", answer.strip()):
        names = [v for v, _ in mentioned_entities(sentence, limit=20)]
        if all(v.lower() in ref for v in names):
            keep.append(sentence)
    return " ".join(keep)


def _words(text):
    return set(re.findall(r"[a-z0-9][a-z0-9.\-]*[a-z0-9]|[a-z0-9]", (text or "").lower()))


def _new_only(answer, facts):
    """Drop the model's sentences that just restate the facts (it's told not to,
    and does anyway): keep only what it adds."""
    known = _words(facts)
    keep = []
    for sentence in re.split(r"(?<=[.!?])\s+", answer.strip()):
        w = _words(sentence)
        if w and len(w & known) / len(w) < 0.6:
            keep.append(sentence)
    return " ".join(keep)


def _not_repeated(answer, convo):
    """Drop sentences the agent already said in its last few replies (a small
    model copies its previous answer when the new results look similar)."""
    said = " ".join(m.get("content") or "" for m in (convo or {}).get("messages", [])[-6:] if m["role"] == "assistant")
    return " ".join(x for x in re.split(r"(?<=[.!?])\s+", answer.strip()) if x.strip() and x.strip() not in said)


def _plain(text):
    """NETWORK_ISOLATION -> network isolation: the model echoes internal names.
    "(call the isolation tool)": the analyst doesn't call tools."""
    text = re.sub(r"\s*\((call|use|using|via) [^)]*\btool\b[^)]*\)", "", text, flags=re.I)
    return re.sub(r"\*{0,2}\b([A-Z]{2,}(?:_[A-Z]{2,})+)\b\*{0,2}", lambda m: m.group(1).replace("_", " ").lower(), text)


def _first_sentences(text, n=3):
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return " ".join(parts[:n])


def _tidy(answer):
    """Drop any markdown table the model wrote anyway (the real data is drawn)."""
    lines = [l for l in answer.splitlines()
             if not re.match(r"^\s*\|.*\|\s*$", l) and l.strip().lower() != "assistant"]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


# when a view is asked for, the smaller tool it replaces is hidden
SUPERSEDED = {"show_screenshots": "get_evidence", "show_graph": "get_host_graph", "show_ledger": "ledger_lookup"}
VIEW_RENDERS = {"dashboard", "graph_explorer", "screenshots", "ledger_view", "compare"}
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _ollama_tools(text, context):
    """The tools the model may call this turn. get_alert needs a real alert id:
    offered only when the message or context has one, or a small model makes
    ids up instead of searching."""
    has_id = UUID.search(f"{text} {context or ''}")
    views = set(_views(text))
    hidden = {SUPERSEDED[v] for v in views if v in SUPERSEDED}   # one obvious choice, not two similar ones
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                              "parameters": t["inputSchema"]}}
            for t in tool_specs()
            if (t["name"] != "get_alert" or has_id) and t["name"] not in hidden
            and (t.get("render") not in VIEW_RENDERS or t["name"] in views)]


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
                out += [{"role": "tool", "content": s.get("summary", "")[:1200], "tool_name": s["tool"]} for s in steps]
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


def _not_found(failed):
    """What to say when the backend's own lookups found nothing: plainly, with no
    guess at what it is or whether it's safe (the model guesses)."""
    lines = []
    for st in failed:
        said = re.split(r"(?<=[.!?])\s+", st["summary"].strip())
        n = 3 if "older ones" in st["summary"] else 1     # keep "the newest is from ..."
        first = " ".join(said[:n])
        lines.append(first[0].upper() + first[1:] if first else "Nothing came back.")
    named = any(k in (st.get("args") or {}) for st in failed for k in ("name", "entity", "hostname", "names"))
    return " ".join(lines) + (" Check the spelling, or ask me to search for part of the name." if named else "")


def run_turn(owner, conversation_id, text, context=None):
    """One analyst message -> a stream of newline-delimited JSON events."""
    convo = get_conversation(owner, conversation_id)
    if not convo:
        yield _event("error", message="Conversation not found")
        return
    append_message(owner, conversation_id, "user", text)

    history = _history(convo)
    general = _general(text)
    answer_only = general or _from_history(text, history)
    plan = None if answer_only else _route(text, convo)
    focus = _focus(convo)
    about = (f"\n\nThe conversation so far is about {focus[0]} (a {focus[1]}): \"it\" or \"this\" means {focus[0]}."
             if focus and not mentioned_entities(text) else "")
    messages = [{"role": "system", "content": SYSTEM + ("\n\n" + GENERAL if general else "" if plan else _hints(text, history)) + about
                 + (f"\n\nThe analyst is looking at: {context}" if context else "")}]
    messages += history
    messages.append({"role": "user", "content": text})
    tools = [] if answer_only else _ollama_tools(text, context)

    steps, blocks, approvals, answer = [], [], [], ""
    lead = []          # facts written from the data, shown first
    reference = text   # everything this turn's results say, for the grounding check
    try:
        for _ in range(MAX_ROUNDS):
            routed = bool(plan)
            if plan:
                # the backend chose: same as if the model had called them
                calls = [{"function": {"name": n, "arguments": a}} for n, a in plan]
                plan = None
            else:
                reply = None
                for kind, payload in _chat(messages, tools):
                    if kind == "token":
                        answer += payload
                        yield _event("token", text=payload)
                    else:
                        reply = payload
                if not reply["tool_calls"]:
                    break
                calls = reply["tool_calls"]
            messages.append({"role": "assistant", "content": "" if routed else reply["content"], "tool_calls": calls})

            proposed, written = False, []
            for call in calls:
                name = call["function"]["name"]
                args = call["function"].get("arguments") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except ValueError:
                        args = {}
                yield _event("step", tool=name, args=args, status="running")
                result = run_tool(name, args, analyst=owner)
                step = {"tool": name, "args": result.get("args", args), "ok": result["ok"], "summary": result["summary"]}
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
                    if result.get("reply"):
                        written.append(result["reply"])
                messages.append({"role": "tool", "content": result["summary"], "tool_name": name})
                reference += "\n" + result["summary"]
                if result["ok"] and result.get("facts") and not result.get("reply"):
                    lead.append(result["facts"])
                    reference += "\n" + result["facts"]
                    yield _event("token", text=result["facts"] + "\n\n")
            # tools that write their own reply (screenshots: the model can't see them
            # and would invent what they show): that IS the answer, no model call
            if written and len(written) == len(calls):
                text_out = "\n\n".join(written)
                answer += text_out
                yield _event("token", text=text_out)
                break
            failed = [st for st in steps[-len(calls):] if not st["ok"] and "approval" not in st["summary"]]
            if routed and failed and len(failed) == len(calls):
                # the backend looked up exactly what was asked and it isn't there:
                # say so, don't let the model guess (or search again for a typo)
                text_out = _not_found(failed)
                answer += text_out
                yield _event("token", text=text_out)
                break
            # all good: answer now. something failed: let it try another tool first
            if lead and (not failed or routed):
                messages[-1]["content"] += "\n\n" + INTERPRET.format(facts="\n".join(lead))
            else:
                viewed = any(b["render"] in VIEW_RENDERS for b in blocks)
                messages[-1]["content"] += "\n\n" + (RETRY if failed else AFTER_VIEW if viewed else AFTER_TOOLS)

            if proposed or (lead and not failed) or routed:
                # facts are out (or an action waits on the analyst): one last call for
                # the meaning, with no tools so it can't wander off
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
    if lead:
        # the model's part: short, and only about things the results mention
        answer = _first_sentences(_not_repeated(_grounded(_new_only(_tidy(answer), "\n".join(lead)), reference), convo))
    answer = _plain(answer)
    acting = bool(approvals) or bool(ACTION_ASK.search(text or ""))
    if acting and CLAIMED_ACTION.search(answer):
        # drop the sentences that claim it (the page swaps in this cleaned answer)
        answer = " ".join(x for x in re.split(r"(?<=[.!?])\s+", answer) if not CLAIMED_ACTION.search(x))
        answer += "\n\nNothing has been changed yet — " + ("approve the card below to go ahead." if approvals
                                                            else "I can only act through an approval card.")

    answer = _tidy("\n\n".join(lead + [answer]) if lead else answer)
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
