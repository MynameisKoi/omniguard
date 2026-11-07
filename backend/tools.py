"""The SOC tool registry: one list of things the AI can do for an analyst.

Used by the in-app agent (the Ask AI page) and by the MCP server, so a tool
added here shows up in both. Each tool has:
  name, description, parameters  the JSON schema the model sees
  kind        "read" runs straight away; "action" changes something and only
              runs after an analyst approves it (see run_tool / approve)
  render      which dashboard component the page draws the result with

A tool returns {"summary": short text for the model, "data": what the page
draws}. The model only reads the summary — a 3B model has little room, and the
numbers on screen come straight from the database either way.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from db import database
from evidence import list_evidence
from graph import get_host_graph
from ledger import append_ledger_entry, get_ledger_for_entity, get_recent_ledger
from status import check_mongo, check_neo4j, check_ollama
from agents import MultiAgentInvestigationPipeline

alerts_collection = database["alerts"]

SEVERITIES = ["critical", "high", "medium", "low"]
STATUSES = ["new", "triaged", "resolved"]
ALERT_FIELDS = {"_id": 0, "simhash": 0}

# what an analyst would type, across the fields they'd mean
SEARCH_FIELDS = ["host", "user", "event_type", "domain", "src_ip", "dst_ip", "source",
                 "mitre_technique", "description", "brand_target", "status", "target_url",
                 "process_name", "alert_id"]
# which field a name is the value of ("LAPTOP-10" is a host)
ENTITY_FIELDS = [("host", "host"), ("user", "user"), ("domain", "domain"),
                 ("brand_target", "impersonated brand"), ("mitre_technique", "MITRE technique"),
                 ("src_ip", "IP address"), ("dst_ip", "IP address"), ("source", "detection engine")]


class ToolError(Exception):
    """A problem the model should read and recover from (bad name, not found)."""


def _given(v):
    # small models fill unused arguments with "" or "null"
    return v not in (None, "", "null", "None", [])


def _when(ts):
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc).strftime("%b %d %H:%M UTC")
    return str(ts or "")


def _alert_line(a):
    bits = [a.get("severity", "?"), a.get("event_type", "?"), f"host={a.get('host')}"]
    if a.get("user"):
        bits.append(f"user={a['user']}")
    if a.get("domain"):
        bits.append(f"domain={a['domain']}")
    bits.append(_when(a.get("timestamp")))
    return " | ".join(bits)


# ── read tools ────────────────────────────────────────────────────────────

def search_alerts(query=None, severity=None, engine=None, host=None, status=None, since_hours=None, limit=20):
    q = {}
    if _given(severity):
        if severity not in SEVERITIES:
            raise ToolError(f"severity must be one of {SEVERITIES}")
        q["severity"] = severity
    if _given(engine):
        q["source"] = str(engine).lower()
    if _given(host):
        q["host"] = {"$regex": f"^{re.escape(str(host))}$", "$options": "i"}
    if _given(status):
        q["status"] = status
    if _given(since_hours):
        q["timestamp"] = {"$gte": datetime.now(timezone.utc) - timedelta(hours=float(since_hours))}
    if _given(query):
        rx = {"$regex": re.escape(str(query)), "$options": "i"}
        q["$or"] = [{f: rx} for f in SEARCH_FIELDS]
    limit = max(1, min(int(limit or 20), 100))
    total = alerts_collection.count_documents(q)
    rows = list(alerts_collection.find(q, ALERT_FIELDS).sort("timestamp", -1).limit(limit))
    sev = Counter(a.get("severity") for a in rows)
    summary = f"{total} alert(s) match" + (f", showing {len(rows)}" if total > len(rows) else "")
    if rows:
        summary += " (" + ", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev[s]) + "):\n"
        summary += "\n".join(f"- {_alert_line(a)}" for a in rows[:8])
    return {"summary": summary, "data": {"alerts": rows, "total": total}}


def get_alert(alert_id):
    a = alerts_collection.find_one({"alert_id": alert_id}, ALERT_FIELDS)
    if not a:
        raise ToolError(f"no alert with id {alert_id}")
    shots = list_evidence(url=a["target_url"], limit=1) if a.get("target_url") else []
    extra = f"\nAgent screenshot: {'phishing' if shots[0]['phishing'] else 'cleared'}" if shots else ""
    return {"summary": _alert_line(a) + (f"\n{a['description']}" if a.get("description") else "") + extra,
            "data": {"alert": a, "evidence": shots[:1]}}


def entity_summary(name):
    name = str(name or "").strip()
    if not name:
        raise ToolError("give the name of a host, user, domain, IP, brand or technique")
    kind, field = None, None
    for f, label in ENTITY_FIELDS:
        n = alerts_collection.count_documents({f: {"$regex": f"^{re.escape(name)}$", "$options": "i"}})
        if n:
            kind, field = label, f
            break
    if not field:
        raise ToolError(f"'{name}' is not a host, user, domain, IP, brand or technique in the alerts. "
                        "If it's a general security term, answer from your own knowledge.")
    fields = [f for f, label in ENTITY_FIELDS if label == kind]   # IPs: src and dst
    rx = {"$regex": f"^{re.escape(name)}$", "$options": "i"}
    rows = list(alerts_collection.find({"$or": [{f: rx} for f in fields]}, ALERT_FIELDS).sort("timestamp", -1))
    times = [a["timestamp"] for a in rows if isinstance(a.get("timestamp"), datetime)]
    sev = Counter(a.get("severity") for a in rows)
    hosts = Counter(a.get("host") for a in rows if a.get("host"))
    distinct = lambda f: sorted({a[f] for a in rows if a.get(f)})
    data = {
        "name": name, "kind": kind, "alert_count": len(rows),
        "first_seen": min(times) if times else None, "last_seen": max(times) if times else None,
        "severity": {s: sev[s] for s in SEVERITIES},
        "hosts": [{"host": h, "alerts": n} for h, n in hosts.most_common()],
        "users": distinct("user"), "domains": distinct("domain"),
        "engines": distinct("source"), "alerts": rows[:20],
    }
    article = "an" if kind[0] in "aeiouI" else "a"
    summary = (f"{name} is {article} {kind} in {len(rows)} alert(s) "
               f"({', '.join(f'{sev[s]} {s}' for s in SEVERITIES if sev[s])}). "
               f"First seen {_when(data['first_seen'])}, last seen {_when(data['last_seen'])}. "
               f"Hosts: {', '.join(f'{h} ({n})' for h, n in hosts.most_common(5)) or 'none'}. "
               f"Domains: {', '.join(data['domains'][:5]) or 'none'}. Engines: {', '.join(data['engines'])}.")
    return {"summary": summary, "data": data}


def host_graph(hostname):
    graph = get_host_graph(hostname)   # neo4j down -> ServiceUnavailable, handled in run_tool
    if not graph["nodes"]:
        raise ToolError(f"no host called {hostname} in the graph")
    kinds = Counter(n["type"] for n in graph["nodes"])
    summary = (f"The graph around {hostname} has {len(graph['nodes'])} entities and {len(graph['edges'])} links: "
               + ", ".join(f"{n} {t}" for t, n in kinds.most_common()) + ". It is drawn for the analyst.")
    return {"summary": summary, "data": {"host": hostname, **graph}}


def get_evidence(alert_id=None, url=None, domain=None):
    if _given(alert_id):
        a = alerts_collection.find_one({"alert_id": alert_id}, {"target_url": 1})
        if not a:
            raise ToolError(f"no alert with id {alert_id}")
        url = a.get("target_url")
    if not (_given(url) or _given(domain)):
        raise ToolError("give an alert_id, a url or a domain")
    shots = list_evidence(domain=domain if _given(domain) else None, url=url if _given(url) else None, limit=6)
    if not shots:
        return {"summary": "The VerifyEye agent has no screenshot of that page yet.", "data": {"evidence": []}}
    e = shots[0]
    verdict = "phishing" if e["phishing"] else "blocked by a bot check" if e.get("blocked") else "cleared"
    summary = (f"{len(shots)} screenshot(s). Latest: {e['url']} — {verdict}"
               + (f", confidence {e['confidence']:.0%}" if e["phishing"] else "")
               + (f", looks like {e['brand']}" if e.get("brand") else "")
               + (f", password goes to {', '.join(e['form_actions'][:2])}" if e.get("off_domain") else "")
               + ". Shown to the analyst.")
    return {"summary": summary, "data": {"evidence": shots}}


def attention_findings():
    alerts = list(alerts_collection.find({}, ALERT_FIELDS))
    findings = []
    local = re.compile(r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")

    engines = {}
    for a in alerts:
        if a.get("host"):
            engines.setdefault(a["host"], set()).add(a.get("source"))
    both = sorted(h for h, e in engines.items() if {"verifyeye", "spectrac2"} <= e)
    if both:
        findings.append({"tone": "bad", "entities": both,
                         "text": f"{', '.join(both)} have both a phishing and a C2 alert — two engines agreeing usually means a real compromise."})

    for field, kind in (("domain", "domain"), ("dst_ip", "IP")):
        seen = {}
        for a in alerts:
            v = a.get(field)
            if v and a.get("host") and not local.match(v):
                seen.setdefault(v, set()).add(a["host"])
        for v, hs in sorted(seen.items(), key=lambda kv: -len(kv[1]))[:2]:
            if len(hs) > 1:
                findings.append({"tone": "bad", "entities": [v],
                                 "text": f"The {kind} {v} is contacted by {len(hs)} hosts — shared attacker infrastructure."})

    open_crit = [a for a in alerts if a.get("severity") == "critical" and a.get("status") == "new"]
    if open_crit:
        top = Counter(a["host"] for a in open_crit).most_common(3)
        findings.append({"tone": "bad", "entities": [h for h, _ in top],
                         "text": f"{len(open_crit)} critical alerts still untriaged, most on " + ", ".join(f"{h} ({n})" for h, n in top) + "."})

    since = datetime.now(timezone.utc) - timedelta(days=1)
    recent = [a for a in alerts if isinstance(a.get("timestamp"), datetime) and a["timestamp"] >= since]
    if recent:
        findings.append({"tone": "warn", "entities": sorted({a["host"] for a in recent})[:3],
                         "text": f"{len(recent)} new alert(s) in the last 24 hours."})

    if not findings:
        findings.append({"tone": "good", "entities": [], "text": "All clear — nothing urgent."})
    return {"summary": "\n".join(f"- {f['text']}" for f in findings), "data": {"findings": findings}}


def system_status():
    s = {"mongo": check_mongo(), "neo4j": check_neo4j(), "ollama": check_ollama()}
    return {"summary": ", ".join(f"{k} {'online' if v else 'OFFLINE'}" for k, v in s.items()), "data": {"status": s}}


def ledger_lookup(entity=None, limit=10):
    rows = get_ledger_for_entity(entity)[:limit] if _given(entity) else get_recent_ledger(int(limit or 10))
    rows = [{k: v for k, v in r.items() if k != "_id"} for r in rows]
    if not rows:
        return {"summary": "No ledger entries" + (f" for {entity}" if _given(entity) else "") + ".", "data": {"records": []}}
    summary = "\n".join(f"- {r.get('timestamp', '')[:16]} {r.get('stage')} {r.get('action_taken')} on "
                        f"{r.get('entity_id')} by {r.get('analyst_user')}" for r in rows[:8])
    return {"summary": summary, "data": {"records": rows}}


def investigate_host(hostname):
    alerts = list(alerts_collection.find({}, {"_id": 0}))
    if not any((a.get("host") or "").lower() == str(hostname).lower() for a in alerts):
        raise ToolError(f"no alerts for a host called {hostname}")
    result = MultiAgentInvestigationPipeline().investigate(hostname, alerts)
    t, c = result.get("triage", {}), result.get("containment", {})
    summary = (f"Verdict: {t.get('classification')} (risk {t.get('risk_score')}/100, confidence "
               f"{t.get('confidence')}). Recommended: "
               + "; ".join(f"{a.get('urgency')}: {a.get('action')}" for a in c.get("recommended_actions", [])))
    return {"summary": summary, "data": {"investigation": result}}


# ── action tools: only run after an analyst approves ─────────────────────

def isolate_host(hostname, reason=None, analyst="unknown"):
    msg = (f"Containment requested for '{hostname}'"
           + (f": {reason}" if _given(reason) else "")
           + ". Simulated for now — no real network action is taken yet.")
    append_ledger_entry(entity_type="HOST", entity_id=hostname, stage="EDR_CONTAINMENT",
                        action_taken="NETWORK_ISOLATION_SIMULATED", reasoning_output=msg, analyst_user=analyst)
    return {"summary": f"{hostname} isolation recorded (simulated) and written to the audit ledger.",
            "data": {"status": "isolation_requested", "simulated": True, "host": hostname, "message": msg}}


def set_alert_status(alert_id, status, note=None, analyst="unknown"):
    if status not in STATUSES:
        raise ToolError(f"status must be one of {STATUSES}")
    a = alerts_collection.find_one_and_update({"alert_id": alert_id}, {"$set": {"status": status}},
                                              projection=ALERT_FIELDS)
    if not a:
        raise ToolError(f"no alert with id {alert_id}")
    reason = f"Alert {alert_id} ({a.get('event_type')} on {a.get('host')}) marked {status}" + (f": {note}" if _given(note) else "")
    append_ledger_entry(entity_type="ALERT", entity_id=alert_id, stage="ALERT_TRIAGE",
                        action_taken=f"STATUS_{status.upper()}", reasoning_output=reason, analyst_user=analyst)
    return {"summary": reason + ". Written to the audit ledger.", "data": {"alert_id": alert_id, "status": status}}


# ── the registry ──────────────────────────────────────────────────────────

S, N = {"type": "string"}, {"type": "number"}

TOOLS = {
    "search_alerts": dict(fn=search_alerts, kind="read", render="alerts",
        description="Find alerts. Filter by free text (host, user, domain, IP, URL, brand...), severity, engine, host, status or recent hours.",
        parameters={"query": S, "severity": {"type": "string", "enum": SEVERITIES}, "engine": {"type": "string", "enum": ["verifyeye", "spectrac2"]},
                    "host": S, "status": {"type": "string", "enum": STATUSES}, "since_hours": N, "limit": N}, required=[]),
    "get_alert": dict(fn=get_alert, kind="read", render="alert",
        description="Full details of one alert by its alert_id, with the agent's screenshot if there is one.",
        parameters={"alert_id": S}, required=["alert_id"]),
    "entity_summary": dict(fn=entity_summary, kind="read", render="entity",
        description="Summarise one host, user, domain, IP, impersonated brand or MITRE technique: when it was seen, how many alerts, which hosts it touched.",
        parameters={"name": S}, required=["name"]),
    "get_host_graph": dict(fn=host_graph, kind="read", render="graph",
        description="Show the attack graph around one host: its users, IPs, domains, URLs and processes.",
        parameters={"hostname": S}, required=["hostname"]),
    "get_evidence": dict(fn=get_evidence, kind="read", render="evidence",
        description="The screenshot the VerifyEye agent took of a phishing page, by alert_id, url or domain.",
        parameters={"alert_id": S, "url": S, "domain": S}, required=[]),
    "attention_findings": dict(fn=attention_findings, kind="read", render="findings",
        description="What needs attention right now across all alerts: corroborated hosts, shared attacker infrastructure, untriaged criticals.",
        parameters={}, required=[]),
    "system_status": dict(fn=system_status, kind="read", render="status",
        description="Whether MongoDB, Neo4j and the local AI model are online.",
        parameters={}, required=[]),
    "ledger_lookup": dict(fn=ledger_lookup, kind="read", render="ledger",
        description="Decisions recorded in the tamper-evident audit ledger, for one host/alert or the most recent ones.",
        parameters={"entity": S, "limit": N}, required=[]),
    "investigate_host": dict(fn=investigate_host, kind="read", render="investigation",
        description="Run the multi-agent investigation (correlate, triage, contain) on one host and get a verdict with recommended actions.",
        parameters={"hostname": S}, required=["hostname"]),
    "isolate_host": dict(fn=isolate_host, kind="action", render="action",
        description="Isolate a compromised host from the network. Needs the analyst's approval before it runs.",
        parameters={"hostname": S, "reason": S}, required=["hostname"]),
    "set_alert_status": dict(fn=set_alert_status, kind="action", render="action",
        description="Mark an alert new, triaged or resolved. Needs the analyst's approval before it runs.",
        parameters={"alert_id": S, "status": {"type": "string", "enum": STATUSES}, "note": S}, required=["alert_id", "status"]),
}


def tool_specs(kinds=("read", "action")):
    """The tools in the shape Ollama / MCP clients expect."""
    return [{"name": name, "description": t["description"], "kind": t["kind"], "render": t["render"],
             "inputSchema": {"type": "object", "properties": t["parameters"], "required": t["required"]}}
            for name, t in TOOLS.items() if t["kind"] in kinds]


def run_tool(name, args=None, analyst="unknown", approved=False):
    """Run a tool. Action tools refuse unless approved. Never raises for the
    model's mistakes: it gets an error it can read and recover from."""
    t = TOOLS.get(name)
    if not t:
        return {"ok": False, "summary": f"There is no tool called {name}.", "render": "text", "data": None}
    params = set(t["parameters"])
    args = {k: v for k, v in (args or {}).items() if k in params and _given(v)}
    missing = [r for r in t["required"] if r not in args]
    if missing:
        return {"ok": False, "summary": f"{name} needs {', '.join(missing)}.", "render": "text", "data": None}
    if t["kind"] == "action":
        if not approved:
            return {"ok": False, "needs_approval": True, "render": "approval", "data": {"tool": name, "args": args},
                    "summary": f"{name} needs the analyst's approval; it has been proposed to them."}
        args["analyst"] = analyst
    try:
        out = t["fn"](**args)
        return {"ok": True, "render": t["render"], **out}
    except ToolError as e:
        return {"ok": False, "summary": str(e), "render": "text", "data": None}
    except Exception as e:   # neo4j down etc.: tell the model, don't crash the chat
        reason = "the graph database is offline" if type(e).__name__ == "ServiceUnavailable" else type(e).__name__
        return {"ok": False, "summary": f"{name} failed: {reason}.", "render": "text", "data": None}
