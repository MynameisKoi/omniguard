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
from difflib import get_close_matches
from datetime import datetime, timedelta, timezone

from db import database
from evidence import list_evidence
from graph import get_host_graph
from ledger import append_ledger_entry, get_ledger_for_entity, get_recent_ledger, verify_ledger_integrity
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
    # small models fill unused arguments with "", "null" or 0 ("the last 0 hours")
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v > 0
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


def _sev_text(counter):
    return ", ".join(f"{counter[x]} {x}" for x in SEVERITIES if counter[x])


def _list(items, n=5):
    items = [str(i) for i in items if i]
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def _ranked(rows, field, n=5):
    c = Counter(a.get(field) for a in rows if a.get(field))
    return _list([f"{v} ({k})" for v, k in c.most_common()], n)


def mentioned_entities(text, limit=5):
    """Names from the alerts that appear in a message, e.g. [("cdn-telemetry-sync.net",
    "domain")]. Tells a small model which tool fits before it guesses."""
    found, low = [], (text or "").lower()
    for field, label in ENTITY_FIELDS:
        for value in alerts_collection.distinct(field):
            v = str(value or "")
            if len(v) >= 3 and _given(v) and re.search(r"(?<![\w.-])" + re.escape(v.lower()) + r"(?![\w-])", low):
                if v not in [f[0] for f in found]:
                    found.append((v, label))
    return found[:limit]


def _entity_values():
    """Every name in the alerts (hosts, users, domains, IPs, brands...)."""
    return {str(v) for f, _ in ENTITY_FIELDS for v in alerts_collection.distinct(f) if _given(v) and len(str(v)) >= 3}


def close_entities(name, n=3, cutoff=0.8):
    """Names in the alerts spelt like this one, best first: [itself] if it
    exists, else close spellings ("mahirjan" -> ["maharjan"]), else []."""
    name = str(name or "").strip()
    if not name:
        return []
    by_low = {v.lower(): v for v in _entity_values()}
    if name.lower() in by_low:
        return [by_low[name.lower()]]
    if "." in name:
        return []     # domains / IPs: one letter off is a different (maybe lookalike) site
    return [by_low[c] for c in get_close_matches(name.lower(), [v for v in by_low if "." not in v], n=n, cutoff=cutoff)]


def closest_entity(name):
    """The name in the alerts this one means, or None. A 3B model retypes names
    and gets a letter wrong, then reports that nothing exists."""
    found = close_entities(name, n=1)
    return found[0] if found else None


# arguments that hold one name, per tool
NAME_ARGS = ("name", "hostname", "entity", "host", "domain")


def _check_names(name, args):
    """Names in a tool's arguments that aren't in the alerts but are spelt like
    ones that are ("mahirjan"). Returns (args, misses): case is fixed silently
    (laptop-10 -> LAPTOP-10); a misspelling is NOT replaced, it goes back to
    the analyst as "did you mean ...?" with the close names."""
    misses = []
    def check(v):
        typed = str(v).strip()
        found = close_entities(typed, n=4, cutoff=0.7)
        if not found:
            return v
        if found[0].lower() == typed.lower():
            return found[0]
        if closest_entity(typed):             # one close enough to be a typo
            misses.append({"typed": typed, "matches": found})
        return v
    for k in NAME_ARGS:
        if _given(args.get(k)):
            args[k] = check(args[k])
    if name == "compare_entities" and _given(args.get("names")):
        parts = re.split(r"\s*(?:,|\band\b|\bvs\.?\b|\bversus\b)\s*", str(args["names"]))
        args["names"] = ", ".join(check(p) for p in parts if p.strip())
    if name == "search_alerts" and _given(args.get("query")) and " " not in str(args["query"]).strip():
        # one word that matches nothing as typed but is a letter off a real name
        if not alerts_collection.count_documents(_alert_query(query=args["query"])):
            args["query"] = check(args["query"])
    return args, misses


# ── read tools ────────────────────────────────────────────────────────────

def _alert_query(query=None, severity=None, engine=None, host=None, status=None, since_hours=None):
    """The Mongo filter behind search_alerts and show_dashboard, so a list and
    a dashboard of "the same thing" always agree."""
    q = {}
    if _given(severity):
        if severity not in SEVERITIES:
            raise ToolError(f"severity must be one of {SEVERITIES}")
        q["severity"] = severity
    if _given(engine) and str(engine).lower() in ("verifyeye", "spectrac2"):   # ignore "all", "any"...
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
    return q


def search_alerts(query=None, severity=None, engine=None, host=None, status=None, since_hours=None, limit=20):
    q = _alert_query(query, severity, engine, host, status, since_hours)
    limit = max(1, min(int(limit or 20), 100))
    total = alerts_collection.count_documents(q)
    relaxed = ""
    if not total and _given(query) and len(q) > 1:
        # a small model adds filters that don't fit ("engine: verifyeye" for a C2
        # domain): the name alone is what the analyst asked about
        q, relaxed = _alert_query(query), f" for {query} (with the other filters there were none)"
        total = alerts_collection.count_documents(q)
    if not total:
        label = " ".join(x for x in (
            "untriaged" if status == "new" else status if _given(status) else "", severity if _given(severity) else "",
            ENGINE_WORD.get(engine, "") if _given(engine) else "", "alerts",
            f"on {host}" if _given(host) else "", f"in the last {_hours(since_hours)}" if _given(since_hours) else "") if x)
        if _given(since_hours):
            wider = alerts_collection.find_one(_alert_query(query, severity, engine, host, status), ALERT_FIELDS,
                                               sort=[("timestamp", -1)])
            if wider:
                raise ToolError(f"No {label}. The newest one without the time limit is from "
                                f"{_when(wider.get('timestamp'))} on {wider.get('host')}. Say plainly that nothing was found.")
        raise ToolError(f"No alerts match{' ' + repr(str(query)) if _given(query) else f' ({label})'}. "
                        "Say plainly that nothing was found; don't guess what it is or whether it's safe.")
    rows = list(alerts_collection.find(q, ALERT_FIELDS).sort("timestamp", -1).limit(limit))
    sev = Counter(a.get("severity") for a in rows)
    summary = f"{total} alert(s) match{relaxed}" + (f", showing {len(rows)}" if total > len(rows) else "")
    if rows:
        summary += " (" + ", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev[s]) + "):\n"
        summary += "\n".join(f"- {_alert_line(a)}" for a in rows[:8])
    every = list(alerts_collection.find(q, {"_id": 0, "severity": 1, "host": 1})) if total > len(rows) else rows
    facts = (f"**{total} alert{'s' if total != 1 else ''}** match{relaxed.split(' (')[0]} "
             f"({_sev_text(Counter(a.get('severity') for a in every))}). Hosts: {_ranked(every, 'host')}."
             + (" The other filters matched nothing, so only the name was used." if relaxed else ""))
    every_next = list(alerts_collection.find(q, {"_id": 0, "source": 1, "user": 1, "host": 1, "domain": 1, "status": 1}).limit(500))
    return {"summary": summary, "facts": facts, "next": _set_next(every_next), "data": {"alerts": rows, "total": total}}


def alert_context(alert_id):
    """One line about an alert, for a chat that's about it: what, where, and where
    it is in triage right now. None if there's no such alert."""
    a = alerts_collection.find_one({"alert_id": alert_id}, ALERT_FIELDS) if alert_id else None
    if not a:
        return None
    t, p = a.get("triage") or {}, a.get("triage_proposal")
    where = (f"triaged as {str(t.get('verdict', '')).replace('_', ' ')} by {t.get('by')}" if t
             else f"an AI triage proposal ({str(p.get('verdict', '')).replace('_', ' ')}) is waiting for approval" if p
             else "not triaged yet")
    return (f"alert {a['alert_id']}: {a.get('severity')} {str(a.get('event_type', 'alert')).replace('_', ' ')} on host "
            f"{a.get('host')}" + (f", user {a['user']}" if a.get("user") else "")
            + (f", domain {a['domain']}" if a.get("domain") else "") + f", {_when(a.get('timestamp'))}; {where}.")


def get_alert(alert_id):
    a = alerts_collection.find_one({"alert_id": alert_id}, ALERT_FIELDS)
    if not a:
        raise ToolError(f"there is no alert with id {alert_id} (don't make ids up). "
                        "Use search_alerts with a host, domain or keyword instead.")
    shots = list_evidence(url=a["target_url"], limit=1) if a.get("target_url") else []
    extra = f"\nAgent screenshot: {'phishing' if shots[0]['phishing'] else 'cleared'}" if shots else ""
    facts = (f"**{a.get('severity', '?').capitalize()} {a.get('event_type', 'alert')}** on {a.get('host')}"
             + (f" (user {a['user']})" if a.get("user") else "") + (f", {a['domain']}" if a.get("domain") else "")
             + f", {_when(a.get('timestamp'))}, status {a.get('status', 'new')}."
             + (f" Triaged as **{str(a['triage'].get('verdict', '')).replace('_', ' ')}** by {a['triage'].get('by')}."
                if a.get("triage") else " An AI triage proposal is waiting for your approval on the alert page."
                if a.get("triage_proposal") else "")
             + (f" The agent's screenshot says **{'phishing' if shots[0]['phishing'] else 'cleared'}**." if shots else ""))
    return {"summary": _alert_line(a) + (f"\n{a['description']}" if a.get("description") else "") + extra,
            "facts": facts, "data": {"alert": a, "evidence": shots[:1]}}


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
                        "If it's a general security term, answer from your own knowledge; otherwise say plainly "
                        "it isn't in the alerts and don't guess what it is or whether it's safe.")
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
    article = "an" if kind[0].lower() in "aeio" else "a"   # an IP / impersonated brand, a user / host
    summary = (f"{name} is {article} {kind} in {len(rows)} alert(s) "
               f"({', '.join(f'{sev[s]} {s}' for s in SEVERITIES if sev[s])}). "
               f"First seen {_when(data['first_seen'])}, last seen {_when(data['last_seen'])}. ")

    if field == "host":
        summary += _host_overview(name, rows, data)
    else:
        summary += (f"Hosts: {', '.join(f'{h} ({n})' for h, n in hosts.most_common(8)) or 'none'}. "
                    f"Domains: {', '.join(data['domains'][:5]) or 'none'}. Engines: {', '.join(data['engines'])}. ")
        summary += _cross_engine(list(hosts), data)
    return {"summary": summary, "facts": _entity_facts(data), "next": _next_steps(data), "data": data}


def _entity_facts(d):
    """One entity in plain words, straight from its data."""
    sev = Counter({k: v for k, v in (d.get("severity") or {}).items() if v})
    out = (f"**{d['name']}** is {'an' if d['kind'][0].lower() in 'aeio' else 'a'} {d['kind']} in "
           f"**{d['alert_count']} alert{'s' if d['alert_count'] != 1 else ''}** ({_sev_text(sev)}), "
           f"last seen {_when(d.get('last_seen'))}.")
    if d["kind"] == "host":
        eng = d.get("engines") or []
        if {"verifyeye", "spectrac2"} <= set(eng):
            out += " It has **both phishing and C2** alerts, which usually means a real compromise."
        if d.get("phishing_domains"):
            out += f" Phishing pages: {_list(d['phishing_domains'], 3)}."
        if d.get("c2_destinations"):
            out += f" C2 traffic to: {_list(d['c2_destinations'], 3)}."
        if d.get("users"):
            out += f" Users: {_list(d['users'], 4)}."
        out += f" {d.get('open', 0)} still untriaged."
        last = d.get("ledger_latest")
        out += (f" Last action: {last['action']} by {last['by']} ({last['when']})." if last else " No action taken yet.")
    else:
        hosts = [h["host"] for h in d.get("hosts") or []]
        out += f" Hosts: {_list(hosts, 6) or 'none'}."
        he = d.get("host_engines") or {}
        both = [h for h in hosts if {"verifyeye", "spectrac2"} <= set(he.get(h, []))]
        if both:
            out += f" **{_list(both, 4)}** had both phishing and C2 alerts."
    return out


# ── next steps: written from the data, so they're always right ──────────
# The model explains what a result means; what to DO comes from here. A 3B
# model suggests isolating hosts that only saw phishing, or blocking things
# that don't exist.

def _isolated(d):
    last = (d.get("ledger_latest") or {}).get("action") or ""
    return "isolation" in last


def _next_steps(d):
    """What to do about one host / user / domain, from its alerts."""
    steps, name, kind = [], d["name"], d["kind"]
    users = d.get("users") or []
    if kind == "host":
        eng = set(d.get("engines") or [])
        phish, c2 = d.get("phishing_domains") or [], d.get("c2_destinations") or []
        if {"verifyeye", "spectrac2"} <= eng:
            steps.append(f"Isolation of **{name}** is recorded (simulated): confirm it's really cut off from the network"
                         if _isolated(d) else f"Isolate **{name}**: say \"contain {name}\" and approve the card")
            if users:
                steps.append(f"Reset the password for {_list(users, 3)} and end their sessions")
            if c2:
                steps.append(f"Block {_list(c2, 3)} at the firewall / DNS")
        elif phish:
            steps.append(f"Check whether {_list(users, 3) or 'the user'} entered a password on {_list(phish, 2)}; if so, reset it")
            steps.append(f"Block {_list(phish, 3)}")
        elif c2:
            steps.append(f"Ask \"investigate {name}\" for a verdict on the C2 traffic to {_list(c2, 2)}")
            steps.append(f"Block {_list(c2, 3)} at the firewall / DNS")
        if d.get("open"):
            steps.append(f"Triage its {d['open']} open alert{'s' if d['open'] != 1 else ''}")
    elif kind == "user":
        he = d.get("host_engines") or {}
        hosts = [h["host"] for h in d.get("hosts") or []]
        both = [h for h in hosts if {"verifyeye", "spectrac2"} <= set(he.get(h, []))]
        if both:
            steps.append(f"Start with **{both[0]}**: it had both phishing and C2 (ask \"tell me about {both[0]}\")")
        steps.append(f"Reset {name}'s password and end their sessions")
        if d.get("domains"):
            steps.append(f"Check what {name} did on {_list(d['domains'], 2)}")
    elif kind in ("domain", "IP address"):
        steps.append(f"Block {name} at the firewall / DNS")
        hosts = [h["host"] for h in d.get("hosts") or []]
        if hosts:
            steps.append(f"Check the hosts that reached it: {_list(hosts, 4)}")
    elif kind == "impersonated brand":
        steps.append(f"Warn users about fake {name} login pages")
        if d.get("domains"):
            steps.append(f"Block {_list(d['domains'], 3)}")
    return steps[:4]


def _set_next(rows):
    """What to do about a set of alerts (a search / dashboard)."""
    steps = []
    phish = [a for a in rows if a.get("source") == "verifyeye"]
    users = sorted({a["user"] for a in phish if a.get("user")})
    hosts = {}
    for a in rows:
        if a.get("host"):
            hosts.setdefault(a["host"], set()).add(a.get("source"))
    both = sorted(h for h, e in hosts.items() if {"verifyeye", "spectrac2"} <= e)
    if both:
        steps.append(f"Start with **{both[0]}**: it had both phishing and C2 (ask \"investigate {both[0]}\")")
    if users:
        steps.append(f"Check whether {_list(users, 3)} entered a password on those pages; reset any that did")
    domains = sorted({a["domain"] for a in phish if a.get("domain") and a["domain"] != "localhost"})
    if domains:
        steps.append(f"Block {_list(domains, 3)}")
    untriaged = sum(1 for a in rows if a.get("status") == "new")
    if untriaged:
        steps.append(f"Triage the {untriaged} untriaged alert{'s' if untriaged != 1 else ''}")
    return steps[:4]


# what kinds of alert each engine raises, in words the analyst uses
ENGINE_WORD = {"verifyeye": "phishing", "spectrac2": "C2"}


def _cross_engine(hosts, data):
    """For the hosts tied to a domain / IP / user / brand: which of them ALSO
    had phishing or C2 alerts anywhere. Answers "which of those hosts also
    had phishing?" without the model having to plan a second lookup."""
    if not hosts:
        return ""
    engines = {}
    for a in alerts_collection.find({"host": {"$in": hosts}}, {"host": 1, "source": 1}):
        engines.setdefault(a["host"], set()).add(a.get("source"))
    data["host_engines"] = {h: sorted(engines.get(h, ())) for h in hosts}
    parts = []
    for engine, word in ENGINE_WORD.items():
        hit = sorted(h for h in hosts if engine in engines.get(h, ()))
        parts.append(f"{', '.join(hit)} also had {word} alerts" if hit else f"none of them had {word} alerts")
    both = sorted(h for h in hosts if {"verifyeye", "spectrac2"} <= engines.get(h, set()))
    out = "Of these hosts: " + "; ".join(parts) + "."
    if both:
        out += f" {', '.join(both)} had BOTH phishing and C2 — likely compromised."
    return out


def _host_overview(host, rows, data):
    """Everything about one host in one call: what each engine saw, where it
    went, who used it, what's been done about it, and a short timeline."""
    by_engine = Counter(a.get("source") for a in rows)
    phishing = sorted({a["domain"] for a in rows if a.get("source") == "verifyeye" and a.get("domain")})
    c2 = sorted({a.get("domain") or a.get("dst_ip") for a in rows
                 if a.get("source") == "spectrac2" and (a.get("domain") or a.get("dst_ip"))})
    open_count = sum(1 for a in rows if a.get("status") == "new")
    ledger = get_ledger_for_entity(host)
    shots = sum(len(list_evidence(url=u, limit=1)) for u in {a["target_url"] for a in rows if a.get("target_url")})
    timeline = sorted((a for a in rows if isinstance(a.get("timestamp"), datetime)), key=lambda a: a["timestamp"])
    if ledger:
        data["ledger_latest"] = {"action": _action_words(ledger[0]), "by": ledger[0].get("analyst_user"),
                                 "when": _ledger_when(ledger[0].get("timestamp"))}
    data.update({"phishing_domains": phishing, "c2_destinations": c2, "open": open_count,
                 "ledger_actions": len(ledger), "screenshots": shots,
                 "timeline": [{"time": a["timestamp"], "event": a.get("event_type"), "severity": a.get("severity"),
                               "detail": a.get("domain") or a.get("dst_ip") or ""} for a in timeline[-8:]]})
    out = ("Engines: " + ", ".join(f"{n} {ENGINE_WORD.get(e, e)}" for e, n in by_engine.most_common()) + ". ")
    if phishing:
        out += f"Phishing pages: {', '.join(phishing[:4])}. "
    if c2:
        out += f"C2 beaconing to: {', '.join(c2[:4])}. "
    if {"verifyeye", "spectrac2"} <= set(by_engine):
        out += "It had BOTH phishing and C2 — likely compromised. "
    if data["users"]:
        out += f"Users: {', '.join(data['users'][:4])}. "
    out += f"{open_count} alert(s) still untriaged. "
    out += (f"{len(ledger)} action(s) in the ledger, latest: {ledger[0].get('action_taken')} by {ledger[0].get('analyst_user')}. "
            if ledger else "No action taken yet. ")
    if shots:
        out += f"{shots} agent screenshot(s). "
    if timeline:
        out += "Timeline: " + "; ".join(f"{_when(a['timestamp'])} {a.get('event_type')}"
                                        + (f" ({a.get('domain') or a.get('dst_ip')})" if a.get('domain') or a.get('dst_ip') else "")
                                        for a in timeline[-5:]) + "."
    return out


def _ledger_when(ts):
    # the ledger stores ISO strings (they're part of each entry's hash)
    try:
        return _when(datetime.fromisoformat(str(ts).replace("Z", "+00:00")))
    except ValueError:
        return str(ts or "")


def _action_words(r):
    a = r.get("action_taken") or ""
    if a.startswith("NETWORK_ISOLATION"):
        return "isolation" + (" (simulated)" if "SIMULATED" in a else "")
    return a.replace("_", " ").lower()


def host_graph(hostname):
    graph = get_host_graph(hostname)   # neo4j down -> ServiceUnavailable, handled in run_tool
    if not graph["nodes"]:
        raise ToolError(f"no host called {hostname} in the graph")
    kinds = Counter(n["type"] for n in graph["nodes"])
    summary = (f"The graph around {hostname} has {len(graph['nodes'])} entities and {len(graph['edges'])} links: "
               + ", ".join(f"{n} {t}" for t, n in kinds.most_common()) + ". It is drawn for the analyst.")
    return {"summary": summary, "facts": f"The graph around **{hostname}**: {len(graph['nodes'])} entities "
            f"({', '.join(f'{n} {t.lower()}' for t, n in kinds.most_common(5))}).", "data": {"host": hostname, **graph}}


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
        raise ToolError("The VerifyEye agent has no screenshot of that page yet. Say so plainly; don't describe any page.")
    e = shots[0]
    verdict = "phishing" if e["phishing"] else "blocked by a bot check" if e.get("blocked") else "cleared"
    summary = (f"{len(shots)} screenshot(s). Latest: {e['url']} — {verdict}"
               + (f", confidence {e['confidence']:.0%}" if e["phishing"] else "")
               + (f", looks like {e['brand']}" if e.get("brand") else "")
               + (f", password goes to {', '.join(e['form_actions'][:2])}" if e.get("off_domain") else "")
               + ". Shown to the analyst. You can't see the image: don't describe what the page looks like.")
    return {"summary": summary, "data": {"evidence": shots}}


def attention_findings():
    alerts = list(alerts_collection.find({}, ALERT_FIELDS))
    findings = []
    local = re.compile(r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")

    engines = {}
    for a in alerts:
        if a.get("host"):
            engines.setdefault(a["host"], set()).add(a.get("source"))
    crit = Counter(a.get("host") for a in alerts if a.get("severity") == "critical")
    total = Counter(a.get("host") for a in alerts)
    # worst first: most critical alerts, then most alerts
    both = sorted((h for h, e in engines.items() if {"verifyeye", "spectrac2"} <= e), key=lambda h: (-crit[h], -total[h], h))
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
    bad = [f for f in findings if f["tone"] == "bad"]
    facts = (f"**{len(bad)} thing{'s' if len(bad) != 1 else ''} need{'s' if len(bad) == 1 else ''} attention.** Most urgent: {bad[0]['text']}"
             if bad else findings[0]["text"])
    nxt = []
    if both:
        nxt.append(f"Start with **{both[0]}**, the worst of them: ask \"investigate {both[0]}\"")
    shared = [f["entities"][0] for f in findings if "shared attacker infrastructure" in f["text"]]
    if shared:
        nxt.append(f"Block the shared infrastructure: {_list(shared, 3)}")
    if open_crit:
        nxt.append("Triage the untriaged critical alerts")
    return {"summary": "\n".join(f"- {f['text']}" for f in findings), "facts": facts, "next": nxt,
            "data": {"findings": findings}}


def system_status():
    s = {"mongo": check_mongo(), "neo4j": check_neo4j(), "ollama": check_ollama()}
    names = {"mongo": "MongoDB", "neo4j": "Neo4j", "ollama": "the local AI model"}
    down = [names[k] for k, v in s.items() if not v]
    reply = ("Everything is online: MongoDB, Neo4j and the local AI model." if not down
             else f"**{_list(down)} {'is' if len(down) == 1 else 'are'} offline.** The rest is running.")
    return {"summary": ", ".join(f"{k} {'online' if v else 'OFFLINE'}" for k, v in s.items()), "reply": reply, "data": {"status": s}}


def ledger_lookup(entity=None, limit=10):
    rows = get_ledger_for_entity(entity)[:limit] if _given(entity) else get_recent_ledger(int(limit or 10))
    rows = [{k: v for k, v in r.items() if k != "_id"} for r in rows]
    if not rows:
        return {"summary": "No ledger entries" + (f" for {entity}" if _given(entity) else "") + ".", "data": {"records": []}}
    summary = "\n".join(f"- {r.get('timestamp', '')[:16]} {r.get('stage')} {r.get('action_taken')} on "
                        f"{r.get('entity_id')} by {r.get('analyst_user')}" for r in rows[:8])
    facts = (f"**{len(rows)} ledger entr{'y' if len(rows) == 1 else 'ies'}**" + (f" for {entity}" if _given(entity) else "")
             + f". Latest: {_action_words(rows[0])} on {rows[0].get('entity_id')} by {rows[0].get('analyst_user')} "
             f"({_ledger_when(rows[0].get('timestamp'))}).")
    return {"summary": summary, "facts": facts, "data": {"records": rows}}


def investigate_host(hostname):
    alerts = list(alerts_collection.find({}, {"_id": 0}))
    if not any((a.get("host") or "").lower() == str(hostname).lower() for a in alerts):
        raise ToolError(f"no alerts for a host called {hostname}")
    result = MultiAgentInvestigationPipeline().investigate(hostname, alerts)
    t, c = result.get("triage", {}), result.get("containment", {})
    summary = (f"Verdict: {t.get('classification')} (risk {t.get('risk_score')}/100, confidence "
               f"{t.get('confidence')}). Recommended: "
               + "; ".join(f"{a.get('urgency')}: {a.get('action')}" for a in c.get("recommended_actions", [])))
    acts = c.get("recommended_actions", [])
    facts = (f"Verdict on **{hostname}**: **{str(t.get('classification', 'unknown')).replace('_', ' ').lower()}**, risk {t.get('risk_score')}/100."
             + (f" Recommended first: {acts[0].get('action', '').replace('_', ' ').lower()}." if acts else ""))
    words = lambda a: str(a.get("action", "")).replace("_", " ").lower()
    isolated = any("ISOLAT" in str(r.get("action_taken", "")).upper() for r in get_ledger_for_entity(hostname)[:5])
    nxt = [((f"Isolation of **{hostname}** is recorded (simulated): confirm it's really cut off from the network" if isolated
             else f"Isolate **{hostname}**: say \"contain {hostname}\" and approve the card") if "isolat" in words(a)
            else words(a)[:1].upper() + words(a)[1:]) for a in acts[:4] if a.get("action")]
    return {"summary": summary, "facts": facts, "next": nxt, "data": {"investigation": result}}


# ── view tools: draw a whole dashboard view inside the reply ─────────────
# Each returns what a real dashboard component draws (alert ids: the page
# already holds the live alerts, so saved chats stay small), plus a summary dense
# enough that the model can answer follow-ups ("which host is worst?") from it.

def _top(rows, field, n=5):
    c = Counter(a.get(field) for a in rows if a.get(field))
    return ", ".join(f"{v} ({k})" for v, k in c.most_common(n)) or "none"


def _view_label(query=None, severity=None, engine=None, host=None, status=None, since_hours=None):
    bits = [f"“{query}”" if _given(query) else None, host if _given(host) else None,
            severity if _given(severity) else None,
            str(engine).lower() if _given(engine) and str(engine).lower() in ENGINE_WORD else None,
            status if _given(status) else None,
            f"last {_hours(since_hours)}" if _given(since_hours) else None]
    return " · ".join(b for b in bits if b) or "all alerts"


def _hours(h):
    h = float(h)
    return f"{h / 24:g} days" if h >= 48 else f"{h:g} hours"


def show_dashboard(query=None, severity=None, engine=None, host=None, status=None, since_hours=None):
    q = _alert_query(query, severity, engine, host, status, since_hours)
    rows = list(alerts_collection.find(q, ALERT_FIELDS).sort("timestamp", -1).limit(500))
    label = _view_label(query, severity, engine, host, status, since_hours)
    if not rows:
        older = ""
        if _given(since_hours):
            wider = alerts_collection.find_one(_alert_query(query, severity, engine, host, status), ALERT_FIELDS,
                                               sort=[("timestamp", -1)])
            if wider:
                older = (f"No alerts match {label}, but there are older ones: the newest is from "
                         f"{_when(wider.get('timestamp'))}. Ask without the time limit to see them. ")
        raise ToolError(older or f"No alerts match {label}. "
                        "Try search_alerts with fewer filters, or tell the analyst.")
    sev = Counter(a.get("severity") for a in rows)
    times = [a["timestamp"] for a in rows if isinstance(a.get("timestamp"), datetime)]
    summary = (f"Dashboard of {label} drawn for the analyst: {len(rows)} alert(s) "
               f"({', '.join(f'{sev[s]} {s}' for s in SEVERITIES if sev[s])}), "
               f"{sum(1 for a in rows if a.get('status') == 'new')} untriaged. "
               f"From {_when(min(times)) if times else '?'} to {_when(max(times)) if times else '?'}. "
               f"Engines: {_top(rows, 'source')}. Hosts: {_top(rows, 'host', 8)}. "
               f"Users: {_top(rows, 'user')}. Domains: {_top(rows, 'domain')}. "
               f"Brands impersonated: {_top(rows, 'brand_target')}. Techniques: {_top(rows, 'mitre_technique')}.")
    facts = (f"**{len(rows)} alert{'s' if len(rows) != 1 else ''}** for {label} ({_sev_text(sev)}), "
             f"{sum(1 for a in rows if a.get('status') == 'new')} untriaged. Hosts: {_ranked(rows, 'host')}."
             + (f" Users: {_ranked(rows, 'user')}." if any(a.get('user') for a in rows) else "")
             + (f" Brands impersonated: {_ranked(rows, 'brand_target', 4)}." if any(a.get('brand_target') for a in rows) else ""))
    return {"summary": summary, "facts": facts, "next": _set_next(rows), "data": {"label": label, "term": str(query) if _given(query) else label,
                                          "alert_ids": [a["alert_id"] for a in rows]}}


def _alerts_about(name):
    """Every alert a name appears in, as any kind of entity (exact match),
    falling back to a text search."""
    rx = {"$regex": f"^{re.escape(name)}$", "$options": "i"}
    rows = list(alerts_collection.find({"$or": [{f: rx} for f, _ in ENTITY_FIELDS]}, ALERT_FIELDS))
    return rows or list(alerts_collection.find(_alert_query(query=name), ALERT_FIELDS).limit(200))


def show_graph(entity):
    name = str(entity or "").strip()
    if not name:
        raise ToolError("give a host, user, domain, IP or brand to centre the graph on")
    rows = _alerts_about(name)
    if not rows:
        raise ToolError(f"'{name}' isn't in any alert, so there's nothing to light up in the graph")
    distinct = lambda f: sorted({a[f] for a in rows if a.get(f)} - {name})
    ips = sorted(({a.get("src_ip") for a in rows} | {a.get("dst_ip") for a in rows}) - {None, "", name})
    summary = (f"Network graph drawn with everything linked to {name} lit up ({len(rows)} alert(s)). "
               f"Connected hosts: {', '.join(distinct('host')[:8]) or 'none'}. "
               f"Users: {', '.join(distinct('user')[:6]) or 'none'}. "
               f"Domains: {', '.join(distinct('domain')[:6]) or 'none'}. IPs: {', '.join(ips[:6]) or 'none'}. "
               f"Techniques: {', '.join(distinct('mitre_technique')[:4]) or 'none'}.")
    linked = [("Hosts", distinct("host")), ("Users", distinct("user")), ("Domains", distinct("domain")), ("IPs", ips)]
    facts = (f"Everything linked to **{name}** is lit up ({len(rows)} alert{'s' if len(rows) != 1 else ''}). "
             + "; ".join(f"{k}: {_list(v, 4)}" for k, v in linked if v) + ".")
    return {"summary": summary, "facts": facts, "data": {"entity": name, "alert_ids": [a["alert_id"] for a in rows]}}


# what a small model puts in `query` when it means the verdict
VERDICT_WORDS = {"phishing": "phishing", "phish": "phishing", "malicious": "phishing", "fake": "phishing",
                 "cleared": "cleared", "safe": "cleared", "genuine": "cleared", "legit": "cleared", "legitimate": "cleared",
                 "blocked": "blocked", "bot check": "blocked", "captcha": "blocked"}


def show_screenshots(domain=None, query=None, verdict=None):
    verdict = verdict if verdict in ("phishing", "cleared", "blocked") else None
    if _given(query) and str(query).strip().lower() in VERDICT_WORDS:
        verdict, query = verdict or VERDICT_WORDS[str(query).strip().lower()], None
    shots = list_evidence(verdict=verdict, limit=300)
    # loose match on purpose: "GitHub" should find github.com and a GitHub look-alike
    for term in (t for t in (domain, query) if _given(t)):
        tl = str(term).lower()
        shots = [e for e in shots if tl in " ".join(str(e.get(k) or "") for k in ("url", "domain", "brand")).lower()]
    shots = shots[:24]
    if not shots:
        what = " / ".join(str(t) for t in (domain, query, verdict) if _given(t)) or "anything"
        raise ToolError(f"The VerifyEye agent has no screenshots of {what}. Say so plainly; don't describe any page.")
    def line(e):
        v = "phishing" if e.get("phishing") else "blocked by a bot check" if e.get("blocked") else "cleared"
        return (f"- {e.get('domain') or e.get('url')}: {v}" + (f", looks like {e['brand']}" if e.get("brand") else "")
                + (f", {e['confidence']:.0%} confident" if e.get("phishing") and e.get("confidence") else "")
                + (", password sent off-domain" if e.get("off_domain") else "") + f", {_when(e.get('captured_at'))}")
    n_phish = sum(1 for e in shots if e.get("phishing"))
    n_block = sum(1 for e in shots if e.get("blocked"))
    n_clear = len(shots) - n_phish - n_block
    phish_domains = sorted({e.get("domain") for e in shots if e.get("phishing") and e.get("domain")})
    # the model can't see images and will invent what they show: the reply is
    # written from the verdicts instead (agent.py uses "reply" as the answer)
    reply = (f"Here {'is' if len(shots) == 1 else 'are'} {len(shots)} page{'s' if len(shots) != 1 else ''} the VerifyEye agent visited: "
             + ", ".join(x for x in (f"**{n_phish} phishing**" if n_phish else "", f"{n_clear} cleared as genuine" if n_clear else "",
                                     f"{n_block} blocked by a bot check" if n_block else "") if x) + "."
             + (f" The phishing ones are on {', '.join(phish_domains[:4])}." if phish_domains else "")
             + " Click any screenshot to see it full size with the agent's reasoning.")
    return {"reply": reply, "summary": (f"{len(shots)} screenshot(s) shown to the analyst. You can't see the images: describe only "
                        "these verdicts, never what a page looks like.\n" + "\n".join(line(e) for e in shots[:10])),
            "data": {"evidence": shots}}


def show_ledger(entity=None):
    rows = get_ledger_for_entity(entity) if _given(entity) else get_recent_ledger(25)
    rows = [{k: v for k, v in r.items() if k != "_id"} for r in rows][:25]
    valid, failing, checked = verify_ledger_integrity()
    chain = {"valid": valid, "failing": failing, "checked": checked}
    head = (f"The whole ledger chain ({checked} blocks) verifies: no entry has been altered. " if valid
            else f"WARNING: the ledger chain is BROKEN at entry {failing}: a record was altered or removed. ")
    if not rows:
        return {"summary": head + "No entries" + (f" for {entity}" if _given(entity) else "") + ".",
                "data": {"records": [], "chain": chain, "entity": entity}}
    summary = head + f"{len(rows)} entr{'y' if len(rows) == 1 else 'ies'}" + (f" for {entity}" if _given(entity) else "") + ", newest first:\n" + \
        "\n".join(f"- {str(r.get('timestamp', ''))[:16]} {r.get('action_taken')} on {r.get('entity_id')} "
                  f"by {r.get('analyst_user')}" for r in rows[:10])
    facts = (("The chain verifies: nothing has been altered. " if valid else f"**The chain is broken at entry {failing}.** ")
             + f"**{len(rows)} entr{'y' if len(rows) == 1 else 'ies'}**" + (f" for {entity}" if _given(entity) else "")
             + f"; latest: {_action_words(rows[0])} on {rows[0].get('entity_id')} by {rows[0].get('analyst_user')} "
             f"({_ledger_when(rows[0].get('timestamp'))}).")
    return {"summary": summary, "facts": facts, "data": {"records": rows, "chain": chain, "entity": entity if _given(entity) else None}}


def compare_entities(names):
    items = names if isinstance(names, list) else re.split(r"\s*(?:,|\band\b|\bvs\.?\b|\bversus\b)\s*", str(names or ""))
    items = [str(n).strip() for n in items if str(n).strip()][:4]
    if len(items) < 2:
        raise ToolError("give at least two names to compare, separated by commas")
    out, lines = [], []
    for n in items:
        try:
            r = entity_summary(n)
            out.append(r["data"])
            lines.append(f"{n}: {r['summary']}")
        except ToolError as e:
            lines.append(f"{n}: {e}")
    if not out:
        raise ToolError("none of those names are in the alerts")
    facts = "\n".join(f"- {_entity_facts(d)}" for d in out)
    return {"summary": "Shown side by side.\n" + "\n".join(lines), "facts": facts, "data": {"entities": out}}


def triage_alerts(alert_id=None, host=None, user=None, analyst="unknown"):
    """AI triage proposals from the chat. Only PROPOSES (stored on each alert, same
    as "Triage with AI" on the alert page): nothing changes until the analyst
    approves each one, in the chat or on the alert page."""
    from triage import propose_triage, triage_candidates, VERDICTS, TriageError
    if _given(alert_id):
        ids = [str(alert_id)]
    elif _given(host) or _given(user):
        who = str(host if _given(host) else user)
        ids = triage_candidates(host=str(host) if _given(host) else None, user=str(user) if _given(user) else None)
        if not ids:
            raise ToolError(f"There's nothing left to triage for {who}: every alert is already triaged or has an AI proposal waiting for your approval.")
    else:
        raise ToolError("say which alert (open it from its page), or which host's or user's alerts to triage")
    out = []
    for aid in ids:
        try:
            out.append(propose_triage(aid, analyst, explain=len(ids) == 1))
        except (LookupError, TriageError) as e:
            raise ToolError(str(e))
    verdicts = Counter(VERDICTS.get(a["triage_proposal"]["verdict"], "?") for a in out)
    one = len(out) == 1
    reply = ((f"I've proposed a triage for this alert: **{next(iter(verdicts))}**." if one else
              f"I've proposed a triage for **{len(out)} alerts**" + (f" on {host}" if _given(host) else f" for {user}" if _given(user) else "") + ": "
              + ", ".join(f"{n} {v.lower()}" for v, n in verdicts.most_common()) + ".")
             + " Nothing changes until you approve " + ("it" if one else "them") + " below"
             + ("" if one else ", one by one or all at once") + ".")
    return {"reply": reply, "summary": f"Triage proposed for {len(out)} alert(s), waiting for the analyst's approval: "
                                       + "; ".join(f"{a.get('event_type')} on {a.get('host')} -> {a['triage_proposal']['verdict']}" for a in out),
            "data": {"alert_ids": [a["alert_id"] for a in out]}}


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
        description="The default way to look things up. Find alerts by free text (any host, user, domain, IP, URL, brand), severity, engine, host, status or recent hours.",
        parameters={"query": S, "severity": {"type": "string", "enum": SEVERITIES}, "engine": {"type": "string", "enum": ["verifyeye", "spectrac2"]},
                    "host": S, "status": {"type": "string", "enum": STATUSES}, "since_hours": N, "limit": N}, required=[]),
    "get_alert": dict(fn=get_alert, kind="read", render="alert",
        description="Full details of one alert. Only use with an exact alert_id (a long id like 60197cfe-ca50-...), never with a name.",
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
    "show_dashboard": dict(fn=show_dashboard, kind="read", render="dashboard",
        description="Draw a full mini dashboard (stats, charts, affected hosts, graph, every alert) for alerts matching text, severity, engine, host, status or recent hours. Use when the analyst asks to SEE, show or visualise a set of alerts.",
        parameters={"query": S, "severity": {"type": "string", "enum": SEVERITIES}, "engine": {"type": "string", "enum": ["verifyeye", "spectrac2"]},
                    "host": S, "status": {"type": "string", "enum": STATUSES}, "since_hours": N}, required=[]),
    "show_graph": dict(fn=show_graph, kind="read", render="graph_explorer",
        description="Draw the interactive network graph with everything linked to one host, user, domain, IP or brand lit up.",
        parameters={"entity": S}, required=["entity"]),
    "show_screenshots": dict(fn=show_screenshots, kind="read", render="screenshots",
        description="Show a gallery of the pages the VerifyEye agent screenshotted, optionally for a domain, a brand/text, or a verdict (phishing, cleared, blocked).",
        parameters={"domain": S, "query": S, "verdict": {"type": "string", "enum": ["phishing", "cleared", "blocked"]}}, required=[]),
    "show_ledger": dict(fn=show_ledger, kind="read", render="ledger_view",
        description="Show the audit trail as its hash chain, for one host/alert or the most recent entries, and whether the chain verifies (nothing tampered).",
        parameters={"entity": S}, required=[]),
    "compare_entities": dict(fn=compare_entities, kind="read", render="compare",
        description="Compare two to four hosts, users, domains or IPs side by side. names is comma separated, e.g. 'BUILD-SRV-02, DEV-BOX-11'.",
        parameters={"names": S}, required=["names"]),
    "triage_alerts": dict(fn=triage_alerts, kind="read", render="triage", needs_analyst=True,
        description="Have the AI triage an alert (by alert_id), or a host's or user's untriaged alerts (by host / user). It only proposes a verdict and actions; the analyst approves each.",
        parameters={"alert_id": S, "host": S, "user": S}, required=[]),
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
    args, misses = _check_names(name, args)
    if misses:
        said = "; ".join(f"no '{m['typed']}' in the alerts (close names: {', '.join(m['matches'])})" for m in misses)
        return {"ok": False, "render": "choices", "did_you_mean": misses, "data": None,
                "summary": f"{said}. The analyst has been asked which one they meant."}
    if t["kind"] == "action":
        if not approved:
            return {"ok": False, "needs_approval": True, "render": "approval", "data": {"tool": name, "args": args},
                    "summary": f"{name} needs the analyst's approval; it has been proposed to them."}
        args["analyst"] = analyst
    elif t.get("needs_analyst"):
        args["analyst"] = analyst      # recorded as who asked for the proposal
    try:
        out = t["fn"](**args)
        args.pop("analyst", None)
        return {"ok": True, "render": t["render"], "args": args, **out}
    except ToolError as e:
        return {"ok": False, "summary": str(e), "render": "text", "data": None}
    except Exception as e:   # neo4j down etc.: tell the model, don't crash the chat
        reason = "the graph database is offline" if type(e).__name__ == "ServiceUnavailable" else type(e).__name__
        return {"ok": False, "summary": f"{name} failed: {reason}.", "render": "text", "data": None}
