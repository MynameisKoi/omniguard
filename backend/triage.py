"""Triage an alert: by hand, or proposed by the AI and approved by an analyst.

Both end in apply_triage(): the alert gets a verdict, a severity, notes and a
status, the chosen response actions are recorded, and every step goes into the
tamper-evident ledger. The AI never applies anything itself: propose_triage()
only stores a proposal on the alert; an analyst approves it (as is, or edited),
or rejects it.

The AI's verdict comes from rules over the data (other engines on the same
host, shared attacker infrastructure, the agent's screenshot verdict,
confidence), so it's always explainable. The local model only writes a short
explanation of that verdict, cleaned like Ask AI's replies.

Response actions are SIMULATED for now (recorded in the ledger only), the same
as isolation from Ask AI; real containment is backlog #19.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone

import httpx

from config import OLLAMA_MODEL, OLLAMA_URL
from db import database
from events import manager
from evidence import list_evidence
from ledger import append_ledger_entry, get_ledger_for_entity

alerts_collection = database["alerts"]

VERDICTS = {
    "true_positive": "True positive",
    "false_positive": "False positive",
    "benign": "Benign / expected",
    "escalate": "Needs escalation",
}
SEVERITIES = ["critical", "high", "medium", "low"]
STATUSES = ["triaged", "resolved"]
ACTION_WORDS = {"isolate_host": "Isolate", "reset_password": "Reset the password for", "block_domain": "Block"}
LOCAL = re.compile(r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")


class TriageError(Exception):
    """Bad input the analyst should see (unknown verdict, action that doesn't fit)."""


def _changed(alert_id):
    """The alert as it is now, sent to every open dashboard: triage can start from
    the alert page, the Alerts list or an Ask AI chat, and all of them should see it."""
    a = _alert(alert_id)
    try:
        from models import Alert
        manager.broadcast_from_thread({"type": "alert_updated", "alert": Alert(**a).model_dump(mode="json")})
    except Exception as e:      # a live update is nice to have, never worth failing the triage over
        print(f"alert_updated broadcast failed for {alert_id}: {e}")
    return a


def _alert(alert_id):
    a = alerts_collection.find_one({"alert_id": alert_id}, {"_id": 0, "simhash": 0})
    if not a:
        raise LookupError(f"Alert '{alert_id}' not found")
    return a


def available_actions(a):
    """The response actions that make sense for this alert, with their targets."""
    out = []
    if a.get("host"):
        out.append({"id": "isolate_host", "target": a["host"], "label": f"Isolate {a['host']}"})
    if a.get("user"):
        out.append({"id": "reset_password", "target": a["user"], "label": f"Reset the password for {a['user']}"})
    target = a.get("domain") or (a.get("dst_ip") if a.get("source") == "spectrac2" else None)
    if target and not LOCAL.match(str(target)):
        out.append({"id": "block_domain", "target": target, "label": f"Block {target}"})
    return out


def _isolated(host):
    return any("ISOLAT" in str(r.get("action_taken", "")).upper() for r in get_ledger_for_entity(host)[:10])


# ── apply: the one way a triage is saved ────────────────────────────────────

def apply_triage(alert_id, verdict, severity, notes, actions, status, analyst, proposal=None):
    """Save a triage decision and record it (and each response action) in the ledger.
    proposal: the AI proposal this came from, if any (who proposed it is recorded).
    severity None keeps the alert's own (bulk triage)."""
    a = _alert(alert_id)
    severity = severity or a.get("severity")
    if verdict not in VERDICTS:
        raise TriageError(f"verdict must be one of {', '.join(VERDICTS)}")
    if severity not in SEVERITIES:
        raise TriageError(f"severity must be one of {', '.join(SEVERITIES)}")
    if status not in STATUSES:
        raise TriageError("status must be triaged or resolved")
    allowed = {x["id"]: x for x in available_actions(a)}
    unknown = [x for x in actions if x not in allowed]
    if unknown:
        raise TriageError(f"these actions don't fit this alert: {', '.join(unknown)}")

    now = datetime.now(timezone.utc)
    record = {
        "verdict": verdict, "notes": (notes or "").strip()[:2000], "status": status,
        "severity": severity, "previous_severity": a.get("severity"), "previous_status": a.get("status"),
        "actions": [allowed[x] for x in actions], "by": analyst, "at": now,
        "via": "ai" if proposal else "manual",
        "proposed_verdict": (proposal or {}).get("verdict"),
        "ai_summary": (proposal or {}).get("summary") or None,
    }

    who = f"AI proposed, approved by {analyst}" if proposal else f"by {analyst}"
    changed = f"; severity {a.get('severity')} -> {severity}" if severity != a.get("severity") else ""
    edited = (f" (AI suggested {VERDICTS.get(proposal['verdict'], proposal['verdict'])})"
              if proposal and proposal.get("verdict") != verdict else "")
    append_ledger_entry(
        entity_type="ALERT", entity_id=alert_id, stage="ALERT_TRIAGE",
        action_taken=f"TRIAGE_{verdict.upper()}",
        reasoning_output=(f"{a.get('event_type')} on {a.get('host')}: {VERDICTS[verdict]}{edited}{changed}; "
                          f"marked {status} ({who})." + (f" Notes: {record['notes']}" if record["notes"] else "")),
        analyst_user=analyst,
        input_context={"via": record["via"], "actions": actions},
    )
    for x in actions:
        act = allowed[x]
        if _already(x, act["target"]):
            act["already"] = True        # e.g. the same host from several alerts: recorded once
            continue
        why = f"Response to alert {alert_id} ({a.get('event_type')}), {VERDICTS[verdict].lower()}"
        if x == "isolate_host":
            append_ledger_entry(entity_type="HOST", entity_id=act["target"], stage="EDR_CONTAINMENT",
                                action_taken="NETWORK_ISOLATION_SIMULATED", analyst_user=analyst,
                                reasoning_output=f"Containment requested for '{act['target']}': {why}. "
                                                 "Simulated for now — no real network action is taken yet.")
        elif x == "reset_password":
            append_ledger_entry(entity_type="USER", entity_id=act["target"], stage="IDENTITY_RESPONSE",
                                action_taken="PASSWORD_RESET_SIMULATED", analyst_user=analyst,
                                reasoning_output=f"Password reset and session revocation requested for "
                                                 f"'{act['target']}': {why}. Simulated for now.")
        elif x == "block_domain":
            append_ledger_entry(entity_type="DOMAIN", entity_id=act["target"], stage="NETWORK_BLOCK",
                                action_taken="DOMAIN_BLOCK_SIMULATED", analyst_user=analyst,
                                reasoning_output=f"Block requested for '{act['target']}' at the firewall / DNS: "
                                                 f"{why}. Simulated for now.")
    alerts_collection.update_one({"alert_id": alert_id},
                                 {"$set": {"status": status, "severity": severity, "triage": record},
                                  "$unset": {"triage_proposal": ""}})
    return _changed(alert_id)


ACTION_CODE = {"isolate_host": "NETWORK_ISOLATION", "reset_password": "PASSWORD_RESET", "block_domain": "DOMAIN_BLOCK"}


def _already(action, target):
    """This response action is already recorded for this host / user / domain."""
    code = ACTION_CODE[action]
    return any(code in str(r.get("action_taken", "")).upper() for r in get_ledger_for_entity(target)[:20])


# ── the AI's proposal ───────────────────────────────────────────────────────

def _decide(a):
    """Verdict, severity, status, actions and the reasons, from the data."""
    host, user, sev = a.get("host"), a.get("user"), a.get("severity") or "medium"
    target = a.get("domain") or a.get("dst_ip")
    on_host = list(alerts_collection.find({"host": host}, {"_id": 0, "source": 1, "severity": 1, "domain": 1,
                                                           "dst_ip": 1})) if host else []
    engines = {x.get("source") for x in on_host}
    both = {"verifyeye", "spectrac2"} <= engines
    shared = len(alerts_collection.distinct("host", {"$or": [{"domain": target}, {"dst_ip": target}]})) \
        if target and not LOCAL.match(str(target)) else 0
    shots = list_evidence(url=a["target_url"], limit=1) if a.get("target_url") else []
    shot = shots[0] if shots else None
    conf = a.get("confidence")
    isolated = bool(host) and _isolated(host)
    reasons, actions = [], []
    acts = {x["id"] for x in available_actions(a)}

    what = str(a.get("event_type") or "suspicious").replace("_", " ").replace(" detected", "")

    def up(s):   # raise severity, never lower it, for a confirmed attack
        return s if SEVERITIES.index(s) < SEVERITIES.index(sev) else sev

    test = (str(a.get("domain") or "").lower() == "localhost" or re.search(r"\b(test|demo)\b", str(host or "").lower().replace("-", " ")))
    if test:
        verdict, severity, status = "benign", "low", "resolved"
        reasons.append("This looks like test traffic: " + ("the page is on localhost" if str(a.get("domain")).lower() == "localhost"
                                                           else f"{host} is a test / demo machine") + ".")
    elif both:
        verdict, severity, status = "true_positive", "critical", "triaged"
        other = {"verifyeye": "C2 alerts too", "spectrac2": "phishing alerts too"}.get(a.get("source"), "both phishing and C2 alerts")
        reasons.append(f"{host} has {other}: two separate engines agree, which usually means a real compromise.")
        actions += ["isolate_host", "reset_password", "block_domain"]
    elif a.get("source") == "verifyeye":
        phish = shot and shot.get("phishing")
        if shot:
            reasons.append(f"The VerifyEye agent visited the page and judged it "
                           + (f"phishing ({shot.get('confidence', 0):.0%} confident)" if phish
                              else "blocked by a bot check" if shot.get("blocked") else "genuine") + ".")
        if phish or (conf or 0) >= 0.8:
            verdict, severity, status = "true_positive", up("high"), "triaged"
            if conf is not None:
                reasons.append(f"Detection confidence is {conf:.0%}.")
            reasons.append(f"Only phishing so far on {host}, no C2: the risk is a stolen password, not malware.")
            actions += ["reset_password", "block_domain"]
        elif shot and not phish and not shot.get("blocked"):
            verdict, severity, status = "false_positive", "low", "resolved"
            reasons.append("The page the agent saw looks genuine.")
        else:
            verdict, severity, status = "escalate", sev, "triaged"
            reasons.append("Confidence is low and there's no screenshot verdict: a person should look at the page.")
    elif a.get("source") == "spectrac2":
        if shared > 1 or (conf or 0) >= 0.8:
            verdict, severity, status = "true_positive", up("high"), "triaged"
            if shared > 1:
                reasons.append(f"{target} is contacted by {shared} hosts: shared attacker infrastructure.")
            if conf is not None:
                reasons.append(f"Beacon detection confidence is {conf:.0%}.")
            actions += ["isolate_host", "block_domain"]
        else:
            verdict, severity, status = "escalate", sev, "triaged"
            reasons.append(f"One {what} detection" + (f" at {conf:.0%} confidence" if conf is not None else "")
                           + ", with no other engine or host backing it up: check the traffic before acting.")
    elif shared > 1:
        verdict, severity, status = "true_positive", up("high"), "triaged"
        reasons.append(f"It involves {target}, which {shared} hosts contact: shared attacker infrastructure.")
        actions += ["block_domain", "reset_password"]
    else:
        verdict, severity, status = "escalate", sev, "triaged"
        reasons.append(f"A {what} alert raised by hand, with nothing else backing it up: a person should confirm it.")

    if "isolate_host" in actions and isolated:
        actions.remove("isolate_host")
        reasons.append(f"{host} already has an isolation recorded (simulated), so it isn't proposed again.")
    actions = [x for x in dict.fromkeys(actions) if x in acts]
    others = Counter(x.get("severity") for x in on_host)
    if len(on_host) > 1:
        reasons.append(f"{host} has {len(on_host)} alerts in total ({others.get('critical', 0)} critical).")
    return verdict, severity, status, actions, reasons


EXPLAIN = ("You are a SOC analyst's assistant. An alert was triaged from the data below.\n\n{facts}\n\n"
           "In TWO or THREE short sentences, explain why the verdict '{verdict}' fits: what likely happened and the "
           "risk.{terms} Only talk about what the data above says. No numbers, no lists, no instructions, don't add "
           "names, attacks or facts that aren't above.")
TERMS = {"phish": " Phishing pages are fake login pages a user OPENED (the host was the victim).",
         "c2": " C2 is malware on the host calling an attacker's server."}
# topics the model may only bring up when the data mentions them
TOPICS = {"phish": re.compile(r"phish|fake login|login page", re.I),
          "c2": re.compile(r"\bc2\b|malware|command.and.control|backdoor|beacon", re.I)}


def _explain(a, verdict, reasons):
    """A short explanation of the verdict by the local model, cleaned like Ask AI's
    replies (no invented names, no claims of actions). Empty if the model is off."""
    from agent import _Cleaner   # here, not at import: agent imports tools, tools may import us later
    facts = (f"Alert: {a.get('event_type')} on host {a.get('host')}"
             + (f", user {a.get('user')}" if a.get("user") else "")
             + (f", domain {a.get('domain')}" if a.get("domain") else "") + ".\n" + "\n".join(reasons))
    low = facts.lower() + " " + str(a.get("event_type", "")).lower()
    present = {k for k in TOPICS if k in low or (k == "c2" and "spectrac2" in str(a.get("source")))}
    terms = "".join(TERMS[k] for k in sorted(present))
    try:
        r = httpx.post(f"{OLLAMA_URL}/api/chat", timeout=60.0, json={
            "model": OLLAMA_MODEL, "stream": False, "keep_alive": "30m",
            "options": {"temperature": 0.2, "num_predict": 160},
            "messages": [{"role": "user", "content": EXPLAIN.format(facts=facts, verdict=VERDICTS[verdict], terms=terms)}]})
        r.raise_for_status()
        text = r.json().get("message", {}).get("content", "")
    except (httpx.HTTPError, ValueError):
        return ""
    c = _Cleaner(facts=facts + ("\nwhich usually means a real compromise" if verdict == "true_positive" else ""),
                 reference=facts, acting=True, limit=3)
    out = (c.feed(text + " ") + c.finish()).strip()
    keep = [x for x in re.split(r"(?<=[.!?])\s+", out)
            if not any(rx.search(x) for k, rx in TOPICS.items() if k not in present)]
    return " ".join(keep).strip()


def propose_triage(alert_id, requested_by, explain=True):
    """The AI's triage of an alert, stored on it as a pending proposal. Nothing
    changes on the alert (or anywhere) until an analyst approves it.
    explain=False skips the model's explanation (the reasons stay): for many
    alerts at once, where a few seconds each adds up."""
    a = _alert(alert_id)
    verdict, severity, status, actions, reasons = _decide(a)
    summary = _explain(a, verdict, reasons) if explain else ""
    proposal = {
        "verdict": verdict, "severity": severity, "status": status, "actions": actions,
        "reasons": reasons, "summary": summary,
        "notes": "\n".join(f"- {r}" for r in reasons),     # the explanation is shown (and kept) separately
        "proposed_at": datetime.now(timezone.utc), "requested_by": requested_by, "model": OLLAMA_MODEL,
    }
    alerts_collection.update_one({"alert_id": alert_id}, {"$set": {"triage_proposal": proposal}})
    return _changed(alert_id)


def approve_proposal(alert_id, analyst, verdict=None, severity=None, notes=None, actions=None, status=None):
    """Apply the AI's proposal, with any edits the analyst made."""
    a = _alert(alert_id)
    p = a.get("triage_proposal")
    if not p:
        raise TriageError("there's no AI proposal on this alert (it was already approved or rejected)")
    return apply_triage(alert_id, verdict or p["verdict"], severity or p["severity"],
                        p["notes"] if notes is None else notes, p["actions"] if actions is None else actions,
                        status or p["status"], analyst, proposal=p)


def reject_proposal(alert_id, analyst, reason=None):
    a = _alert(alert_id)
    p = a.get("triage_proposal")
    if not p:
        raise TriageError("there's no AI proposal on this alert")
    alerts_collection.update_one({"alert_id": alert_id}, {"$unset": {"triage_proposal": ""}})
    append_ledger_entry(entity_type="ALERT", entity_id=alert_id, stage="ALERT_TRIAGE",
                        action_taken="AI_TRIAGE_REJECTED", analyst_user=analyst,
                        reasoning_output=f"AI proposed {VERDICTS.get(p['verdict'], p['verdict'])}; rejected by {analyst}"
                                         + (f": {reason}" if reason else "."))
    return _changed(alert_id)


# ── many at once ────────────────────────────────────────────────────────────

MAX_BULK = 50


def bulk(fn, alert_ids, *args, **kwargs):
    """Run one triage step over several alerts. Returns (changed alerts, problems):
    one alert that can't be done doesn't stop the rest."""
    done, problems = [], []
    for aid in list(dict.fromkeys(alert_ids))[:MAX_BULK]:
        try:
            done.append(fn(aid, *args, **kwargs))
        except (LookupError, TriageError) as e:
            problems.append({"alert_id": aid, "error": str(e)})
    return done, problems


def triage_candidates(host=None, limit=8):
    """Untriaged alerts with no proposal yet, worst and newest first."""
    q = {"status": "new", "triage_proposal": {"$exists": False}}
    if host:
        q["host"] = {"$regex": f"^{re.escape(host)}$", "$options": "i"}
    rows = list(alerts_collection.find(q, {"_id": 0, "alert_id": 1, "severity": 1, "timestamp": 1}))
    rows.sort(key=lambda a: (SEVERITIES.index(a.get("severity")) if a.get("severity") in SEVERITIES else 9,
                             -(a.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc)).timestamp()))
    return [a["alert_id"] for a in rows[:limit]]
