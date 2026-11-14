"""Real host containment.

The analyst asks to isolate or release a host; this records the request and the
confirmation in the tamper-evident ledger and hands a command to that host's
containment agent (demo/containment_agent.py), which actually cuts the machine
off the network and restores it. Nothing happens without an analyst's request,
and the agent confirms back when the action is really applied.

State machine per host:
    released  -> isolating -> isolated -> releasing -> released
(isolating / releasing are the windows where a command is waiting for the agent;
 error means the agent reported it could not apply the action.)
"""

from datetime import datetime, timezone

from db import database
from events import manager
from ledger import append_ledger_entry

containment_collection = database["containment"]

# how long with no poll before we call an agent offline (seconds)
AGENT_STALE_SECONDS = 20
# how long a request can sit waiting for the agent before we call it stalled
STALL_SECONDS = 25


def _now():
    return datetime.now(timezone.utc)


def _key(host):
    """Host names reach us from the extension, the beacon and the agent with
    different capitalisation ('Lenovo-10' vs 'lenovo-10'). Match them all to one
    key so a request and its agent can never miss each other over a capital."""
    return (host or "").strip().lower()


def _broadcast(host, state):
    manager.broadcast_from_thread({
        "type": "containment_updated", "host": host, "state": state,
    })


def _doc(host):
    return containment_collection.find_one({"_id": _key(host)}, {"_id": 0})


def get_state(host):
    """Current containment state for one host (released if we've never touched it)."""
    d = _doc(host)
    if not d:
        return {"host": host, "state": "released", "agent_online": False}
    seen = d.get("agent_seen_at")
    online = (isinstance(seen, datetime)
              and (_now() - seen).total_seconds() <= AGENT_STALE_SECONDS)
    # a request waiting too long with no agent to apply it = stalled (agent not
    # running / unreachable), so the dashboard can say so instead of spinning
    state = d.get("state", "released")
    req = d.get("requested_at")
    stalled = (state in ("isolating", "releasing") and not online
               and isinstance(req, datetime)
               and (_now() - req).total_seconds() > STALL_SECONDS)
    return {**d, "host": host, "agent_online": bool(online), "stalled": bool(stalled)}


def reset(host, by="unknown"):
    """Clear a stuck request (the agent never answered). Returns to 'released' —
    the host was never actually isolated, since no agent applied it."""
    containment_collection.delete_one({"_id": _key(host)})
    append_ledger_entry(
        entity_type="HOST", entity_id=host, stage="EDR_CONTAINMENT",
        action_taken="NETWORK_ISOLATION_RESET",
        reasoning_output=f"Analyst {by} cleared a pending containment request for "
                         f"{host} that the agent never answered.",
        analyst_user=by,
    )
    _broadcast(host, "released")
    return {"host": host, "state": "released", "agent_online": False, "stalled": False}


def list_states():
    """Every host we have a containment record for (for the dashboard)."""
    return [get_state(d["_id"]) for d in containment_collection.find({}, {"_id": 1})]


def request_isolation(host, by="unknown"):
    """Analyst asks to cut this host off. Queues the command for its agent."""
    now = _now()
    containment_collection.update_one(
        {"_id": _key(host)},
        {"$set": {"state": "isolating", "requested_action": "isolate",
                  "requested_at": now, "requested_by": by, "message": None}},
        upsert=True,
    )
    append_ledger_entry(
        entity_type="HOST", entity_id=host, stage="EDR_CONTAINMENT",
        action_taken="NETWORK_ISOLATION_REQUESTED",
        reasoning_output=f"Analyst {by} requested network isolation of {host}. "
                         f"Waiting for the host's containment agent to apply it.",
        analyst_user=by,
    )
    _broadcast(host, "isolating")
    return {"host": host, "state": "isolating", "requested_action": "isolate",
            "requested_by": by, "requested_at": now,
            "agent_online": get_state(host)["agent_online"]}


def request_release(host, by="unknown"):
    """Analyst asks to bring this host back online. Queues the command."""
    now = _now()
    containment_collection.update_one(
        {"_id": _key(host)},
        {"$set": {"state": "releasing", "requested_action": "release",
                  "requested_at": now, "requested_by": by, "message": None}},
        upsert=True,
    )
    append_ledger_entry(
        entity_type="HOST", entity_id=host, stage="EDR_CONTAINMENT",
        action_taken="NETWORK_ISOLATION_RELEASE_REQUESTED",
        reasoning_output=f"Analyst {by} requested release of {host} from isolation. "
                         f"Waiting for the host's containment agent to restore it.",
        analyst_user=by,
    )
    _broadcast(host, "releasing")
    return {"host": host, "state": "releasing", "requested_action": "release",
            "requested_by": by, "requested_at": now,
            "agent_online": get_state(host)["agent_online"]}


def agent_poll(host):
    """Called by the host's agent. Records that it's alive and returns the one
    action it should take now (or none)."""
    containment_collection.update_one(
        {"_id": _key(host)}, {"$set": {"agent_seen_at": _now()}}, upsert=True,
    )
    d = _doc(host) or {}
    state = d.get("state", "released")
    if state == "isolating":
        return {"action": "isolate"}
    if state == "releasing":
        return {"action": "release"}
    return {"action": None}


def agent_ack(host, action, ok=True, message=None):
    """Called by the agent once it has really applied (or failed to apply) the
    action. This is the confirmation that the machine is actually cut off / back."""
    now = _now()
    if action == "isolate":
        state = "isolated" if ok else "error"
        code = "NETWORK_ISOLATION_APPLIED" if ok else "NETWORK_ISOLATION_FAILED"
        human = (f"Containment agent confirmed {host} is isolated from the network."
                 if ok else f"Containment agent could NOT isolate {host}: {message}")
    elif action == "release":
        state = "released" if ok else "error"
        code = "NETWORK_ISOLATION_RELEASED" if ok else "NETWORK_ISOLATION_RELEASE_FAILED"
        human = (f"Containment agent confirmed {host} is back online."
                 if ok else f"Containment agent could NOT release {host}: {message}")
    else:
        return get_state(host)

    containment_collection.update_one(
        {"_id": _key(host)},
        {"$set": {"state": state, "applied_at": now, "message": message,
                  "agent_seen_at": now}},
        upsert=True,
    )
    append_ledger_entry(
        entity_type="HOST", entity_id=host, stage="EDR_CONTAINMENT",
        action_taken=code, reasoning_output=human, analyst_user="containment-agent",
    )
    _broadcast(host, state)
    return get_state(host)
