"""Live Host DFIR (Digital Forensics & Incident Response) Snapshots.

Allows an analyst (or Ask AI) to request a live forensic snapshot from any
endpoint running `demo/containment_agent.py`:
  - Active network connections (established sockets, remote IPs/ports, PIDs)
  - Running processes (flagged for suspicious reverse-shell / beacon indicators)
  - Local hosts file overrides & OS/admin telemetry

Snapshots are persisted in MongoDB (`dfir_snapshots`), recorded in the tamper-
evident decision ledger, and broadcast live to dashboards via WebSocket.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from db import database
from events import manager
from ledger import append_ledger_entry
from containment import containment_collection, _key

dfir_collection = database["dfir_snapshots"]

SUSPICIOUS_PROC_RE = re.compile(
    r"(beacon_sim|beacon_agent|reverse.?shell|/dev/tcp|\bnc\b|\bncat\b|\bsocat\b|"
    r"powershell.*-enc|cmd\.exe.*/c|bash\s+-i|python.*socket|meterpreter|sliver)",
    re.IGNORECASE,
)

SUSPICIOUS_PORTS = {4444, 4445, 1337, 8443, 9000, 9001, 5555, 6666, 31337}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def analyze_snapshot_risk(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Deterministically flag suspicious processes and likely C2 network sockets."""
    suspicious_procs: list[dict[str, Any]] = []
    for p in snapshot.get("processes") or []:
        cmd = f"{p.get('name', '')} {p.get('cmdline', '')}".strip()
        if SUSPICIOUS_PROC_RE.search(cmd):
            suspicious_procs.append({
                "pid": p.get("pid"),
                "name": p.get("name", ""),
                "cmdline": p.get("cmdline", "")[:240],
                "user": p.get("user", ""),
                "reason": "Matches C2 beacon / reverse-shell process signature",
            })

    suspicious_conns: list[dict[str, Any]] = []
    for c in snapshot.get("connections") or []:
        rport = c.get("remote_port")
        try:
            rport_int = int(rport) if rport is not None else None
        except (TypeError, ValueError):
            rport_int = None
        proc = str(c.get("process", ""))
        if (rport_int in SUSPICIOUS_PORTS) or SUSPICIOUS_PROC_RE.search(proc):
            suspicious_conns.append({
                **c,
                "reason": (
                    f"Connection to common C2/shell port {rport_int}"
                    if rport_int in SUSPICIOUS_PORTS
                    else "Socket owned by suspicious process"
                ),
            })

    risk_level = (
        "critical" if (suspicious_procs and suspicious_conns)
        else "high" if (suspicious_procs or suspicious_conns)
        else "low"
    )
    return {
        "risk_level": risk_level,
        "suspicious_processes": suspicious_procs,
        "suspicious_connections": suspicious_conns,
        "process_count": len(snapshot.get("processes") or []),
        "connection_count": len(snapshot.get("connections") or []),
    }


def request_snapshot(host: str, by: str = "unknown") -> dict[str, Any]:
    """Queue a live DFIR snapshot collection request for the host's containment agent."""
    k = _key(host)
    now = _now()
    containment_collection.update_one(
        {"_id": k},
        {"$set": {"dfir_requested": True, "dfir_requested_at": now, "dfir_requested_by": by}},
        upsert=True,
    )
    append_ledger_entry(
        entity_type="HOST",
        entity_id=host,
        stage="DFIR_COLLECTION",
        action_taken="DFIR_SNAPSHOT_REQUESTED",
        reasoning_output=f"Analyst {by} requested a live DFIR snapshot (processes, sockets, hosts) from {host}.",
        analyst_user=by,
    )
    manager.broadcast_from_thread({
        "type": "dfir_requested",
        "host": host,
        "requested_by": by,
        "requested_at": now.isoformat(),
    })
    return {
        "host": host,
        "status": "dfir_requested",
        "requested_by": by,
        "requested_at": now.isoformat(),
    }


def store_snapshot(host: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Persist a DFIR snapshot reported by the endpoint agent and broadcast it."""
    k = _key(host)
    now = _now()
    analysis = analyze_snapshot_risk(payload)
    doc = {
        "host": host,
        "host_key": k,
        "collected_at": now.isoformat(),
        "os": payload.get("os", "unknown"),
        "hostname": payload.get("hostname", host),
        "is_admin": bool(payload.get("is_admin", False)),
        "gateways": payload.get("gateways") or [],
        "processes": (payload.get("processes") or [])[:100],
        "connections": (payload.get("connections") or [])[:100],
        "hosts_entries": (payload.get("hosts_entries") or [])[:50],
        "analysis": analysis,
    }
    dfir_collection.insert_one(dict(doc))
    containment_collection.update_one(
        {"_id": k},
        {"$set": {"dfir_requested": False, "dfir_last_collected_at": now, "agent_seen_at": now}},
        upsert=True,
    )
    append_ledger_entry(
        entity_type="HOST",
        entity_id=host,
        stage="DFIR_COLLECTION",
        action_taken="DFIR_SNAPSHOT_COLLECTED",
        reasoning_output=(
            f"Collected DFIR snapshot from {host}: {analysis['process_count']} processes, "
            f"{analysis['connection_count']} sockets, "
            f"{len(analysis['suspicious_processes'])} suspicious processes, "
            f"{len(analysis['suspicious_connections'])} suspicious connections."
        ),
        analyst_user="containment-agent",
    )
    manager.broadcast_from_thread({"type": "dfir_updated", "host": host, "snapshot": doc})
    return doc


def get_latest_snapshot(host: str) -> dict[str, Any] | None:
    """Return the most recent DFIR snapshot for a host (case-insensitive)."""
    k = _key(host)
    docs = list(dfir_collection.find({"host_key": k}, {"_id": 0}).sort("collected_at", -1).limit(1))
    return docs[0] if docs else None


def list_snapshots(host: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
    query = {"host_key": _key(host)} if host and host.strip() else {}
    return list(dfir_collection.find(query, {"_id": 0}).sort("collected_at", -1).limit(limit))
