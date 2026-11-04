"""Replayable cryptographic investigation decision ledger for OmniGuard SOC.

Inspired by AiSOC / SOC 2 / ISO 27001 auditability standards:
Records every AI reasoning step, graph evaluation, triage verdict, and containment
action into an immutable, SHA-256 hash-chained decision ledger stored in MongoDB.
Provides cryptographic tamper detection (verify_ledger_integrity) so that decisions
can be audited, reviewed, and replayed with zero ambiguity.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from db import database

ledger_collection = database["decision_ledger"]

GENESIS_HASH = "0" * 64


def compute_entry_hash(
    prev_hash: str,
    timestamp: str,
    entity_id: str,
    stage: str,
    reasoning_output: str,
    action_taken: str,
) -> str:
    """Computes a SHA-256 hash across canonical ledger record attributes."""
    canonical_payload = (
        f"{prev_hash}|{timestamp}|{entity_id}|{stage}|{reasoning_output.strip()}|{action_taken.strip()}"
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def append_ledger_entry(
    entity_type: str,
    entity_id: str,
    stage: str,
    action_taken: str,
    reasoning_output: str,
    analyst_user: str = "system/ai",
    incident_id: Optional[str] = None,
    input_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Appends a new hash-chained entry to the decision ledger.
    Retrieves the last entry's entry_hash as prev_hash; if empty, uses GENESIS_HASH.
    """
    last_doc = ledger_collection.find_one(sort=[("timestamp", -1)])
    prev_hash = last_doc.get("entry_hash", GENESIS_HASH) if last_doc else GENESIS_HASH

    now_iso = datetime.now(timezone.utc).isoformat()
    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        timestamp=now_iso,
        entity_id=entity_id,
        stage=stage,
        reasoning_output=reasoning_output,
        action_taken=action_taken,
    )

    doc: Dict[str, Any] = {
        "ledger_id": str(uuid4()),
        "incident_id": incident_id,
        "entity_type": entity_type.upper(),
        "entity_id": entity_id,
        "stage": stage.upper(),
        "action_taken": action_taken,
        "reasoning_output": reasoning_output,
        "analyst_user": analyst_user,
        "input_context": input_context or {},
        "timestamp": now_iso,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
    }

    ledger_collection.insert_one(doc)
    doc.pop("_id", None)
    return doc


def verify_ledger_integrity() -> Tuple[bool, Optional[str], int]:
    """
    Walks through all ledger entries in chronological order and verifies:
    1. entry_hash matches computed hash from record data.
    2. prev_hash correctly matches previous record's entry_hash.
    Returns (is_valid, failing_ledger_id, total_checked).
    """
    entries = list(ledger_collection.find({}, sort=[("timestamp", 1)]))
    if not entries:
        return True, None, 0

    expected_prev = GENESIS_HASH
    for doc in entries:
        ledger_id = doc.get("ledger_id", "unknown")
        actual_prev = doc.get("prev_hash")
        actual_hash = doc.get("entry_hash")

        if actual_prev != expected_prev:
            return False, ledger_id, len(entries)

        computed = compute_entry_hash(
            prev_hash=actual_prev,
            timestamp=doc.get("timestamp", ""),
            entity_id=doc.get("entity_id", ""),
            stage=doc.get("stage", ""),
            reasoning_output=doc.get("reasoning_output", ""),
            action_taken=doc.get("action_taken", ""),
        )

        if computed != actual_hash:
            return False, ledger_id, len(entries)

        expected_prev = actual_hash

    return True, None, len(entries)


def get_ledger_for_entity(entity_id: str) -> List[Dict[str, Any]]:
    """Retrieves all decision ledger records associated with an entity or host."""
    return list(ledger_collection.find({"entity_id": entity_id}, {"_id": 0}).sort("timestamp", -1))


def get_recent_ledger(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves the newest decision ledger records."""
    return list(ledger_collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))

