"""Saved AI conversations (#1): ChatGPT-style threads, each with its own memory.

One document per conversation, owned by one analyst. Messages keep what the
page needs to redraw them later (tool steps, the data behind a graph or a
screenshot, approvals), so reopening a chat shows it exactly as it was.

Other analysts' conversations are invisible: asking for one you don't own
looks exactly like asking for one that doesn't exist.
"""
import uuid
from datetime import datetime, timezone

from pymongo import DESCENDING

from db import database

conversations_collection = database["conversations"]
conversations_collection.create_index([("owner", 1), ("updated_at", DESCENDING)])
conversations_collection.create_index("conversation_id", unique=True)

TITLE_WORDS = 7
MAX_TITLE = 80


def _now():
    return datetime.now(timezone.utc)


def title_from(text):
    """A short title from the first question: its first few words."""
    words = " ".join((text or "").split()).split(" ")
    title = " ".join(words[:TITLE_WORDS]).rstrip("?.!,")
    return (title + ("…" if len(words) > TITLE_WORDS else ""))[:MAX_TITLE] or "New chat"


def create_conversation(owner, title=None, alert_id=None, seed_messages=None):
    """alert_id: a chat about one alert ("Ask AI about this alert"); every message
    in it is answered with that alert in mind.
    seed_messages: prior turns to pre-load (e.g. handing the corner chat off to the
    full Ask AI), so the agent keeps the whole memory, not just the last message."""
    now = _now()
    seeded = [
        {"message_id": str(uuid.uuid4()), "role": m["role"],
         "content": (m.get("content") or "").strip(), "created_at": now}
        for m in (seed_messages or [])
        if m.get("role") in ("user", "assistant") and (m.get("content") or "").strip()
    ]
    doc = {
        "conversation_id": str(uuid.uuid4()),
        "owner": owner,
        "alert_id": alert_id or None,
        "title": (title or "").strip()[:MAX_TITLE] or "New chat",
        "titled": bool((title or "").strip()),   # false: take the title from the first question
        "created_at": now,
        "updated_at": now,
        "messages": seeded,
    }
    conversations_collection.insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


def list_conversations(owner, limit=100):
    rows = conversations_collection.find(
        {"owner": owner},
        {"_id": 0, "conversation_id": 1, "title": 1, "alert_id": 1, "created_at": 1, "updated_at": 1, "messages": {"$slice": -1}},
    ).sort("updated_at", DESCENDING).limit(limit)
    out = []
    for r in rows:
        last = (r.pop("messages") or [None])[0]
        r["preview"] = (last or {}).get("content", "")[:120]
        out.append(r)
    return out


def get_conversation(owner, conversation_id):
    return conversations_collection.find_one({"conversation_id": conversation_id, "owner": owner}, {"_id": 0})


def rename_conversation(owner, conversation_id, title):
    title = (title or "").strip()[:MAX_TITLE]
    if not title:
        return None
    res = conversations_collection.find_one_and_update(
        {"conversation_id": conversation_id, "owner": owner},
        {"$set": {"title": title, "titled": True}},
        projection={"_id": 0, "messages": 0}, return_document=True)
    return res


def delete_conversation(owner, conversation_id):
    return conversations_collection.delete_one({"conversation_id": conversation_id, "owner": owner}).deleted_count == 1


def append_message(owner, conversation_id, role, content, **extra):
    """Add a message (user, assistant). extra: steps, blocks, approval... The
    first user message names an untitled conversation."""
    message = {"message_id": str(uuid.uuid4()), "role": role, "content": content, "created_at": _now(), **extra}
    convo = get_conversation(owner, conversation_id)
    if not convo:
        return None
    update = {"$push": {"messages": message}, "$set": {"updated_at": message["created_at"]}}
    if role == "user" and not convo.get("titled"):
        update["$set"].update({"title": title_from(content), "titled": True})
    conversations_collection.update_one({"conversation_id": conversation_id, "owner": owner}, update)
    return message


def update_message(owner, conversation_id, message_id, fields):
    """Change a stored message (e.g. an approval card once it's approved)."""
    sets = {f"messages.$.{k}": v for k, v in fields.items()}
    sets["updated_at"] = _now()
    res = conversations_collection.update_one(
        {"conversation_id": conversation_id, "owner": owner, "messages.message_id": message_id}, {"$set": sets})
    return res.modified_count == 1
