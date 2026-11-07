"""Agent evidence (#3): what VerifyEye's sandboxed agent actually saw.

When the agent opens a login page it screenshots it and sends the capture here,
with its verdict. Heavy blobs live in Mongo (per the architecture); every image
is stored with its SHA-256 so a swapped or edited screenshot is detectable.

Captures are linked to alerts by URL — an alert's target_url is the page the
extension asked the agent to check — so the extension needs no changes.
"""
import base64
import hashlib
import urllib.parse
import uuid
from datetime import datetime, timezone

from pymongo import DESCENDING

from db import database

evidence_collection = database["evidence"]
evidence_collection.create_index([("url", 1), ("captured_at", DESCENDING)])
evidence_collection.create_index([("domain", 1), ("captured_at", DESCENDING)])

MAX_IMAGE_BYTES = 5 * 1024 * 1024
# the first bytes of each format we accept, so a renamed file can't slip in
MAGIC = {"image/jpeg": b"\xff\xd8\xff", "image/png": b"\x89PNG\r\n\x1a\n"}

# everything but the image itself, for lists and metadata
META = {"_id": 0, "image": 0}


class EvidenceError(ValueError):
    pass


def _public(doc):
    doc["image_url"] = f"/evidence/{doc['evidence_id']}/image"
    return doc


def store_evidence(capture):
    """capture: an EvidenceCreate as a dict. Returns the stored metadata."""
    try:
        image = base64.b64decode(capture.pop("image_b64"), validate=True)
    except Exception:
        raise EvidenceError("image_b64 is not valid base64")
    if len(image) > MAX_IMAGE_BYTES:
        raise EvidenceError("screenshot is larger than 5 MB")
    if not image.startswith(MAGIC[capture["image_type"]]):
        raise EvidenceError("image bytes don't match image_type")

    doc = {
        "evidence_id": str(uuid.uuid4()),
        "captured_at": datetime.now(timezone.utc),
        "domain": (urllib.parse.urlparse(capture["url"]).hostname or "").lower(),
        **capture,
        "image": image,
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_size": len(image),
    }
    evidence_collection.insert_one(dict(doc))
    doc.pop("image")
    doc.pop("_id", None)
    return _public(doc)


def list_evidence(domain=None, url=None, verdict=None, limit=50):
    query = {}
    if domain:
        query["domain"] = domain.lower()
    if url:
        query["url"] = url
    if verdict == "phishing":
        query["phishing"] = True
    elif verdict == "cleared":
        query["phishing"] = False
        query["blocked"] = {"$ne": True}
    elif verdict == "blocked":
        query["blocked"] = True
    rows = evidence_collection.find(query, META).sort("captured_at", DESCENDING).limit(limit)
    return [_public(r) for r in rows]


def get_evidence(evidence_id):
    """Metadata plus a fresh integrity check of the stored image."""
    doc = evidence_collection.find_one({"evidence_id": evidence_id}, {"_id": 0})
    if not doc:
        return None
    doc["integrity_ok"] = hashlib.sha256(doc.pop("image")).hexdigest() == doc["image_sha256"]
    return _public(doc)


def get_image(evidence_id):
    doc = evidence_collection.find_one(
        {"evidence_id": evidence_id}, {"_id": 0, "image": 1, "image_type": 1, "image_sha256": 1}
    )
    return doc
