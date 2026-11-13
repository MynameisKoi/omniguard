"""Web push notifications to the analyst's phone (or any browser).

When Live AI flags an alert that needs attention, we send a push so the analyst
is told even when the dashboard is closed and the phone is locked. Phones only
let their own vendor's servers wake a closed app, so the *delivery* hops through
the browser's push service (Apple / Google) — exactly like every phone app. But
the push we send is a **contentless ping** ("the dashboard needs you"): no host
names, no verdicts, nothing sensitive. The analyst taps it, the app opens, and
only then pulls the real details from this local server. The intel never leaves
the network; only a doorbell ring does.

Uses VAPID (self-generated keys, no account anywhere). The private key is
generated once and kept next to this file; the public key is handed to the
browser so it can subscribe.
"""

import json
import os
from pathlib import Path

from py_vapid import Vapid, b64urlencode
from cryptography.hazmat.primitives import serialization
from pywebpush import webpush, WebPushException

from db import database

_HERE = Path(__file__).resolve().parent
_KEY_FILE = _HERE / ".vapid_private.pem"
# who the push service can contact about our pushes (VAPID requires a contact).
# Apple's Web Push rejects the token ("BadJwtToken") if this isn't a valid
# mailto/https URL with a real TLD — '.local' is refused — so use a real domain.
VAPID_CONTACT = os.getenv("VAPID_CONTACT", "mailto:soc@omniguard.io")

subs_collection = database["push_subscriptions"]


def _load_or_create_vapid() -> Vapid:
    v = Vapid()
    if _KEY_FILE.exists():
        return Vapid.from_file(str(_KEY_FILE))
    v.generate_keys()
    v.save_key(str(_KEY_FILE))      # private key PEM, generated once
    print(f"[push] generated VAPID key at {_KEY_FILE.name}")
    return v


_vapid = _load_or_create_vapid()


def get_public_key() -> str:
    """The application server key the browser needs to subscribe (base64url)."""
    raw = _vapid.public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return b64urlencode(raw)


def save_subscription(sub: dict) -> bool:
    """Store a browser's push subscription (keyed by its endpoint, so re-subscribing
    the same browser doesn't pile up duplicates)."""
    endpoint = (sub or {}).get("endpoint")
    if not endpoint:
        return False
    subs_collection.update_one({"_id": endpoint}, {"$set": {"sub": sub}}, upsert=True)
    return True


def remove_subscription(endpoint: str) -> None:
    subs_collection.delete_one({"_id": endpoint})


def count() -> int:
    return subs_collection.estimated_document_count()


def send_to_all(title: str, body: str, url: str = "/", tag: str = "omniguard") -> int:
    """Send one notification to every subscribed browser. Dead subscriptions
    (the browser unsubscribed / expired) are dropped as we find them. Returns how
    many were delivered."""
    payload = json.dumps({"title": title, "body": body, "url": url, "tag": tag})
    sent = 0
    for doc in list(subs_collection.find({})):
        try:
            webpush(
                subscription_info=doc["sub"],
                data=payload,
                vapid_private_key=str(_KEY_FILE),
                vapid_claims={"sub": VAPID_CONTACT},
                timeout=10,
            )
            sent += 1
        except WebPushException as e:
            status = getattr(e.response, "status_code", None)
            if status in (404, 410):          # subscription is gone for good
                remove_subscription(doc["_id"])
            else:
                print(f"[push] send failed ({status}): {e}")
        except Exception as e:
            print(f"[push] send error: {e}")
    return sent
