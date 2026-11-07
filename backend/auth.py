import hashlib
import hmac
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

from db import database, users_collection

# only SOC analysts have accounts, and they're created with this script (no
# public signup). passwords are never stored, only a salted scrypt hash.
#
# signing in issues a session token (#18): a random value the dashboard sends
# as "Authorization: Bearer <token>" and the API checks on every request. Only
# its SHA-256 is stored, so a copy of the database can't be used to sign in.
SESSION_HOURS = 12   # one shift
sessions_collection = database["sessions"]
# Mongo deletes sessions on its own once they expire
sessions_collection.create_index("expires_at", expireAfterSeconds=0)
sessions_collection.create_index("token_hash", unique=True)

# machine clients (the MCP server...) authenticate with a long-lived token
# from the environment instead of a password: API_SERVICE_TOKENS=tok1,tok2
SERVICE_TOKENS = {t.strip() for t in os.getenv("API_SERVICE_TOKENS", "").split(",") if t.strip()}

def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}:{digest.hex()}"

def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split(":")
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        # constant-time compare so timing doesn't leak how much matched
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False

def check_login(email, password):
    user = users_collection.find_one({"email": email.strip().lower()})
    if not user or not verify_password(password, user.get("password_hash", "")):
        return None
    return {"email": user["email"], "name": user.get("name", "")}

def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()

def create_session(user):
    """A new session for a signed-in user. Returns the token (shown once)."""
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=SESSION_HOURS)
    sessions_collection.insert_one({
        "token_hash": _token_hash(token),
        "email": user["email"],
        "created_at": now,
        "expires_at": expires,
    })
    return token, expires

def session_user(token):
    """Who this token belongs to, or None if it's unknown or expired."""
    if not token:
        return None
    if any(hmac.compare_digest(token, t) for t in SERVICE_TOKENS):
        return {"email": "service", "name": "Service client", "service": True}
    session = sessions_collection.find_one({"token_hash": _token_hash(token)})
    # Mongo's expiry sweep runs about once a minute, so check the time too
    if not session or session["expires_at"] <= datetime.now(timezone.utc):
        return None
    user = users_collection.find_one({"email": session["email"]}, {"_id": 0, "email": 1, "name": 1})
    return user and {"email": user["email"], "name": user.get("name", "")}

def end_session(token):
    sessions_collection.delete_one({"token_hash": _token_hash(token)})

def update_user(email, current_password, name, new_password=None, keep_token=None):
    # changes still need the current password, on top of the session: a
    # borrowed, signed-in laptop shouldn't be enough to take over the account
    if not check_login(email, current_password):
        return None
    changes = {"name": name.strip()}
    if new_password:
        changes["password_hash"] = hash_password(new_password)
    users_collection.update_one({"email": email.strip().lower()}, {"$set": changes})
    if new_password:
        # a new password signs out every other session for this account
        # (keep_token: the one making the change stays signed in)
        query = {"email": email.strip().lower()}
        if keep_token:
            query["token_hash"] = {"$ne": _token_hash(keep_token)}
        sessions_collection.delete_many(query)
    return {"email": email.strip().lower(), "name": changes["name"]}

def create_user(email, password, name=""):
    email = email.strip().lower()
    users_collection.update_one(
        {"email": email},
        {"$set": {"email": email, "name": name, "password_hash": hash_password(password)}},
        upsert=True,
    )

def seed_default_user(email="analyst@omniguard.io", password="omniguard123", name="SOC Analyst"):
    """Seeds a default SOC analyst user if the users collection is currently empty."""
    try:
        if users_collection.estimated_document_count() == 0:
            create_user(email, password, name)
            print(f"[auth] Seeded default SOC analyst account: {email}")
            return True
    except Exception as e:
        print(f"[auth] Warning: could not check or seed default user: {e}")
    return False

# usage: python auth.py analyst@omniguard.io "password" "A. Maharjan"
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print('usage: python auth.py <email> <password> [name]')
        sys.exit(1)
    create_user(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    print(f"saved user {sys.argv[1].strip().lower()}")
