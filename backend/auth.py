import hashlib
import hmac
import os
import sys

from db import users_collection

# v1 login: only SOC analysts have accounts, and they're created with this script
# (no public signup). passwords are never stored, only a salted scrypt hash.
# next step: tokens so the API itself checks who is asking.

def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}:{digest.hex()}"

def verify_password(password, stored):
    salt_hex, digest_hex = stored.split(":")
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    # constant-time compare so timing doesn't leak how much matched
    return hmac.compare_digest(digest.hex(), digest_hex)

def check_login(email, password):
    user = users_collection.find_one({"email": email.strip().lower()})
    if not user or not verify_password(password, user["password_hash"]):
        return None
    return {"email": user["email"], "name": user.get("name", "")}

def update_user(email, current_password, name, new_password=None):
    # every change needs the current password, since v1 has no tokens yet
    if not check_login(email, current_password):
        return None
    changes = {"name": name.strip()}
    if new_password:
        changes["password_hash"] = hash_password(new_password)
    users_collection.update_one({"email": email.strip().lower()}, {"$set": changes})
    return {"email": email.strip().lower(), "name": changes["name"]}

def create_user(email, password, name=""):
    email = email.strip().lower()
    users_collection.update_one(
        {"email": email},
        {"$set": {"email": email, "name": name, "password_hash": hash_password(password)}},
        upsert=True,
    )

# usage: python auth.py analyst@omniguard.io "password" "A. Maharjan"
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print('usage: python auth.py <email> <password> [name]')
        sys.exit(1)
    create_user(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    print(f"saved user {sys.argv[1].strip().lower()}")
