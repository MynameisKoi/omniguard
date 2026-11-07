"""Session tokens (#18): sign-in issues one, the API checks it, sign-out and
expiry end it, and only its hash is ever stored.

The Mongo collections are swapped for small in-memory fakes.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import auth  # noqa: E402


class FakeCollection:
    def __init__(self, docs=None):
        self.docs = list(docs or [])

    @staticmethod
    def _match(doc, query):
        def ok(value, cond):
            if isinstance(cond, dict) and "$ne" in cond:
                return value != cond["$ne"]
            return value == cond
        return all(ok(doc.get(k), v) for k, v in query.items())

    def insert_one(self, doc):
        self.docs.append(dict(doc))

    def find_one(self, query, proj=None):
        for d in self.docs:
            if self._match(d, query):
                return dict(d)
        return None

    def update_one(self, query, update, upsert=False):
        for d in self.docs:
            if self._match(d, query):
                d.update(update["$set"])
                return

    def delete_one(self, query):
        for d in self.docs:
            if self._match(d, query):
                self.docs.remove(d)
                return

    def delete_many(self, query):
        self.docs = [d for d in self.docs if not self._match(d, query)]


@pytest.fixture
def db(monkeypatch):
    users = FakeCollection([{
        "email": "analyst@omniguard.io",
        "name": "A. Analyst",
        "password_hash": auth.hash_password("correct horse"),
    }])
    sessions = FakeCollection()
    monkeypatch.setattr(auth, "users_collection", users)
    monkeypatch.setattr(auth, "sessions_collection", sessions)
    monkeypatch.setattr(auth, "SERVICE_TOKENS", set())
    return users, sessions


def sign_in():
    user = auth.check_login("analyst@omniguard.io", "correct horse")
    return auth.create_session(user)[0]


def test_token_identifies_the_user(db):
    token = sign_in()
    assert auth.session_user(token) == {"email": "analyst@omniguard.io", "name": "A. Analyst"}


def test_only_the_hash_is_stored(db):
    _, sessions = db
    token = sign_in()
    stored = sessions.docs[0]
    assert token not in stored.values()
    assert stored["token_hash"] == auth._token_hash(token)


def test_unknown_missing_and_wrong_tokens_are_rejected(db):
    sign_in()
    assert auth.session_user(None) is None
    assert auth.session_user("") is None
    assert auth.session_user("not-a-real-token") is None


def test_expired_session_is_rejected(db):
    _, sessions = db
    token = sign_in()
    sessions.docs[0]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert auth.session_user(token) is None


def test_sign_out_ends_the_session(db):
    token = sign_in()
    auth.end_session(token)
    assert auth.session_user(token) is None


def test_password_change_signs_out_other_sessions_but_not_this_one(db):
    this_laptop = sign_in()
    other_laptop = sign_in()
    assert auth.update_user("analyst@omniguard.io", "correct horse", "A. Analyst",
                            new_password="battery staple", keep_token=this_laptop)
    assert auth.session_user(this_laptop) is not None
    assert auth.session_user(other_laptop) is None


def test_deleted_account_loses_its_sessions(db):
    users, _ = db
    token = sign_in()
    users.docs.clear()
    assert auth.session_user(token) is None


def test_service_token(db, monkeypatch):
    monkeypatch.setattr(auth, "SERVICE_TOKENS", {"svc-token-123"})
    assert auth.session_user("svc-token-123")["service"] is True
    assert auth.session_user("svc-token-12") is None
