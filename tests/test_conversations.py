"""Saved AI conversations (#1): titles, ownership and message history.

The Mongo collection is swapped for a small in-memory fake.
"""

import os
import sys

import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import conversations as conv  # noqa: E402


class FakeCollection:
    def __init__(self):
        self.docs = []

    def _match(self, d, q):
        return all(d.get(k) == v for k, v in q.items())

    def insert_one(self, doc):
        self.docs.append(dict(doc, messages=list(doc["messages"])))

    def find_one(self, q, proj=None):
        for d in self.docs:
            if self._match(d, q):
                return {k: v for k, v in d.items() if k != "_id"}
        return None

    def update_one(self, q, update):
        for d in self.docs:
            if self._match(d, q):
                for k, v in update.get("$set", {}).items():
                    d[k] = v
                for k, v in update.get("$push", {}).items():
                    d[k].append(v)

    def delete_one(self, q):
        before = len(self.docs)
        self.docs = [d for d in self.docs if not self._match(d, q)]
        return type("R", (), {"deleted_count": before - len(self.docs)})()


@pytest.fixture(autouse=True)
def store(monkeypatch):
    fake = FakeCollection()
    monkeypatch.setattr(conv, "conversations_collection", fake)
    return fake


@pytest.mark.parametrize("text, title", [
    ("which hosts got phished this week?", "which hosts got phished this week"),
    ("walk me through everything that happened on LAPTOP-10 since Monday", "walk me through everything that happened on…"),
    ("   contain   it   ", "contain it"),
    ("", "New chat"),
])
def test_title_from_first_question(text, title):
    assert conv.title_from(text) == title


def test_first_question_names_an_untitled_chat():
    c = conv.create_conversation("a@x.io")
    assert c["title"] == "New chat"
    conv.append_message("a@x.io", c["conversation_id"], "user", "is cdn-telemetry-sync.net bad?")
    conv.append_message("a@x.io", c["conversation_id"], "user", "and what about LAPTOP-10?")
    got = conv.get_conversation("a@x.io", c["conversation_id"])
    assert got["title"] == "is cdn-telemetry-sync.net bad"          # the first question, not the second
    assert [m["content"] for m in got["messages"]] == ["is cdn-telemetry-sync.net bad?", "and what about LAPTOP-10?"]


def test_a_chosen_title_is_kept():
    c = conv.create_conversation("a@x.io", "LAPTOP-10 incident")
    conv.append_message("a@x.io", c["conversation_id"], "user", "what happened?")
    assert conv.get_conversation("a@x.io", c["conversation_id"])["title"] == "LAPTOP-10 incident"


def test_other_analysts_cannot_see_or_touch_it():
    c = conv.create_conversation("a@x.io")
    cid = c["conversation_id"]
    assert conv.get_conversation("b@x.io", cid) is None
    assert conv.append_message("b@x.io", cid, "user", "hi") is None
    assert conv.delete_conversation("b@x.io", cid) is False
    assert conv.get_conversation("a@x.io", cid)["messages"] == []


def test_messages_keep_what_the_page_needs_to_redraw():
    c = conv.create_conversation("a@x.io")
    m = conv.append_message("a@x.io", c["conversation_id"], "assistant", "Here's the graph.",
                            steps=[{"tool": "get_host_graph", "ok": True}], blocks=[{"render": "graph"}])
    stored = conv.get_conversation("a@x.io", c["conversation_id"])["messages"][0]
    assert stored["message_id"] == m["message_id"]
    assert stored["steps"][0]["tool"] == "get_host_graph" and stored["blocks"][0]["render"] == "graph"
