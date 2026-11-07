"""Tests for agent evidence storage (#3): validation, hashing, integrity, lookups.

The Mongo collection is swapped for a small in-memory fake, so these run
without a database.
"""

import base64
import hashlib
import os
import sys

import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import evidence  # noqa: E402

# smallest valid-looking images: the right magic bytes plus some payload
JPEG = b"\xff\xd8\xff\xe0" + b"jpeg-body" * 10
PNG = b"\x89PNG\r\n\x1a\n" + b"png-body" * 10


class FakeCursor(list):
    def sort(self, key, direction):
        return FakeCursor(sorted(self, key=lambda d: d[key], reverse=direction < 0))

    def limit(self, n):
        return FakeCursor(self[:n])


class FakeCollection:
    def __init__(self):
        self.docs = []

    def insert_one(self, doc):
        self.docs.append(dict(doc))

    @staticmethod
    def _match(doc, query):
        def ok(value, cond):
            if isinstance(cond, dict) and "$ne" in cond:
                return value != cond["$ne"]
            return value == cond
        return all(ok(doc.get(k), v) for k, v in query.items())

    @staticmethod
    def _project(doc, proj):
        if not proj:
            return dict(doc)
        if any(v == 1 for v in proj.values()):
            return {k: doc[k] for k, v in proj.items() if v == 1 and k in doc}
        return {k: v for k, v in doc.items() if proj.get(k, 1) != 0}

    def find(self, query, proj=None):
        return FakeCursor(self._project(d, proj) for d in self.docs if self._match(d, query))

    def find_one(self, query, proj=None):
        hits = self.find(query, proj)
        return hits[0] if hits else None


@pytest.fixture
def store(monkeypatch):
    fake = FakeCollection()
    monkeypatch.setattr(evidence, "evidence_collection", fake)
    return fake


def capture(**overrides):
    base = {
        "url": "https://evil-login.example/signin",
        "final_url": "https://evil-login.example/signin",
        "title": "Sign in",
        "phishing": True,
        "confidence": 0.95,
        "brand": "Microsoft",
        "off_domain": True,
        "credential_form": True,
        "form_actions": ["https://harvest.example/collect"],
        "image_type": "image/jpeg",
        "image_b64": base64.b64encode(JPEG).decode(),
    }
    base.update(overrides)
    return base


def test_store_hashes_image_and_hides_bytes(store):
    meta = evidence.store_evidence(capture())

    assert meta["image_sha256"] == hashlib.sha256(JPEG).hexdigest()
    assert meta["image_size"] == len(JPEG)
    assert meta["domain"] == "evil-login.example"
    assert meta["image_url"] == f"/evidence/{meta['evidence_id']}/image"
    # the response never carries the image itself; the stored document does
    assert "image" not in meta and "image_b64" not in meta
    assert store.docs[0]["image"] == JPEG


def test_png_accepted(store):
    meta = evidence.store_evidence(capture(image_type="image/png", image_b64=base64.b64encode(PNG).decode()))
    assert meta["image_type"] == "image/png"


@pytest.mark.parametrize("bad, message", [
    ({"image_b64": "not base64 !!"}, "base64"),
    ({"image_b64": base64.b64encode(b"<html>not an image</html>").decode()}, "don't match"),
    ({"image_type": "image/png"}, "don't match"),   # jpeg bytes labelled as png
])
def test_rejects_bad_images(store, bad, message):
    with pytest.raises(evidence.EvidenceError, match=message):
        evidence.store_evidence(capture(**bad))
    assert store.docs == []


def test_rejects_oversized_image(store, monkeypatch):
    monkeypatch.setattr(evidence, "MAX_IMAGE_BYTES", 50)
    with pytest.raises(evidence.EvidenceError, match="larger"):
        evidence.store_evidence(capture())


def test_list_filters_by_verdict_domain_and_url(store):
    evidence.store_evidence(capture())
    evidence.store_evidence(capture(url="https://login.microsoftonline.com/", phishing=False, confidence=0.1))

    assert len(evidence.list_evidence()) == 2
    assert [e["phishing"] for e in evidence.list_evidence(verdict="phishing")] == [True]
    assert [e["phishing"] for e in evidence.list_evidence(verdict="cleared")] == [False]
    assert len(evidence.list_evidence(domain="EVIL-LOGIN.example")) == 1
    assert len(evidence.list_evidence(url="https://login.microsoftonline.com/")) == 1
    # lists never include image bytes
    assert all("image" not in e for e in evidence.list_evidence())


def test_blocked_captures_are_neither_phishing_nor_cleared(store):
    # the agent hit a bot check: it couldn't see the page, so it's not "safe"
    evidence.store_evidence(capture(url="https://claude.ai/login", phishing=False, confidence=0.0,
                                    blocked=True, blocked_by="challenge page"))
    evidence.store_evidence(capture(url="https://github.com/login", phishing=False, confidence=0.5))

    assert [e["url"] for e in evidence.list_evidence(verdict="blocked")] == ["https://claude.ai/login"]
    assert [e["url"] for e in evidence.list_evidence(verdict="cleared")] == ["https://github.com/login"]
    assert evidence.list_evidence(verdict="phishing") == []


def test_list_is_newest_first(store):
    first = evidence.store_evidence(capture())
    second = evidence.store_evidence(capture())
    assert [e["evidence_id"] for e in evidence.list_evidence()] == [second["evidence_id"], first["evidence_id"]]


def test_integrity_check_catches_a_swapped_image(store):
    meta = evidence.store_evidence(capture())
    assert evidence.get_evidence(meta["evidence_id"])["integrity_ok"] is True

    # someone edits the stored screenshot behind our back
    store.docs[0]["image"] = JPEG + b"edited"
    assert evidence.get_evidence(meta["evidence_id"])["integrity_ok"] is False


def test_missing_evidence_returns_none(store):
    assert evidence.get_evidence("nope") is None
    assert evidence.get_image("nope") is None
