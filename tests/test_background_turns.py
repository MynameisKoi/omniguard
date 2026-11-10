"""Ask AI replies run in the background (backend/turns.py): leaving the page
must not stop a reply, and coming back re-attaches to everything so far."""
import os
import sys
import threading

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import turns  # noqa: E402


def test_a_follower_that_leaves_doesnt_stop_the_turn_and_a_new_one_gets_everything(monkeypatch):
    gate = threading.Event()

    def fake_turn(owner, cid, text, context=None):
        yield "a\n"
        gate.wait(5)             # the reply is still being written...
        yield "b\n"
        yield "done\n"

    monkeypatch.setattr(turns, "run_turn", fake_turn)
    turn = turns.start("me", "c1", "hi")
    first = turn.follow()
    assert next(first) == "a\n"                       # the page reads one event, then leaves
    first.close()
    assert turns.running("me", "c1") is turn          # still running without it
    assert turns.start("me", "c1", "again") is None   # one reply per chat at a time
    assert turns.running("someone-else", "c1") is None
    gate.set()
    assert list(turn.follow()) == ["a\n", "b\n", "done\n"]   # coming back: from the start
    assert turns.running("me", "c1") is None
    assert "c1" not in turns.running_ids("me")


def test_a_crashing_turn_still_ends(monkeypatch):
    def broken(owner, cid, text, context=None):
        yield "a\n"
        raise RuntimeError("boom")

    monkeypatch.setattr(turns, "run_turn", broken)
    events = list(turns.start("me", "c2", "hi").follow())
    assert events[0] == "a\n" and '"type": "error"' in events[-1]
