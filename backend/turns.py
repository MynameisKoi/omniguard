"""Ask AI replies run in the background.

A turn used to live inside the HTTP response: leave the page (to look at the
dashboard, or another chat) and the reply was dropped. Now each turn runs in
its own thread and keeps every event it streams; the page only *follows* it.
Leave and come back, and the page re-attaches: it gets everything so far, then
the rest live. The finished reply is saved to the conversation as before.

One turn per conversation at a time. In memory only: a backend restart drops
running turns (the analyst's message is already saved; they can ask again).
"""
from __future__ import annotations

import json
import threading
import time

from agent import run_turn

KEEP_DONE = 600          # seconds a finished turn stays here (for a late re-attach)

_jobs: dict[str, "Turn"] = {}
_lock = threading.Lock()


class Turn:
    def __init__(self, owner, conversation_id):
        self.owner, self.conversation_id = owner, conversation_id
        self.events: list[str] = []
        self.done = False
        self.finished_at = None
        self.cond = threading.Condition()

    def _add(self, event):
        with self.cond:
            self.events.append(event)
            self.cond.notify_all()

    def run(self, events):
        try:
            for event in events:
                self._add(event)
        except Exception as e:   # never leave a follower waiting forever
            self._add(json.dumps({"type": "error", "message": f"The reply failed ({type(e).__name__})."}) + "\n")
        finally:
            with self.cond:
                self.done, self.finished_at = True, time.time()
                self.cond.notify_all()

    def follow(self):
        """Every event so far, then each new one as it happens, until the turn ends."""
        i = 0
        while True:
            with self.cond:
                while i >= len(self.events) and not self.done:
                    self.cond.wait(timeout=30)
                batch, i, done = self.events[i:], len(self.events), self.done
            yield from batch
            if done and i >= len(self.events):
                return


def _tidy():
    now = time.time()
    for cid in [c for c, t in _jobs.items() if t.done and now - t.finished_at > KEEP_DONE]:
        del _jobs[cid]


def start(owner, conversation_id, text, context=None):
    """Start a turn in the background. None if this conversation is already replying."""
    with _lock:
        _tidy()
        current = _jobs.get(conversation_id)
        if current and not current.done:
            return None
        turn = _jobs[conversation_id] = Turn(owner, conversation_id)
    threading.Thread(target=turn.run, args=(run_turn(owner, conversation_id, text, context),),
                     name=f"ask-{conversation_id[:8]}", daemon=True).start()
    return turn


def running(owner, conversation_id):
    """The turn still replying in this conversation, or None."""
    t = _jobs.get(conversation_id)
    return t if t and t.owner == owner and not t.done else None


def running_ids(owner):
    return {c for c, t in list(_jobs.items()) if t.owner == owner and not t.done}
