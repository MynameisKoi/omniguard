"""Live AI: the model reviews every new alert the moment it lands, instead of
only when an analyst clicks.

When an alert arrives, it is queued here. A single background worker picks it up,
runs the same propose_triage() the analyst's "Ask the AI" button runs, and
broadcasts the result to every open dashboard: first an `ai_reviewing` ping (so
the card can show it's being looked at), then `ai_proposed` with the AI's
verdict, severity, suggested actions and explanation.

Nothing is ever applied. This only produces a *proposal* on the alert — an
analyst still approves or rejects it. Live AI watches; a person still decides.

One worker, not many, on purpose: the local model (llama3.2:3b) handles one
explanation at a time, so a burst of alerts queues up calmly instead of
launching a dozen model calls at once.
"""

import asyncio
import os

from starlette.concurrency import run_in_threadpool

from events import manager

# default on; set LIVE_AI=0 to start with it off (toggle at runtime via /ai/live)
_enabled = os.getenv("LIVE_AI", "1").strip().lower() not in ("0", "false", "no", "off", "")
_queue: "asyncio.Queue[tuple[str, str | None]]" = asyncio.Queue(maxsize=500)
_worker_task: asyncio.Task | None = None


def is_enabled() -> bool:
    return _enabled


def set_enabled(value: bool) -> bool:
    global _enabled
    _enabled = bool(value)
    return _enabled


def enqueue(alert_id: str, host: str | None = None) -> None:
    """Queue a freshly-created alert for AI review. No-op if Live AI is off or the
    queue is full (we drop rather than block the ingest path)."""
    if not _enabled:
        return
    try:
        _queue.put_nowait((alert_id, host))
    except asyncio.QueueFull:
        print(f"live-ai: queue full, dropping review for {alert_id}")


def _needs_attention(proposal: dict | None) -> bool:
    """Should this pop a notification at the analyst? True for anything the AI
    thinks is real or wants a human on; benign / false-positive stays quiet."""
    if not proposal:
        return False
    if proposal.get("verdict") in ("true_positive", "escalate"):
        return True
    if proposal.get("severity") in ("high", "critical"):
        return True
    if proposal.get("actions"):
        return True
    return False


def _serialize(alert: dict) -> dict:
    try:
        from models import Alert
        return Alert(**alert).model_dump(mode="json")
    except Exception:
        return alert


async def _review_one(alert_id: str, host: str | None) -> None:
    # tell the dashboards we're looking at it (card shows an "AI reviewing…" state)
    await manager.broadcast({"type": "ai_reviewing", "alert_id": alert_id, "host": host})

    # propose_triage is synchronous (pymongo + a call to the local model), so it
    # runs in the threadpool; the worker stays free for nothing else anyway.
    from triage import propose_triage
    try:
        alert = await run_in_threadpool(propose_triage, alert_id, "live-ai")
    except Exception as e:
        print(f"live-ai: review failed for {alert_id}: {e}")
        await manager.broadcast({"type": "ai_review_failed", "alert_id": alert_id})
        return

    proposal = (alert or {}).get("triage_proposal")
    await manager.broadcast({
        "type": "ai_proposed",
        "alert": _serialize(alert),
        "needs_attention": _needs_attention(proposal),
    })


async def _worker() -> None:
    while True:
        alert_id, host = await _queue.get()
        try:
            if _enabled:
                await _review_one(alert_id, host)
        except Exception as e:
            print(f"live-ai: worker error on {alert_id}: {e}")
        finally:
            _queue.task_done()


def start() -> "asyncio.Task":
    """Start the background worker (idempotent). Called once at app startup."""
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(_worker())
    return _worker_task
