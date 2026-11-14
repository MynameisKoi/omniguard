from __future__ import annotations

import asyncio
import base64
import logging
import os
import time
import urllib.parse

import httpx
from fastapi import BackgroundTasks, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from dom.crawler import analyze_page


log = logging.getLogger("verifyeye")

# where evidence screenshots go (#3). docker-compose points this at the backend container
CORE_API_URL = os.getenv("CORE_API_URL", "http://localhost:8000")

# verdict cache (#8): every login page used to launch a fresh ~300 MB chromium,
# even on a reload. a verdict is reused for CACHE_TTL seconds per URL, and
# simultaneous checks of the same URL share one browser run.
CACHE_TTL = 600
CACHE_MAX = 500
_cache: dict[str, tuple[float, dict]] = {}
_inflight: dict[str, asyncio.Future] = {}

# concurrency cap (#8): a ~300 MB browser launches per distinct URL checked, so a
# burst of many different URLs could exhaust the machine. Never run more than this
# many browser checks at once; extra requests simply wait their turn.
MAX_CONCURRENT = int(os.getenv("VERIFY_MAX_CONCURRENT", "3"))
_sem = asyncio.Semaphore(MAX_CONCURRENT)

app = FastAPI(title="VerifyEye Ingress")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r"chrome-extension://.*",
    allow_methods=["*"],
    allow_headers=["*"],
)


class VerifyRequest(BaseModel):
    url: str


def _registrable(host: str) -> str:
    return ".".join(host.lower().split(".")[-2:]) if host else ""


def _submits_off_domain(url: str, actions: list[str]) -> bool:
    page = _registrable(urllib.parse.urlparse(url).hostname or "")
    for action in actions:
        action_host = urllib.parse.urlparse(urllib.parse.urljoin(url, action)).hostname or ""
        if action_host and _registrable(action_host) != page:
            return True
    return False


@app.get("/health")
def health():
    return {"status": "ok", "cached_verdicts": len(_cache)}


@app.post("/cache/clear")
def clear_cache():
    """Forget cached verdicts, so the next check of each URL runs the browser
    (and captures evidence) again. Used by check_urls.py --fresh."""
    n = len(_cache)
    _cache.clear()
    return {"cleared": n}


def _verdict(result: dict) -> dict:
    credential_form = result.get("credential_form", False)
    brand = result.get("brand_target")
    off_domain = _submits_off_domain(result["url"], result.get("form_actions", []))

    blocked_by = result.get("blocked_by")
    phishing = credential_form and off_domain
    if blocked_by and not phishing:
        # the agent never saw the real page: no verdict either way
        confidence = 0.0
    elif phishing and brand:
        confidence = 0.95
    elif phishing:
        confidence = 0.8
    elif credential_form and brand:
        confidence = 0.5
    else:
        confidence = 0.1

    return {
        "phishing": phishing,
        "confidence": confidence,
        "brand": brand,
        "off_domain": off_domain,
        "credential_form": credential_form,
        "blocked": bool(blocked_by) and not phishing,
        "blocked_by": blocked_by,
        "title": result.get("title"),
        "form_actions": result.get("form_actions", []),
    }


def _send_evidence(url: str, result: dict, verdict: dict) -> None:
    """Post the screenshot + verdict to the core API. Runs after the response,
    so the extension never waits on it; a failure only costs the evidence."""
    shot = result.get("screenshot")
    if not shot:
        return
    try:
        resp = httpx.post(f"{CORE_API_URL}/evidence", timeout=10.0, json={
            "url": url,
            "final_url": result.get("final_url"),
            "title": (verdict.get("title") or "")[:500],
            "phishing": verdict["phishing"],
            "confidence": verdict["confidence"],
            "brand": verdict.get("brand"),
            "off_domain": verdict["off_domain"],
            "credential_form": verdict["credential_form"],
            "blocked": verdict["blocked"],
            "blocked_by": verdict["blocked_by"],
            "form_actions": verdict["form_actions"][:50],
            "image_type": "image/jpeg",
            "image_b64": base64.b64encode(shot).decode(),
        })
        resp.raise_for_status()
    except Exception as e:
        log.warning("evidence upload failed for %s: %s", url, e)


@app.post("/verify")
async def verify(req: VerifyRequest, background: BackgroundTasks):
    url = req.url
    hit = _cache.get(url)
    if hit and hit[0] > time.monotonic():
        return {**hit[1], "cached": True}

    # someone is already checking this URL: wait for their answer
    if url in _inflight:
        return {**(await asyncio.shield(_inflight[url])), "cached": True}

    future = asyncio.get_running_loop().create_future()
    _inflight[url] = future
    try:
        async with _sem:                              # wait if too many are running
            result = await run_in_threadpool(analyze_page, url)
        verdict = _verdict(result)
        verdict["evidence"] = bool(result.get("screenshot"))
        future.set_result(verdict)
    except Exception as e:
        future.set_exception(e)
        raise
    finally:
        _inflight.pop(url, None)

    if len(_cache) >= CACHE_MAX:
        _cache.pop(min(_cache, key=lambda k: _cache[k][0]))   # drop the oldest
    _cache[url] = (time.monotonic() + CACHE_TTL, verdict)

    background.add_task(_send_evidence, url, result, verdict)
    return {**verdict, "cached": False}
