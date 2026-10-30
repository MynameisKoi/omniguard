from __future__ import annotations

import urllib.parse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from dom.crawler import analyze_page


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
    return {"status": "ok"}


@app.post("/verify")
async def verify(req: VerifyRequest):
    result = await run_in_threadpool(analyze_page, req.url)

    credential_form = result.get("credential_form", False)
    brand = result.get("brand_target")
    off_domain = _submits_off_domain(result["url"], result.get("form_actions", []))

    phishing = credential_form and off_domain
    if phishing and brand:
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
        "title": result.get("title"),
        "form_actions": result.get("form_actions", []),
    }
