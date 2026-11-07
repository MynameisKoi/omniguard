from fastapi import FastAPI, WebSocket,  WebSocketDisconnect, HTTPException, Response, Depends, Request
from fastapi.responses import JSONResponse
from neo4j.exceptions import ServiceUnavailable
from starlette.concurrency import run_in_threadpool
from events import manager
from models import Alert, AlertCreate
from db import database, brands_collection
from ai import run_triage, answer_question
from auth import check_login, update_user, create_session, session_user, end_session
from status import check_mongo, check_neo4j, check_ollama
from datetime import datetime, timezone, timedelta
from typing import Literal
from pydantic import BaseModel, Field
from graph import ingest_alert, get_overview_graph, get_host_graph, get_graph_view
from tools import tool_specs, run_tool
from evidence import store_evidence, list_evidence, get_evidence, get_image, EvidenceError
from dedup import compute_alert_simhash, find_matching_alert
from ledger import (
    append_ledger_entry,
    verify_ledger_integrity,
    get_ledger_for_entity,
    get_recent_ledger,
)
from agents import MultiAgentInvestigationPipeline
from ocsf import alert_to_ocsf, export_alerts_to_ocsf

from config import CORS_ORIGINS

from fastapi.middleware.cors import CORSMiddleware

# getting the collection
alerts_collection = database["alerts"]


app = FastAPI(title="OmniGuard SOC API")

# graph endpoints while Neo4j is down: a clear 503, not a hang or a bare 500
@app.exception_handler(ServiceUnavailable)
async def neo4j_unavailable(request, exc):
    return JSONResponse(status_code=503, content={"detail": "Graph database (Neo4j) is unavailable"})

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=r"chrome-extension://.*",   # VerifyEye extension (id varies per machine)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ── who's asking (#18) ──────────────────────────────────────────────
# the dashboard sends "Authorization: Bearer <session token>" (from
# /auth/login); machine clients send a service token. Endpoints the detectors
# use to report (POST /alerts, POST /evidence, GET /brands) stay open for now.
def bearer_token(request: Request):
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header.lower().startswith("bearer ") else None

def current_user(request: Request):
    user = session_user(bearer_token(request))
    if not user:
        raise HTTPException(status_code=401, detail="Not signed in", headers={"WWW-Authenticate": "Bearer"})
    return user

AUTH = [Depends(current_user)]

@app.get("/health")
def get_health():
    return {"status": "ok"}

class LoginRequest(BaseModel):
    email: str
    password: str

# analyst login for the dashboard. same error for a wrong email or a wrong
# password, so nobody can use it to find out which emails have accounts
@app.post("/auth/login")
async def login(payload: LoginRequest):
    user = await run_in_threadpool(check_login, payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token, expires = await run_in_threadpool(create_session, user)
    return {**user, "token": token, "expires_at": expires}

@app.post("/auth/logout", status_code=204)
async def logout(request: Request):
    token = bearer_token(request)
    if token:
        await run_in_threadpool(end_session, token)

class ProfileUpdate(BaseModel):
    email: str
    current_password: str
    name: str = Field(default="", max_length=80)
    new_password: str | None = Field(default=None, min_length=8)

# profile page: change display name and/or password
@app.post("/auth/profile")
async def update_profile(payload: ProfileUpdate, request: Request, me: dict = Depends(current_user)):
    if payload.email.strip().lower() != me["email"]:
        raise HTTPException(status_code=403, detail="You can only change your own account")
    user = await run_in_threadpool(
        update_user, payload.email, payload.current_password, payload.name, payload.new_password,
        bearer_token(request),
    )
    if not user:
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    return user

# This is coming from our security system
# They store the event here
@app.post("/alerts", response_model=Alert, status_code=201)
async def create_alert(payload: AlertCreate) -> Alert:
    now = datetime.now(timezone.utc)
    sim_val, sim_hex = compute_alert_simhash(payload.model_dump())

    # Sliding-window deduplication (AiSOC pattern):
    # Check candidate recent alerts from the same host in the last 120s
    cutoff = now - timedelta(seconds=120)
    try:
        recent = await run_in_threadpool(
            lambda: list(
                alerts_collection.find(
                    {"host": payload.host, "last_seen": {"$gte": cutoff}},
                    {"_id": 0},
                ).limit(50)
            )
        )
    except Exception:
        recent = []

    match = find_matching_alert(sim_val, recent, max_hamming_distance=3)
    if match:
        updated = await run_in_threadpool(
            lambda: alerts_collection.find_one_and_update(
                {"alert_id": match["alert_id"]},
                {
                    "$inc": {"occurrence_count": 1},
                    "$set": {"last_seen": now},
                },
                return_document=True,
            )
        )
        if updated:
            updated.pop("_id", None)
            fused_alert = Alert(**updated)
            await manager.broadcast({
                "type": "alert_fused",
                "alert": fused_alert.model_dump(mode="json"),
            })
            return fused_alert

    alert = Alert(
        **payload.model_dump(),
        simhash=sim_hex,
        occurrence_count=1,
        last_seen=now,
    )

    # running in threadpool
    await run_in_threadpool(alerts_collection.insert_one, alert.model_dump())

    # now creating the graph in neo4j as well
    # running in threadpool. if neo4j is down the alert is already saved in mongo,
    # so log it and carry on — the dashboard should still get the live alert
    try:
        await run_in_threadpool(ingest_alert, alert)
    except Exception as e:
        print(f"graph write failed for alert {alert.alert_id}: {e}")

    # now broadcasting to all the websockets about the new alert
    await manager.broadcast(alert.model_dump(mode="json"))

    return alert

# This is for the frontend 
@app.get("/alerts", response_model=list[Alert], dependencies=AUTH)
def get_alerts() -> list[Alert]:
    alerts: list[Alert] = list(alerts_collection.find({}, {"_id": 0}))
    return alerts

# ── OCSF Export Endpoints (Enterprise SIEM Integration) ─────────────

@app.get("/alerts/export/ocsf", dependencies=AUTH)
async def export_ocsf(limit: int = 200):
    """Exports alerts in standardized OCSF v1.2.0 batch envelope for Splunk/AWS Security Lake."""
    alerts = list(alerts_collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
    return export_alerts_to_ocsf(alerts)


@app.get("/alerts/{alert_id}/ocsf", dependencies=AUTH)
async def get_alert_ocsf(alert_id: str):
    """Retrieves an individual alert formatted as an OCSF Class 2001 (Security Finding)."""
    alert = alerts_collection.find_one({"alert_id": alert_id}, {"_id": 0})
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert_to_ocsf(alert)

# ── agent evidence (#3) ─────────────────────────────────────────────
# VerifyEye's sandboxed agent posts a screenshot + its verdict for every page
# it checks (phishing or cleared). See evidence.py.
class EvidenceCreate(BaseModel):
    url: str = Field(max_length=4096)
    final_url: str | None = Field(default=None, max_length=4096)
    title: str | None = Field(default=None, max_length=500)
    phishing: bool
    confidence: float = Field(ge=0, le=1)
    brand: str | None = Field(default=None, max_length=200)
    off_domain: bool = False
    credential_form: bool = False
    # the agent hit a bot check and never saw the real page (no verdict)
    blocked: bool = False
    blocked_by: str | None = Field(default=None, max_length=100)
    form_actions: list[str] = Field(default_factory=list, max_length=50)
    image_type: Literal["image/jpeg", "image/png"] = "image/jpeg"
    # base64 of the screenshot; the decoded image is capped at 5 MB in evidence.py
    image_b64: str = Field(max_length=7_000_000)

@app.post("/evidence", status_code=201)
async def create_evidence(payload: EvidenceCreate):
    try:
        return await run_in_threadpool(store_evidence, payload.model_dump())
    except EvidenceError as e:
        raise HTTPException(status_code=422, detail=str(e))

@app.get("/evidence", dependencies=AUTH)
async def evidence_list(domain: str | None = None, url: str | None = None,
                        verdict: Literal["phishing", "cleared", "blocked"] | None = None, limit: int = 50):
    return await run_in_threadpool(list_evidence, domain, url, verdict, max(1, min(limit, 200)))

@app.get("/evidence/{evidence_id}", dependencies=AUTH)
async def evidence_detail(evidence_id: str):
    doc = await run_in_threadpool(get_evidence, evidence_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return doc

@app.get("/evidence/{evidence_id}/image", dependencies=AUTH)
async def evidence_image(evidence_id: str):
    doc = await run_in_threadpool(get_image, evidence_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Evidence not found")
    # captures never change once stored, so the browser can keep them
    return Response(content=doc["image"], media_type=doc["image_type"], headers={
        "Cache-Control": "private, max-age=86400, immutable",
        "ETag": f'"{doc["image_sha256"]}"',
    })

@app.get("/alerts/{alert_id}/evidence", dependencies=AUTH)
async def alert_evidence(alert_id: str):
    """Every capture of the page this alert is about, newest first."""
    alert = alerts_collection.find_one({"alert_id": alert_id}, {"_id": 0, "target_url": 1})
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    if not alert.get("target_url"):
        return []
    return await run_in_threadpool(list_evidence, None, alert["target_url"], None, 20)

# ── SOC tools (tools.py): one registry for the AI agent and the MCP server ──
@app.get("/agent/tools", dependencies=AUTH)
async def list_tools():
    return tool_specs()

class ToolCall(BaseModel):
    args: dict = Field(default_factory=dict)
    # action tools only run when approved. An analyst (or a service client
    # with its own approval step, like an MCP host) sets this deliberately
    approved: bool = False

@app.post("/agent/tools/{name}")
async def call_tool(name: str, payload: ToolCall, me: dict = Depends(current_user)):
    return await run_in_threadpool(run_tool, name, payload.args, me["email"], payload.approved)

class AlertStatus(BaseModel):
    status: Literal["new", "triaged", "resolved"]
    note: str | None = Field(default=None, max_length=500)

# mark an alert triaged / resolved from the dashboard (recorded in the ledger)
@app.post("/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, payload: AlertStatus, me: dict = Depends(current_user)):
    out = await run_in_threadpool(run_tool, "set_alert_status",
                                  {"alert_id": alert_id, "status": payload.status, "note": payload.note},
                                  me["email"], True)
    if not out["ok"]:
        raise HTTPException(status_code=404 if "no alert" in out["summary"] else 400, detail=out["summary"])
    return out["data"]

# This is for graph to be shown in the frontend 
@app.get("/graph", dependencies=AUTH)
def get_graph() -> None:
    return get_overview_graph()

# This endpoint is for individual alerts and for its graph 
# graph at scale (#13): ask for only what will be drawn.
#   limit    the N most-connected entities (None = all)
#   include  entity ids that must be in it anyway ("Host:LAPTOP-10"), e.g. what
#            "See in network graph" is about to light up
#   only     exactly these entities, for the filtered views
class GraphViewRequest(BaseModel):
    limit: int | None = Field(default=None, ge=1, le=20000)
    include: list[str] = Field(default_factory=list, max_length=5000)
    only: list[str] | None = Field(default=None, max_length=5000)

@app.post("/graph/view", dependencies=AUTH)
async def graph_view(payload: GraphViewRequest):
    return await run_in_threadpool(get_graph_view, payload.limit, payload.include, payload.only)

@app.get("/graph/host/{hostname}", dependencies=AUTH)
def get_host_graph_route(hostname: str):
    return get_host_graph(hostname)


# making the websocket connection for live alert in the frontend 
@app.websocket("/ws/alerts")
async def get_live_alerts(websocket: WebSocket) -> None:
    # browsers can't set headers on a websocket, so the token rides in the query
    user = await run_in_threadpool(session_user, websocket.query_params.get("token"))
    if not user:
        await websocket.close(code=1008, reason="Not signed in")
        return
    await manager.connect(websocket)
    while True:
        try:
            await websocket.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(websocket)
            break

# new endpoint for getting the brands
@app.get("/brands")
def get_brands():
    return list(brands_collection.find({}, {"_id": 0}))

# endpoint for ai summary for all the alerts
@app.get("/ai/summary", dependencies=AUTH)
async def ai_summary():
    alerts = list(alerts_collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(50))
    triage = await run_in_threadpool(run_triage, alerts)
    return {"triage": triage, "alert_count": len(alerts)}

# live health of every piece the dashboard shows in its status panel. the checks
# block (they talk to mongo/neo4j/ollama over the network) so we run them off the
# event loop. "ingestion" means the pipeline can actually store alerts — mongo is
# up and at least one alert has landed.
@app.get("/status", dependencies=AUTH)
async def get_status():
    def gather():
        mongo = check_mongo()
        return {
            "backend": True,
            "mongo": mongo,
            "neo4j": check_neo4j(),
            "ollama": check_ollama(),
            "ingestion": mongo and alerts_collection.estimated_document_count() > 0,
        }
    return await run_in_threadpool(gather)

class ChatTurn(BaseModel):
    role: Literal["user", "ai"]
    text: str

class ChatRequest(BaseModel):
    question: str
    history: list[ChatTurn] = Field(default_factory=list, max_length=10)

@app.post("/ai/chat", dependencies=AUTH)
async def ai_chat(payload: ChatRequest):
    # newest first; counts use all of them, the prompt only lists the newest 50
    alerts = list(alerts_collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(2000))
    history = [t.model_dump() for t in payload.history]
    answer = await run_in_threadpool(answer_question, payload.question, alerts, history)

    # Record to replayable decision ledger
    try:
        await run_in_threadpool(
            append_ledger_entry,
            entity_type="SYSTEM",
            entity_id="SOC_AI_CHAT",
            stage="AI_ANALYST_CONSULTATION",
            action_taken="ANSWER_QUERY",
            reasoning_output=answer,
            input_context={"question": payload.question, "alerts_evaluated": len(alerts)},
        )
    except Exception as e:
        print(f"Ledger write notice: {e}")

    return {"answer": answer}


class PipelineInvestigationRequest(BaseModel):
    hostname: str


@app.post("/ai/investigate/pipeline", dependencies=AUTH)
async def run_pipeline_investigation(payload: PipelineInvestigationRequest):
    """
    Runs multi-agent investigation workflow on a target host:
    CorrelatorAgent -> TriageAgent -> ContainmentAgent.
    """
    alerts = await run_in_threadpool(lambda: list(alerts_collection.find({}, {"_id": 0})))
    pipeline = MultiAgentInvestigationPipeline()
    result = await run_in_threadpool(pipeline.investigate, payload.hostname, alerts)
    return result


@app.post("/hosts/{hostname}/isolate", status_code=202)
async def isolate_host(hostname: str, me: dict = Depends(current_user)):
    """Host containment (DEMO STUB): recorded in the ledger, no real network
    action yet. Same code the AI agent's approved isolate_host runs (tools.py)."""
    out = await run_in_threadpool(run_tool, "isolate_host", {"hostname": hostname}, me["email"], True)
    if not out["ok"]:
        raise HTTPException(status_code=400, detail=out["summary"])
    return {**out["data"], "action": "network_isolation"}


# ── Decision Ledger Audit Endpoints ─────────────────────────────────

@app.get("/investigations/ledger", dependencies=AUTH)
async def read_ledger(limit: int = 50):
    """Retrieves newest entries from the replayable investigation decision ledger."""
    records = await run_in_threadpool(get_recent_ledger, limit)
    return {"records": records, "count": len(records)}


@app.get("/investigations/ledger/host/{hostname}", dependencies=AUTH)
async def read_host_ledger(hostname: str):
    """Retrieves all decision ledger records associated with a specific host."""
    records = await run_in_threadpool(get_ledger_for_entity, hostname)
    return {"host": hostname, "records": records, "count": len(records)}


@app.get("/investigations/ledger/verify", dependencies=AUTH)
async def verify_ledger():
    """
    Cryptographic verification endpoint:
    Audits the entire SHA-256 hash chain to verify zero tampering or dropped records.
    """
    is_valid, failing_id, total = await run_in_threadpool(verify_ledger_integrity)
    return {
        "valid": is_valid,
        "failing_ledger_id": failing_id,
        "records_checked": total,
        "status": "verified" if is_valid else "tamper_detected",
    }
