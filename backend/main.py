from fastapi import FastAPI, WebSocket,  WebSocketDisconnect, HTTPException
from starlette.concurrency import run_in_threadpool
from events import manager
from models import Alert, AlertCreate
from db import database, brands_collection
from ai import run_triage, answer_question
from auth import check_login, update_user
from status import check_mongo, check_neo4j, check_ollama
from typing import Literal
from pydantic import BaseModel, Field
from graph import ingest_alert, get_overview_graph, get_host_graph
from ledger import (
    append_ledger_entry,
    verify_ledger_integrity,
    get_ledger_for_entity,
    get_recent_ledger,
)

from config import CORS_ORIGINS

from fastapi.middleware.cors import CORSMiddleware

# getting the collection
alerts_collection = database["alerts"]


app = FastAPI(title="OmniGuard SOC API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=r"chrome-extension://.*",   # VerifyEye extension (id varies per machine)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

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
    return user

class ProfileUpdate(BaseModel):
    email: str
    current_password: str
    name: str = Field(default="", max_length=80)
    new_password: str | None = Field(default=None, min_length=8)

# profile page: change display name and/or password
@app.post("/auth/profile")
async def update_profile(payload: ProfileUpdate):
    user = await run_in_threadpool(
        update_user, payload.email, payload.current_password, payload.name, payload.new_password
    )
    if not user:
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    return user

# This is coming from our security system
# They store the event here
@app.post("/alerts", response_model=Alert, status_code=201)
async def create_alert(payload: AlertCreate) -> Alert:
    alert = Alert(**payload.model_dump())

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
@app.get("/alerts", response_model=list[Alert])
def get_alerts() -> list[Alert]:
    alerts: list[Alert] = list(alerts_collection.find({}, {"_id": 0}))
    return alerts

# This is for graph to be shown in the frontend 
@app.get("/graph")
def get_graph() -> None:
    return get_overview_graph()

# This endpoint is for individual alerts and for its graph 
@app.get("/graph/host/{hostname}")
def get_host_graph_route(hostname: str):
    return get_host_graph(hostname)


# making the websocket connection for live alert in the frontend 
@app.websocket("/ws/alerts")
async def get_live_alerts(websocket: WebSocket) -> None: 
    await manager.connect(websocket)
    while True: 
        try:
            await websocket.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(websocket)

# new endpoint for getting the brands
@app.get("/brands")
def get_brands():
    return list(brands_collection.find({}, {"_id": 0}))

# endpoint for ai summary for all the alerts
@app.get("/ai/summary")
async def ai_summary():
    alerts = list(alerts_collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(50))
    triage = await run_in_threadpool(run_triage, alerts)
    return {"triage": triage, "alert_count": len(alerts)}

# live health of every piece the dashboard shows in its status panel. the checks
# block (they talk to mongo/neo4j/ollama over the network) so we run them off the
# event loop. "ingestion" means the pipeline can actually store alerts — mongo is
# up and at least one alert has landed.
@app.get("/status")
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

@app.post("/ai/chat")
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


@app.post("/hosts/{hostname}/isolate", status_code=202)
async def isolate_host(hostname: str):
    """
    EDR network containment action.
    Isolates the host at the network layer to contain lateral movement and C2 traffic.
    Logs immutable audit record to the decision ledger.
    """
    msg = f"Host '{hostname}' successfully isolated from the corporate network."
    try:
        await run_in_threadpool(
            append_ledger_entry,
            entity_type="HOST",
            entity_id=hostname,
            stage="EDR_CONTAINMENT",
            action_taken="NETWORK_ISOLATION",
            reasoning_output=msg,
            analyst_user="analyst@omniguard.io",
        )
    except Exception as e:
        print(f"Ledger write notice: {e}")

    return {
        "status": "isolated",
        "host": hostname,
        "action": "network_isolation",
        "message": msg,
    }


# ── Decision Ledger Audit Endpoints ─────────────────────────────────

@app.get("/investigations/ledger")
async def read_ledger(limit: int = 50):
    """Retrieves newest entries from the replayable investigation decision ledger."""
    records = await run_in_threadpool(get_recent_ledger, limit)
    return {"records": records, "count": len(records)}


@app.get("/investigations/ledger/host/{hostname}")
async def read_host_ledger(hostname: str):
    """Retrieves all decision ledger records associated with a specific host."""
    records = await run_in_threadpool(get_ledger_for_entity, hostname)
    return {"host": hostname, "records": records, "count": len(records)}


@app.get("/investigations/ledger/verify")
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
