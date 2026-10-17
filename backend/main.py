from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool
from events import manager
ws_manager = manager
from models import Alert, AlertCreate, AlertStatusUpdate
from db import database, brands_collection
from ai import run_triage
from status import check_mongo, check_neo4j, check_ollama
from graph import ingest_alert, get_overview_graph, get_host_graph, update_alert_status

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

# This is coming from our security system
# They store the event here
@app.post("/alerts", response_model=Alert, status_code=201)
async def create_alert(payload: AlertCreate) -> Alert:
    alert = Alert(**payload.model_dump())

    # running in threadpool
    await run_in_threadpool(alerts_collection.insert_one, alert.model_dump())

    # now creating the graph in neo4j as well
    # running in threadpool 
    await run_in_threadpool(ingest_alert, alert)

    # now broadcasting to all the websockets about the new alert
    await manager.broadcast(alert.model_dump(mode="json"))

    return alert

# This is for the frontend 
@app.get("/alerts", response_model=list[Alert])
def get_alerts() -> list[Alert]:
    alerts: list[Alert] = list(alerts_collection.find({}, {"_id": 0}))
    return alerts

@app.patch("/alerts/{alert_id}", response_model=Alert)
async def patch_alert_status(alert_id: str, payload: AlertStatusUpdate) -> Alert:
    """Updates triage status for an alert in MongoDB and Neo4j, then broadcasts to active dashboards."""
    res = alerts_collection.find_one_and_update(
        {"alert_id": alert_id},
        {"$set": {"status": payload.status}},
        return_document=True,
    )
    if not res:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    # Sync to Neo4j Alert node
    update_alert_status(alert_id, payload.status)

    res.pop("_id", None)
    alert = Alert(**res)

    await manager.broadcast({"type": "alert_updated", "alert": alert.model_dump(mode="json")})
    return alert

@app.post("/hosts/{hostname}/isolate", status_code=202)
def isolate_host(hostname: str):
    """
    EDR network containment action.
    Isolates the host at the network layer to contain lateral movement and C2 traffic.
    """
    return {
        "status": "isolated",
        "host": hostname,
        "action": "network_isolation",
        "message": f"Host '{hostname}' successfully isolated from the corporate network.",
    }

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
    try:
        while True: 
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        manager.disconnect(websocket)

# new endpoint for getting the brands
@app.get("/brands")
def get_brands():
    return list(brands_collection.find({}, {"_id": 0}))

# endpoint for ai summary for all the alerts
@app.get("/ai/summary")
async def ai_summary():
    alerts = list(alerts_collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(50))
    try:
        triage = await run_in_threadpool(run_triage, alerts)
        return {"triage": triage, "alert_count": len(alerts)}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"AI triage unavailable: {e}")

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
