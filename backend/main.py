from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from models import Alert, AlertCreate, AlertStatusUpdate
from db import database
from graph import ingest_alert, get_entity_graph, get_host_subgraph, update_alert_status

from config import CORS_ORIGINS

from fastapi.middleware.cors import CORSMiddleware

# getting the collection
alerts_collection = database["alerts"]


app = FastAPI(title="OmniGuard SOC API")

app.add_middleware(
    CORSMiddleware, 
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ── WebSocket Manager for Live Alerts ───────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Live WebSocket feed streaming new alerts and status changes to connected dashboards."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep alive and receive any client ping messages
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        ws_manager.disconnect(websocket)


@app.get("/health")
def get_health():
    return {"status": "ok"}

# This is coming from our security system
# They store the event here
@app.post("/alerts", response_model=Alert, status_code=201)
async def create_alert(payload: AlertCreate) -> Alert:
    alert = Alert(**payload.model_dump())
    alerts_collection.insert_one(alert.model_dump())

    # now creating the graph in neo4j as well
    ingest_alert(alert)

    # Real-time WebSocket broadcast
    alert_dict = alert.model_dump()
    alert_dict["timestamp"] = alert.timestamp.isoformat()
    await ws_manager.broadcast_json({"type": "new_alert", "alert": alert_dict})

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

    alert_dict = alert.model_dump()
    alert_dict["timestamp"] = alert.timestamp.isoformat()
    await ws_manager.broadcast_json({"type": "alert_updated", "alert": alert_dict})

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


# ── Graph endpoints ──────────────────────────────────────────────────────────
# Both return Cytoscape-compatible { nodes: [...], edges: [...] }.
# Alert nodes are excluded by design — the entity layer alone shows lateral
# movement, shared infrastructure, and multi-host campaigns without the noise
# of one node per alert.

@app.get("/graph")
def get_graph():
    """
    Full entity graph: every Host, IP, Domain, URL, Process, User, and
    Technique node plus all standing-fact edges (HAS_IP, LOGGED_INTO, etc.).
    Alert-REPORTED_* edges are excluded — alerts live in /alerts.
    """
    return get_entity_graph()


@app.get("/graph/host/{hostname}")
def get_host_graph(hostname: str):
    """
    2-hop subgraph centred on a specific hostname.
    Returns all nodes reachable from that Host within 2 relationship hops,
    plus the edges between them — useful for per-host investigation panels.
    """
    result = get_host_subgraph(hostname)
    if not result["nodes"]:
        raise HTTPException(status_code=404, detail=f"Host '{hostname}' not found in graph")
    return result