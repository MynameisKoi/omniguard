from fastapi import FastAPI, HTTPException
from models import Alert, AlertCreate
from db import database
from graph import ingest_alert, get_entity_graph, get_host_subgraph

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

@app.get("/health")
def get_health():
    return {"status": "ok"}

# This is coming from our security system
# They store the event here
@app.post("/alerts", response_model=Alert, status_code=201)
def create_alert(payload: AlertCreate) -> Alert:
    alert = Alert(**payload.model_dump())
    alerts_collection.insert_one(alert.model_dump())

    # now creating the graph in neo4j as well
    ingest_alert(alert)

    return alert

# This is for the frontend 
@app.get("/alerts", response_model=list[Alert])
def get_alerts() -> list[Alert]:
    alerts: list[Alert] = list(alerts_collection.find({}, {"_id": 0}))
    return alerts

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