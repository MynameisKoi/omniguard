from fastapi import FastAPI, WebSocket,  WebSocketDisconnect
from starlette.concurrency import run_in_threadpool
from events import manager
from models import Alert, AlertCreate
from db import database
from graph import ingest_alert, get_overview_graph

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

# This is for graph to be shown in the frontend 
@app.get("/graph")
def get_graph() -> None:
    return get_overview_graph()


# making the websocket connection for live alert in the frontend 
@app.websocket("/ws/alerts")
async def get_live_alerts(websocket: WebSocket) -> None: 
    await manager.connect(websocket)
    while True: 
        try:
            await websocket.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(websocket)