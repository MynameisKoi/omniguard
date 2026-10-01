from fastapi import FastAPI 
from models import Alert, AlertCreate
from db import database
from graph import ingest_alert

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