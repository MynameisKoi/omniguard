from fastapi import FastAPI 
from models import Alert, AlertCreate

# This is temporary as we don't have a storage for now
alerts: list[Alert] = []

app = FastAPI(title="OmniGuard SOC API")

@app.get("/health")
def get_health():
    return {"status": "ok"}

# This is coming from our security system
# They store the event here
@app.post("/alerts", response_model=Alert, status_code=201)
def create_alert(payload: AlertCreate) -> Alert:
    alert = Alert(**payload.model_dump())

    alerts.append(alert)

    return alert

# This is for the frontend 
@app.get("/alerts", response_model=list[Alert])
def get_alerts() -> list[Alert]:
    return alerts