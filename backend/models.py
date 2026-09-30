# This file will contain all the models that will be used for the project
# starting with alertEvents 

# import statements
from datetime import datetime, timezone
from uuid import uuid4
from typing import Literal


from pydantic import BaseModel, Field

class AlertCreate(BaseModel): 
    """What a detection engine sends us. The details"""
    
    # we will be requiring these from the engines 
    source: Literal["verifyeye", "spectrac2", "manual"] = Field(
        description="which detection subsystem produced this alert",
        examples=["verifyeye"]
    )
    event_type: str = Field(
        description="event type that will be shown dont know about the type for now",
        examples=["phishing_page_detected"]
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        description="analyst-facing triage priority",
        examples=["high"],
    )
    host: str = Field(
        description="hostname of the affected machine, it will become the host node in the graph",
        examples=["LAPTOP-10"],
    )
    user: str | None = Field(
        None,
        description="account involved, if attributable; becomes a User node",
        examples=["maharjan"],
    )
    src_ip: str | None = Field(
        None,
        description="source IP address, it becomes an IP node",
        examples=["10.0.0.42"],
    )
    dst_ip: str| None = Field(
        None,
        description="destination IP, the C2 listener; becomes an IP node.",
        examples=["198.51.100.42"]
    )
    confidence: float | None = Field(
        None, 
        description="detector confidence, 0.0-1.0.",
        ge=0.0,
        le=1.0,
        examples=[0.633]
    )
    domain: str | None = Field(
        None,
        description="domain involved; becomes a Domain node",
        examples=["evil-microsoft-login.com"],
    )
    mitre_technique: str | None = Field(
        None,
        description="MITRE ATT&CK technique ID",
        examples=["T1566"],
    )  
    status: Literal["new", "triaged", "resolved"] = Field(
        "new",
        description="triage state, updated by the dashboard after fixes or during or after",
    )

    description: str = Field(
        "",
        description="human-readable summary shown to the analyst",
        examples=["Credential harvesting page impersonating Microsoft 365 login"],
    )
    dst_port: int | None = Field(
        None, 
        description="destination port of the connection",
        ge=1,
        le=65535,
        examples=[433]
    )
    beacon_interval: float| None = Field(
        None, 
        description="dominant beacon period in seconds, from SpectraC2's FFT",
        ge=0.0,
        examples=[60.0]
    )
    mean_jitter: float | None = Field(
        None, 
        description="mean timing jitter in seconds",
        ge=0.0,
        examples=[18.2]
    )
    process_name: str | None = Field(
        None, 
        description="originating process binary; becomes a Process node",
        examples=["sliver-agent.exe"]
    )
    pid: int | None = Field(
        None, 
        description="OS process id; combined with host it keys the Process node",
        examples=[4920]
    )
    target_url: str | None = Field(
        None, 
        description="full URL of the phishing page; becomes a URL node",
        examples=["https://evil-microsoft-login.com/auth/login.php"]
    )
    action_endpoint: str | None = Field(
        None,
        description="where the credential form would submit; off-domain actions are the phishing signal",
        examples=["https://evil-microsoft-login.com/api/v1/harvest"],
    )
    brand_target: str | None = Field(
        None,
        description="brand the page impersonates, from VerifyEye logo detection",
        examples=["Microsoft 365"],
    )

# now creating a Alert class that will inherit from AlertCreate
# we will create unique ids and then the timestamp for that alert
class Alert(AlertCreate):
    """The server side data that will help us to track the alert through alert_id and also logs time"""
    alert_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Key to hold the alert_id it is automatically generated everytime"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp for when the alert was created"
    )


class AlertStatusUpdate(BaseModel):
    """Payload for PATCH /alerts/{alert_id}"""
    status: Literal["new", "triaged", "resolved"]