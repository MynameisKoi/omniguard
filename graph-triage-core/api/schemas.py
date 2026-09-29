"""Pydantic schemas for Graph-Triage Core Alert Ingestion.

Supports both SpectraC2 encrypted beaconing alerts and VerifyEye
perceptual phishing interception alerts.
"""

from __future__ import annotations

from typing import Optional, Literal, Dict, Any, Union
from pydantic import BaseModel, Field, field_validator


class SpectraC2AlertInput(BaseModel):
    """Normalized incoming alert emitted by the SpectraC2 beacon detector."""
    source: Literal["spectrac2", "verifyeye", "manual"] = Field(
        "spectrac2", description="Subsystem that produced the alert"
    )
    event_type: str = Field(
        "c2_beacon_detected", description="Classification of threat event"
    )
    severity: str = Field(
        "CRITICAL", description="Analyst triage priority (LOW, MEDIUM, HIGH, CRITICAL)"
    )
    timestamp: float = Field(
        ..., description="Epoch timestamp of the detected beacon event"
    )
    host_id: str = Field(
        ..., description="Identifier of the affected machine (Host node in Neo4j)"
    )
    src_ip: str = Field(
        ..., description="Source IP address of affected host"
    )
    dst_ip: str = Field(
        ..., description="Destination IP address of C2 listener"
    )
    dst_port: int = Field(
        ..., ge=1, le=65535, description="Destination port"
    )
    proto: str = Field(
        "tcp", description="Network protocol"
    )
    service: str = Field(
        "ssl", description="Detected application layer service"
    )
    sni: Optional[str] = Field(
        None, description="TLS Server Name Indication / target domain"
    )
    mitre_technique: str = Field(
        "T1071", description="MITRE ATT&CK technique code"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Calibrated ensemble detection confidence"
    )
    beacon_interval: float = Field(
        ..., ge=0.0, description="Dominant beacon periodicity interval in seconds"
    )
    mean_jitter: float = Field(
        ..., ge=0.0, description="Mean absolute timing jitter in seconds"
    )
    pid: Optional[int] = Field(
        None, description="Originating process PID if endpoint telemetry is available"
    )
    process_name: Optional[str] = Field(
        None, description="Originating binary executable name"
    )

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        return v.upper() if isinstance(v, str) else v


class VerifyEyeAlertInput(BaseModel):
    """Alert emitted by VerifyEye Chrome Extension / Ingress Crawler on phishing detection."""
    source: Literal["verifyeye"] = Field(
        "verifyeye", description="Subsystem that produced the alert"
    )
    event_type: str = Field(
        "phishing_page_detected", description="Classification of threat event"
    )
    severity: str = Field(
        "CRITICAL", description="Analyst triage priority (LOW, MEDIUM, HIGH, CRITICAL)"
    )
    timestamp: float = Field(
        ..., description="Epoch timestamp of the detection event"
    )
    host_id: str = Field(
        ..., description="Identifier of the affected machine (Host node in Neo4j)"
    )
    user: Optional[str] = Field(
        None, description="Account involved (User node in Neo4j)"
    )
    src_ip: Optional[str] = Field(
        None, description="Source IP address of affected host"
    )
    target_url: str = Field(
        ..., description="Full URL of the flagged phishing site"
    )
    domain: str = Field(
        ..., description="Domain being visited (Domain node in Neo4j)"
    )
    action_endpoint: Optional[str] = Field(
        None, description="Form action endpoint where credentials would be sent"
    )
    brand_target: str = Field(
        ..., description="Brand impersonated (e.g. Microsoft 365, Okta)"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Detection confidence score"
    )
    phash_distance: Optional[float] = Field(
        None, description="Perceptual hash hamming distance"
    )
    input_frozen: bool = Field(
        True, description="Whether client-side script blocked form inputs"
    )
    mitre_technique: str = Field(
        "T1566.002", description="MITRE ATT&CK technique code"
    )
    description: str = Field(
        "", description="Human-readable threat summary"
    )
    raw_metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="Additional DOM/browser forensic metadata"
    )

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        return v.upper() if isinstance(v, str) else v


UnifiedAlertInput = Union[VerifyEyeAlertInput, SpectraC2AlertInput]


class AlertIngestResponse(BaseModel):
    """Response returned upon successful receipt and buffering of an alert."""
    status: str = "accepted"
    alert_id: str
    timestamp: float
    buffered_in: Literal["redis", "memory"]
    queue_size: int
