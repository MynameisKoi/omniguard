"""Pydantic schemas for Graph-Triage Core Alert Ingestion."""

from __future__ import annotations

from typing import Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


class SpectraC2AlertInput(BaseModel):
    """Normalized incoming alert emitted by the SpectraC2 beacon detector."""
    source: Literal["spectrac2", "verifyeye", "manual"] = Field(
        "spectrac2", description="Subsystem that produced the alert"
    )
    event_type: str = Field(
        "c2_beacon_detected", description="Classification of threat event"
    )
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        "CRITICAL", description="Analyst triage priority"
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


class AlertIngestResponse(BaseModel):
    """Response returned upon successful receipt and buffering of an alert."""
    status: str = "accepted"
    alert_id: str
    timestamp: float
    buffered_in: Literal["redis", "memory"]
    queue_size: int
