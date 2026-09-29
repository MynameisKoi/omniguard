"""Pydantic schemas for SpectraC2 API endpoints."""

from __future__ import annotations

from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field


class FlowInput(BaseModel):
    """Input payload representing a network flow session."""
    timestamps: List[float] = Field(
        ...,
        description="Sequential packet arrival epoch timestamps in seconds",
        examples=[[1700000000.0, 1700000010.1, 1700000020.2, 1700000030.05]],
    )
    packet_sizes: Optional[List[int]] = Field(
        None,
        description="Packet payload sizes in bytes",
        examples=[[128, 64, 128, 64]],
    )
    directions: Optional[List[Literal["fwd", "bwd"]]] = Field(
        None,
        description="Direction of each packet relative to the monitored host",
        examples=[["fwd", "bwd", "fwd", "bwd"]],
    )
    host: Optional[str] = Field("UNKNOWN-HOST", description="Originating hostname")
    user: Optional[str] = Field(None, description="Associated user context if available")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address (listener)")
    domain: Optional[str] = Field(None, description="Resolved domain if available")


class SpectralAnalysisRequest(BaseModel):
    """Request for detailed frequency-domain analysis and visualization data."""
    timestamps: List[float] = Field(..., description="Array of packet arrival timestamps")
    bin_size: Optional[float] = Field(0.5, description="Time bin resolution in seconds")


class SpectrumPoint(BaseModel):
    frequency: float
    power: float


class SpectralResponse(BaseModel):
    dominant_frequency: float
    dominant_period: float
    dominant_power: float
    total_power: float
    peak_to_average_ratio: float
    spectral_entropy: float
    periodicity_score: float
    spectrum: List[SpectrumPoint]


class FlowClassificationResponse(BaseModel):
    """Response containing behavioral analysis, model outputs, and optional alert."""
    is_beacon: bool
    threat_score: float
    severity: Literal["low", "medium", "high", "critical"]
    packet_count: int
    dominant_period: float
    dominant_frequency: float
    periodicity_score: float
    model_scores: Dict[str, float]
    alert: Optional[Dict[str, Any]] = None
