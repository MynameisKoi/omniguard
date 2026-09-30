"""SpectraC2 Microservice API

Exposes high-throughput flow classification, FFT spectral analysis, and
alert generation endpoints for the OmniGuard SOC platform.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

current_dir = os.path.dirname(os.path.abspath(__file__))
engine_root = os.path.dirname(current_dir)
if engine_root not in sys.path:
    sys.path.insert(0, engine_root)

from feature_extraction.spectral import SpectralFeatureExtractor

from inference.predictor import SpectraC2Predictor
from service.schemas import (
    FlowInput,
    FlowClassificationResponse,
    SpectralAnalysisRequest,
    SpectralResponse,
)

# Look for trained model checkpoints
models_dir = os.path.join(engine_root, "inference", "models")
lstm_ckpt = os.path.join(models_dir, "spectrac2_lstm.pt")
iso_ckpt = os.path.join(models_dir, "isolation_forest.joblib")

predictor = SpectraC2Predictor(
    lstm_checkpoint=lstm_ckpt if os.path.exists(lstm_ckpt) else None,
    iso_forest_checkpoint=iso_ckpt if os.path.exists(iso_ckpt) else None,
)

app = FastAPI(
    title="OmniGuard SpectraC2 Engine",
    description="Encrypted C2 beacon detection via temporal IAT and FFT/PSD spectral analytics",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "spectrac2-engine",
        "models": {
            "lstm_loaded": predictor.lstm.model is not None,
            "isolation_forest_loaded": predictor.iso_forest is not None and predictor.iso_forest.is_fitted,
        },
    }


@app.post("/api/v1/classify-flow", response_model=FlowClassificationResponse)
def classify_flow(payload: FlowInput) -> FlowClassificationResponse:
    """Evaluates a single network flow for periodic or jittered C2 beaconing."""
    if len(payload.timestamps) < 2:
        raise HTTPException(status_code=400, detail="At least 2 timestamps are required to calculate IAT.")

    meta = {
        "host": payload.host,
        "user": payload.user,
        "src_ip": payload.src_ip,
        "dst_ip": payload.dst_ip,
        "domain": payload.domain,
    }

    result = predictor.analyze_flow(
        timestamps=payload.timestamps,
        packet_sizes=payload.packet_sizes,
        directions=payload.directions,
        flow_metadata=meta,
    )

    spec = result["spectral_metrics"]

    return FlowClassificationResponse(
        is_beacon=result["is_beacon"],
        threat_score=result["threat_score"],
        severity=result["severity"],
        packet_count=result["packet_count"],
        dominant_period=spec["dominant_period"],
        dominant_frequency=spec["dominant_frequency"],
        periodicity_score=spec["periodicity_score"],
        model_scores=result["model_scores"],
        alert=result["alert"],
    )


@app.post("/api/v1/spectral-analysis", response_model=SpectralResponse)
def spectral_analysis(payload: SpectralAnalysisRequest) -> SpectralResponse:
    """Computes Fourier Transform and Power Spectral Density for heatmap visualization."""
    if len(payload.timestamps) < 4:
        raise HTTPException(status_code=400, detail="At least 4 timestamps are required for spectral analysis.")

    extractor = SpectralFeatureExtractor(bin_size=payload.bin_size or 0.5)
    metrics = extractor.compute_fft(payload.timestamps)

    return SpectralResponse(
        dominant_frequency=metrics.dominant_frequency,
        dominant_period=metrics.dominant_period,
        dominant_power=metrics.dominant_power,
        total_power=metrics.total_power,
        peak_to_average_ratio=metrics.peak_to_average_ratio,
        spectral_entropy=metrics.spectral_entropy,
        periodicity_score=metrics.periodicity_score,
        spectrum=[{"frequency": p["frequency"], "power": p["power"]} for p in metrics.spectrum],
    )
