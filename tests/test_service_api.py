"""Integration tests for SpectraC2 FastAPI endpoints."""

import sys
import os
import pytest
from fastapi.testclient import TestClient

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
engine_root = os.path.join(repo_root, "spectrac2-engine")
if engine_root not in sys.path:
    sys.path.insert(0, engine_root)

from service.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "spectrac2-engine"
    assert "models" in data


def test_classify_flow_endpoint():
    # 20 packets with periodic 5-second interval
    timestamps = [1700000000.0 + i * 5.0 for i in range(20)]
    payload = {
        "timestamps": timestamps,
        "packet_sizes": [128, 64] * 10,
        "directions": ["fwd", "bwd"] * 10,
        "host": "TEST-ENDPOINT-01",
        "src_ip": "10.10.10.5",
        "dst_ip": "198.51.100.22",
        "domain": "stealth-beacon-c2.com",
    }
    response = client.post("/api/v1/classify-flow", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "is_beacon" in data
    assert "threat_score" in data
    assert "severity" in data
    assert "dominant_period" in data
    assert "model_scores" in data
    assert data["packet_count"] == 20


def test_spectral_analysis_endpoint():
    timestamps = [100.0 + i * 2.5 for i in range(24)]
    payload = {
        "timestamps": timestamps,
        "bin_size": 0.5,
    }
    response = client.post("/api/v1/spectral-analysis", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "dominant_frequency" in data
    assert "dominant_period" in data
    assert "total_power" in data
    assert "spectrum" in data
    assert len(data["spectrum"]) > 0


def test_classify_insufficient_timestamps():
    response = client.post("/api/v1/classify-flow", json={"timestamps": [1.0]})
    assert response.status_code == 400
