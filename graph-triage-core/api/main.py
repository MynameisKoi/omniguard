"""Graph-Triage Core Microservice API.

Ingests normalized behavioral alerts from SpectraC2, logs the structured payload,
and buffers them in Redis (key: soc:pending_alerts) for downstream Neo4j graph
entity resolution and Ollama LLM triage.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from collections import deque
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

# Ensure graph-triage-core is in sys.path
api_dir = os.path.dirname(os.path.abspath(__file__))
core_dir = os.path.dirname(api_dir)
if core_dir not in sys.path:
    sys.path.insert(0, core_dir)

from api.schemas import SpectraC2AlertInput, AlertIngestResponse

try:
    import redis
    REDIS_INSTALLED = True
except ImportError:
    REDIS_INSTALLED = False
    redis = None  # type: ignore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Graph-Triage-Core] %(message)s",
)
logger = logging.getLogger("GraphTriageCore")

app = FastAPI(
    title="OmniGuard Graph-Triage Core API",
    description="Alert ingestion, Neo4j correlation, and Local LLM Incident Triage Core",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_ALERT_KEY = "soc:pending_alerts"

# In-Memory Fallback Queue (used when Redis is offline or for local testing)
memory_buffer: deque[Dict[str, Any]] = deque(maxlen=1000)
redis_client: Optional[Any] = None
last_redis_fail_time: float = 0.0


def get_redis_client() -> Optional[Any]:
    """Returns a connected Redis client if available, else None."""
    global redis_client, last_redis_fail_time
    if not REDIS_INSTALLED:
        return None
    if redis_client is not None:
        try:
            redis_client.ping()
            return redis_client
        except Exception:
            redis_client = None
            last_redis_fail_time = time.time()

    # Cooldown check: avoid repeating TCP connection timeouts when Redis is offline
    if time.time() - last_redis_fail_time < 5.0:
        return None

    try:
        client = redis.Redis.from_url(
            REDIS_URL,
            socket_timeout=0.2,
            socket_connect_timeout=0.2,
            decode_responses=True,
        )
        client.ping()
        redis_client = client
        logger.info(f"Connected to Redis at {REDIS_URL}")
        return redis_client
    except Exception as exc:
        last_redis_fail_time = time.time()
        logger.debug(f"Redis not available at {REDIS_URL} ({exc}). Using in-memory buffer.")
        redis_client = None
        return None


@app.get("/health")
def health_check() -> Dict[str, Any]:
    """Service health and connection diagnostic."""
    client = get_redis_client()
    redis_connected = client is not None
    pending_count = 0
    if redis_connected and client:
        try:
            pending_count = client.llen(REDIS_ALERT_KEY)
        except Exception:
            pending_count = len(memory_buffer)
    else:
        pending_count = len(memory_buffer)

    return {
        "status": "ok",
        "service": "graph-triage-core",
        "redis_connected": redis_connected,
        "buffer_mode": "redis" if redis_connected else "memory",
        "pending_alerts_count": pending_count,
    }


@app.post("/api/v1/alerts", response_model=AlertIngestResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_alert(alert_input: SpectraC2AlertInput) -> AlertIngestResponse:
    """Ingests, logs, and queues a SpectraC2 beaconing alert for graph resolution."""
    alert_id = str(uuid.uuid4())
    alert_data = alert_input.model_dump()
    alert_data["alert_id"] = alert_id
    alert_data["ingested_at"] = time.time()

    # Log structured alert payload
    logger.warning(
        f"🚨 [INGESTED ALERT] ID: {alert_id} | Host: {alert_data['host_id']} | "
        f"Target: {alert_data.get('sni') or alert_data['dst_ip']}:{alert_data['dst_port']} | "
        f"Severity: {alert_data['severity']} | Conf: {alert_data['confidence']:.1%} | "
        f"Interval: {alert_data['beacon_interval']}s | Jitter: {alert_data['mean_jitter']}s"
    )

    client = get_redis_client()
    buffered_in = "memory"
    queue_size = 0

    if client:
        try:
            client.rpush(REDIS_ALERT_KEY, json.dumps(alert_data))
            queue_size = client.llen(REDIS_ALERT_KEY)
            buffered_in = "redis"
        except Exception as exc:
            logger.warning(f"Redis push failed ({exc}). Buffering in memory.")
            memory_buffer.append(alert_data)
            queue_size = len(memory_buffer)
            buffered_in = "memory"
    else:
        memory_buffer.append(alert_data)
        queue_size = len(memory_buffer)
        buffered_in = "memory"

    return AlertIngestResponse(
        status="accepted",
        alert_id=alert_id,
        timestamp=alert_data["timestamp"],
        buffered_in=buffered_in,
        queue_size=queue_size,
    )


@app.get("/api/v1/alerts")
def get_pending_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves pending alerts from Redis or the in-memory buffer."""
    client = get_redis_client()
    alerts: List[Dict[str, Any]] = []

    if client:
        try:
            raw_items = client.lrange(REDIS_ALERT_KEY, 0, limit - 1)
            for item in raw_items:
                alerts.append(json.loads(item))
            return alerts
        except Exception:
            pass

    # In-memory fallback
    return list(memory_buffer)[:limit]
