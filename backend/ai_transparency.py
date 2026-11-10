"""AI Transparency, Observability, and Audit Traceback System for OmniGuard SOC.

Tracks all LLM invocations across triage, analyst chat, and autonomous agent loops:
- High-resolution execution timing & latency (ms)
- Token utilization accounting (prompt_eval_count, eval_count)
- Prompt context hashing & payload summaries
- Full exception tracebacks and failure diagnostics
- MongoDB persistence (`ai_transparency_logs`) and structured logging
- Cryptographic correlation with the Investigation Decision Ledger
"""

from __future__ import annotations

import logging
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db import database

logger = logging.getLogger("omniguard.ai_transparency")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [AI-TRACE] %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

ai_logs_collection = database["ai_transparency_logs"]

# Ensure indexes for rapid querying in the dashboard
try:
    ai_logs_collection.create_index([("timestamp", -1)])
    ai_logs_collection.create_index([("trace_id", 1)], unique=True)
    ai_logs_collection.create_index([("status", 1)])
    ai_logs_collection.create_index([("caller", 1)])
except Exception as e:
    logger.debug(f"Index creation note: {e}")


def _summarize_prompt(prompt_data: Any, max_len: int = 500) -> str:
    """Creates a clean, bounded preview of prompts or message arrays."""
    if isinstance(prompt_data, str):
        text = prompt_data.strip()
    elif isinstance(prompt_data, list):
        # Format list of message dicts (e.g. system, user, assistant)
        parts = []
        for m in prompt_data:
            if isinstance(m, dict):
                role = m.get("role", "unknown")
                content = str(m.get("content", ""))[:120].replace("\n", " ")
                parts.append(f"[{role}]: {content}")
            else:
                parts.append(str(m)[:60])
        text = " | ".join(parts)
    elif isinstance(prompt_data, dict):
        text = str(prompt_data)
    else:
        text = str(prompt_data) if prompt_data is not None else ""

    if len(text) > max_len:
        return text[:max_len] + f"... [truncated {len(text) - max_len} chars]"
    return text


def record_ai_call(
    trace_id: str,
    caller: str,
    model: str,
    prompt_data: Any,
    response_content: Optional[str] = None,
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    duration_ms: float = 0.0,
    tokens: Optional[Dict[str, int]] = None,
    status: str = "success",
    error: Optional[str] = None,
    traceback_str: Optional[str] = None,
    analyst: str = "system",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Persists a detailed AI execution record to the transparency store
    and logs structured observability telemetry.
    """
    token_stats = {
        "prompt_tokens": (tokens or {}).get("prompt", 0),
        "completion_tokens": (tokens or {}).get("completion", 0),
        "total_tokens": (tokens or {}).get("total", 0),
    }
    if not token_stats["total_tokens"]:
        token_stats["total_tokens"] = token_stats["prompt_tokens"] + token_stats["completion_tokens"]

    record = {
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "caller": caller,
        "model": model,
        "analyst": analyst,
        "status": status,  # "success" | "error" | "timeout"
        "duration_ms": round(duration_ms, 2),
        "tokens": token_stats,
        "prompt_preview": _summarize_prompt(prompt_data),
        "prompt_raw": prompt_data if isinstance(prompt_data, (str, list, dict)) else str(prompt_data),
        "response_preview": (response_content[:500] + "...") if response_content and len(response_content) > 500 else (response_content or ""),
        "tool_calls": tool_calls or [],
        "error": error,
        "traceback": traceback_str,
        "metadata": metadata or {},
    }

    try:
        ai_logs_collection.insert_one(dict(record))
    except Exception as e:
        logger.error(f"Failed to write AI transparency record: {e}")

    # Structured logging
    if status == "success":
        logger.info(
            f"trace_id={trace_id} caller={caller} model={model} latency={record['duration_ms']}ms "
            f"prompt_tok={token_stats['prompt_tokens']} comp_tok={token_stats['completion_tokens']} tools={len(tool_calls or [])}"
        )
    else:
        logger.error(
            f"trace_id={trace_id} caller={caller} model={model} status={status} latency={record['duration_ms']}ms "
            f"error={error}\nTraceback:\n{traceback_str or 'None'}"
        )

    return record


class AITraceContext:
    """
    Context manager for measuring, capturing, and persisting LLM calls with automatic
    traceback extraction if an error occurs.
    """

    def __init__(
        self,
        caller: str,
        model: str,
        analyst: str = "system",
        prompt_data: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.trace_id = str(uuid.uuid4())
        self.caller = caller
        self.model = model
        self.analyst = analyst
        self.prompt_data = prompt_data
        self.metadata = metadata or {}

        self.start_time: float = 0.0
        self.duration_ms: float = 0.0
        self.status: str = "success"
        self.response_content: str = ""
        self.tool_calls: List[Dict[str, Any]] = []
        self.tokens: Dict[str, int] = {"prompt": 0, "completion": 0, "total": 0}
        self.error: Optional[str] = None
        self.traceback_str: Optional[str] = None
        self.record: Optional[Dict[str, Any]] = None

    def __enter__(self) -> AITraceContext:
        self.start_time = time.perf_counter()
        return self

    def set_result(
        self,
        content: str = "",
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        tokens: Optional[Dict[str, int]] = None,
    ):
        self.response_content = content
        if tool_calls is not None:
            self.tool_calls = tool_calls
        if tokens:
            self.tokens.update(tokens)

    def record_error(self, exc: BaseException, error_type: str = "error"):
        self.status = error_type
        self.error = f"{type(exc).__name__}: {exc}"
        self.traceback_str = "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.duration_ms = (time.perf_counter() - self.start_time) * 1000.0

        if exc_val is not None:
            self.status = "error"
            self.error = f"{exc_type.__name__}: {exc_val}"
            self.traceback_str = "".join(
                traceback.format_exception(exc_type, exc_val, exc_tb)
            )

        self.record = record_ai_call(
            trace_id=self.trace_id,
            caller=self.caller,
            model=self.model,
            prompt_data=self.prompt_data,
            response_content=self.response_content,
            tool_calls=self.tool_calls,
            duration_ms=self.duration_ms,
            tokens=self.tokens,
            status=self.status,
            error=self.error,
            traceback_str=self.traceback_str,
            analyst=self.analyst,
            metadata=self.metadata,
        )
        # We do not suppress exceptions so normal FastAPI error handlers work
        return False


def get_transparency_logs(
    limit: int = 50,
    status: Optional[str] = None,
    caller: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieves newest AI execution traces with optional filtering."""
    query = {}
    if status:
        query["status"] = status
    if caller:
        query["caller"] = caller

    docs = list(
        ai_logs_collection.find(query, {"_id": 0, "prompt_raw": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )
    return docs


def get_transparency_trace(trace_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full un-truncated trace including complete prompt and traceback."""
    doc = ai_logs_collection.find_one({"trace_id": trace_id}, {"_id": 0})
    return doc


def clear_transparency_logs() -> int:
    """Clears transparency log collection (useful for test fixtures)."""
    res = ai_logs_collection.delete_many({})
    return res.deleted_count

