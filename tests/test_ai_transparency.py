"""Unit and integration tests for AI Transparency, Logging, and Traceback Harness."""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(repo_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from ai_transparency import (
    record_ai_call,
    AITraceContext,
    get_transparency_logs,
    get_transparency_trace,
    clear_transparency_logs,
    ai_logs_collection,
)
import ai


@pytest.fixture(autouse=True)
def clean_ai_logs():
    clear_transparency_logs()
    yield
    clear_transparency_logs()


def test_record_ai_call_basic():
    record = record_ai_call(
        trace_id="test-trace-1",
        caller="triage_summary",
        model="llama3.2:1b",
        prompt_data="System prompt and alerts",
        response_content="Phishing surge detected on LAPTOP-10.",
        duration_ms=450.2,
        tokens={"prompt": 55, "completion": 20},
        status="success",
        analyst="analyst@omniguard.io",
    )

    assert record["trace_id"] == "test-trace-1"
    assert record["status"] == "success"
    assert record["duration_ms"] == 450.2
    assert record["tokens"]["prompt_tokens"] == 55
    assert record["tokens"]["completion_tokens"] == 20
    assert record["tokens"]["total_tokens"] == 75
    assert "Phishing surge" in record["response_preview"]
    assert record["error"] is None
    assert record["traceback"] is None


def test_ai_trace_context_success():
    with AITraceContext(caller="chat_analyst", model="llama3.2:1b", analyst="soc_lead") as trace:
        # Simulate work
        trace.set_result(
            content="Host LAPTOP-10 has 3 high severity alerts.",
            tool_calls=[{"tool": "inspect_host", "args": {"hostname": "LAPTOP-10"}}],
            tokens={"prompt": 100, "completion": 30},
        )

    assert trace.status == "success"
    assert trace.duration_ms >= 0.0
    assert len(trace.tool_calls) == 1
    assert trace.tokens["prompt"] == 100

    # Verify document in MongoDB
    saved = get_transparency_trace(trace.trace_id)
    assert saved is not None
    assert saved["caller"] == "chat_analyst"
    assert saved["status"] == "success"
    assert saved["tokens"]["total_tokens"] == 130


def test_ai_trace_context_captures_traceback_on_error():
    captured_trace_id = None

    with pytest.raises(ValueError, match="Simulated model failure"):
        with AITraceContext(caller="soc_agent", model="llama3.2:1b", prompt_data="Check alerts") as trace:
            captured_trace_id = trace.trace_id
            # Raise an unexpected error inside the trace block
            raise ValueError("Simulated model failure")

    assert captured_trace_id is not None
    saved = get_transparency_trace(captured_trace_id)
    assert saved is not None
    assert saved["status"] == "error"
    assert "ValueError: Simulated model failure" in saved["error"]
    assert saved["traceback"] is not None
    assert "raise ValueError(\"Simulated model failure\")" in saved["traceback"]
    assert "test_ai_transparency.py" in saved["traceback"]


def test_run_triage_trace_recording():
    sample_alerts = [
        {"severity": "critical", "source": "verifyeye", "event_type": "phishing", "host": "HOST-A"}
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": "Summary: Phishing attack in progress.\nNext steps: Isolate HOST-A.",
        "prompt_eval_count": 80,
        "eval_count": 25,
    }

    with patch("httpx.post", return_value=mock_resp):
        triage_text = ai.run_triage(sample_alerts, analyst="analyst@omniguard.io")
        assert "Phishing attack in progress" in triage_text

    logs = get_transparency_logs(caller="triage_summary")
    assert len(logs) == 1
    assert logs[0]["status"] == "success"
    assert logs[0]["tokens"]["prompt_tokens"] == 80
    assert logs[0]["tokens"]["completion_tokens"] == 25


def test_run_triage_traceback_on_http_error():
    sample_alerts = [{"severity": "high", "source": "spectrac2", "host": "HOST-B"}]

    with patch("httpx.post", side_effect=Exception("Connection refused to Ollama:11434")):
        with pytest.raises(Exception, match="Connection refused to Ollama:11434"):
            ai.run_triage(sample_alerts)

    logs = get_transparency_logs(caller="triage_summary", status="error")
    assert len(logs) == 1
    assert logs[0]["status"] == "error"
    assert "Connection refused" in logs[0]["error"]
    assert logs[0]["traceback"] is not None
    assert "Connection refused to Ollama:11434" in logs[0]["traceback"]


def test_answer_question_trace_recording():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"content": "There are 2 critical alerts involving HOST-C."},
        "prompt_eval_count": 120,
        "eval_count": 15,
    }

    with patch("httpx.post", return_value=mock_resp):
        ans = ai.answer_question("How many critical alerts?", [{"severity": "critical", "host": "HOST-C"}])
        assert "HOST-C" in ans

    logs = get_transparency_logs(caller="chat_analyst")
    assert len(logs) == 1
    assert logs[0]["status"] == "success"
    assert logs[0]["tokens"]["total_tokens"] == 135


def test_api_transparency_endpoints():
    os.environ.setdefault("NEO4J_PASSWORD", "test_pass")

    with patch("neo4j.GraphDatabase.driver"), \
         patch("pymongo.MongoClient"):
        import main as backend_main
        from main import app
        from fastapi.testclient import TestClient

        app.dependency_overrides[backend_main.current_user] = lambda: {
            "email": "analyst@omniguard.io",
            "name": "SOC Analyst",
            "role": "analyst",
        }

        client = TestClient(app)

        # Record a test trace
        record_ai_call(
            trace_id="api-test-trace-123",
            caller="soc_agent",
            model="llama3.2:1b",
            prompt_data="Inspect alert 42",
            response_content="Alert triaged.",
            duration_ms=120.0,
            status="success",
        )
        record_ai_call(
            trace_id="api-test-trace-error-456",
            caller="soc_agent",
            model="llama3.2:1b",
            prompt_data="Inspect alert 99",
            duration_ms=30.0,
            status="error",
            error="OllamaTimeout: timed out",
            traceback_str="Traceback (most recent call last):\n  File 'agent.py', line 420\nTimeoutError",
        )

        # GET /ai/transparency/logs
        res1 = client.get("/ai/transparency/logs")
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["count"] >= 2
        assert any(t["trace_id"] == "api-test-trace-123" for t in data1["traces"])

        # GET /ai/transparency/logs?status=error
        res_err = client.get("/ai/transparency/logs?status=error")
        assert res_err.status_code == 200
        data_err = res_err.json()
        assert all(t["status"] == "error" for t in data_err["traces"])
        assert any(t["trace_id"] == "api-test-trace-error-456" for t in data_err["traces"])

        # GET /ai/transparency/logs/{trace_id} (success trace)
        res2 = client.get("/ai/transparency/logs/api-test-trace-123")
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["trace_id"] == "api-test-trace-123"
        assert data2["prompt_raw"] == "Inspect alert 42"

        # GET /ai/transparency/logs/{trace_id} (error trace with traceback)
        res3 = client.get("/ai/transparency/logs/api-test-trace-error-456")
        assert res3.status_code == 200
        data3 = res3.json()
        assert data3["status"] == "error"
        assert "TimeoutError" in data3["traceback"]

        # GET /ai/transparency/logs/non-existent
        res4 = client.get("/ai/transparency/logs/does-not-exist")
        assert res4.status_code == 404
