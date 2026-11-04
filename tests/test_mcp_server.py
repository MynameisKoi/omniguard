"""Unit tests for the OmniGuard Model Context Protocol (MCP) server."""

import json
import os
import sys
from unittest.mock import MagicMock, patch
import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from mcp_server.server import handle_jsonrpc_message, execute_tool, TOOLS


def test_mcp_initialize():
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    resp = handle_jsonrpc_message(msg)
    assert resp is not None
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "omniguard-soc-mcp"
    assert "tools" in resp["result"]["capabilities"]


def test_mcp_tools_list():
    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    }
    resp = handle_jsonrpc_message(msg)
    assert resp is not None
    assert resp["id"] == 2
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "get_active_alerts" in tool_names
    assert "inspect_host_graph" in tool_names
    assert "isolate_host" in tool_names
    assert "get_system_health" in tool_names


def test_mcp_execute_get_active_alerts():
    mock_client = MagicMock()
    mock_res = MagicMock()
    mock_res.json.return_value = [
        {"alert_id": "a1", "severity": "critical", "host": "HOST-1"},
        {"alert_id": "a2", "severity": "low", "host": "HOST-2"},
    ]
    mock_client.get.return_value = mock_res

    # Test with severity filter
    call_msg = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_active_alerts",
            "arguments": {"severity": "critical", "limit": 10},
        },
    }
    resp = handle_jsonrpc_message(call_msg, client=mock_client)
    assert resp is not None
    assert resp["id"] == 3
    content_text = resp["result"]["content"][0]["text"]
    parsed = json.loads(content_text)
    assert len(parsed) == 1
    assert parsed[0]["alert_id"] == "a1"


def test_mcp_execute_isolate_host():
    mock_client = MagicMock()
    mock_res = MagicMock()
    mock_res.json.return_value = {
        "status": "isolated",
        "host": "WORKSTATION-CORP-01",
        "action": "network_isolation",
    }
    mock_client.post.return_value = mock_res

    call_msg = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "isolate_host",
            "arguments": {"hostname": "WORKSTATION-CORP-01"},
        },
    }
    resp = handle_jsonrpc_message(call_msg, client=mock_client)
    assert resp is not None
    assert resp["id"] == 4
    content_text = resp["result"]["content"][0]["text"]
    parsed = json.loads(content_text)
    assert parsed["status"] == "isolated"
    assert parsed["host"] == "WORKSTATION-CORP-01"


def test_mcp_unknown_method():
    msg = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": "unsupported/method",
    }
    resp = handle_jsonrpc_message(msg)
    assert resp is not None
    assert "error" in resp
    assert resp["error"]["code"] == -32601

