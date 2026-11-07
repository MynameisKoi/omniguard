"""Unit tests for the OmniGuard Model Context Protocol (MCP) server.

The server is a thin wrapper over the backend's shared tool registry
(GET /agent/tools, POST /agent/tools/{name}); the HTTP client is mocked.
"""

import json
import os
import sys
from unittest.mock import MagicMock

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from mcp_server.server import handle_jsonrpc_message, execute_tool, list_tools  # noqa: E402

REGISTRY = [
    {"name": "search_alerts", "description": "Find alerts.", "kind": "read", "render": "alerts",
     "inputSchema": {"type": "object", "properties": {"severity": {"type": "string"}}, "required": []}},
    {"name": "get_host_graph", "description": "Graph around a host.", "kind": "read", "render": "graph",
     "inputSchema": {"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]}},
    {"name": "isolate_host", "description": "Isolate a host.", "kind": "action", "render": "action",
     "inputSchema": {"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]}},
]


def client_returning(post_json=None, get_json=REGISTRY):
    client = MagicMock()
    client.get.return_value = MagicMock(json=MagicMock(return_value=get_json))
    client.post.return_value = MagicMock(json=MagicMock(return_value=post_json))
    return client


def call(name, arguments, client, msg_id=3):
    return handle_jsonrpc_message({"jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments}}, client=client)


def test_mcp_initialize():
    resp = handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                   "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                              "clientInfo": {"name": "test-client", "version": "1.0"}}})
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "omniguard-soc-mcp"
    assert "tools" in resp["result"]["capabilities"]


def test_tools_come_from_the_registry_with_safety_hints():
    client = client_returning()
    resp = handle_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, client=client)
    client.get.assert_called_once_with("/agent/tools")
    tools = {t["name"]: t for t in resp["result"]["tools"]}
    assert set(tools) == {"search_alerts", "get_host_graph", "isolate_host"}
    # MCP hosts ask the user before destructive tools
    assert tools["isolate_host"]["annotations"] == {"readOnlyHint": False, "destructiveHint": True}
    assert tools["search_alerts"]["annotations"]["readOnlyHint"] is True
    assert "kind" not in tools["search_alerts"]   # backend-only fields stay out


def test_call_returns_summary_then_data():
    client = client_returning({"ok": True, "summary": "1 alert(s) match", "data": {"alerts": [{"alert_id": "a1"}]}})
    resp = call("search_alerts", {"severity": "critical"}, client)
    client.post.assert_called_once_with("/agent/tools/search_alerts",
                                        json={"args": {"severity": "critical"}, "approved": True})
    summary, data = resp["result"]["content"]
    assert summary["text"] == "1 alert(s) match"
    assert json.loads(data["text"])["alerts"][0]["alert_id"] == "a1"


def test_old_tool_names_still_work():
    client = client_returning({"ok": True, "summary": "ok", "data": {}})
    for old, new in [("get_active_alerts", "search_alerts"), ("inspect_host_graph", "get_host_graph"),
                     ("get_system_health", "system_status")]:
        client.post.reset_mock()
        call(old, {}, client)
        assert client.post.call_args.args[0] == f"/agent/tools/{new}"


def test_mcp_execute_isolate_host():
    client = client_returning({"ok": True, "summary": "LAPTOP-10 isolation recorded (simulated)",
                               "data": {"status": "isolation_requested", "host": "LAPTOP-10"}})
    resp = call("isolate_host", {"hostname": "LAPTOP-10"}, client, msg_id=4)
    assert resp["id"] == 4
    assert json.loads(resp["result"]["content"][1]["text"])["host"] == "LAPTOP-10"


def test_tool_errors_come_back_as_mcp_errors():
    client = client_returning({"ok": False, "summary": "no host called NOPE in the graph", "data": None})
    resp = call("get_host_graph", {"hostname": "NOPE"}, client)
    assert resp["result"]["isError"] is True
    assert "no host called NOPE" in resp["result"]["content"][0]["text"]


def test_backend_unreachable_on_list():
    client = MagicMock()
    client.get.side_effect = ConnectionError("refused")
    resp = handle_jsonrpc_message({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}, client=client)
    assert resp["error"]["code"] == -32603


def test_mcp_unknown_method():
    resp = handle_jsonrpc_message({"jsonrpc": "2.0", "id": 99, "method": "unsupported/method"})
    assert resp["error"]["code"] == -32601


def test_direct_helpers():
    assert [t["name"] for t in list_tools(client=client_returning())] == ["search_alerts", "get_host_graph", "isolate_host"]
    assert execute_tool("search_alerts", {}, client=client_returning({"ok": True, "summary": "s", "data": 1})) == {"summary": "s", "data": 1}
