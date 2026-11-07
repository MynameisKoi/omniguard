"""OmniGuard Model Context Protocol (MCP) Server.

Enables AI developer tools and clients (Claude Desktop, Cursor, Continue) to directly
interact with the OmniGuard SOC platform over standard JSON-RPC (stdio transport):
- get_active_alerts: Queries newest alerts with optional severity filtering.
- inspect_host_graph: Inspects attack graph nodes and connections for a hostname.
- isolate_host: Triggers EDR network isolation on a compromised host.
- get_system_health: Audits health status of MongoDB, Neo4j, Ollama, and API backend.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional
import httpx

API_BASE_URL = os.environ.get("OMNIGUARD_API_URL", "http://localhost:8000")
# the backend requires sign-in for alerts / graphs / isolation. machine clients
# use a service token: set the same value in the backend's API_SERVICE_TOKENS
API_TOKEN = os.environ.get("OMNIGUARD_API_TOKEN", "")

# the tools come from the backend's shared registry (backend/tools.py), the
# same list the in-app AI agent uses, so a tool added there appears here too.
# names from the first version of this server still work:
ALIASES = {
    "get_active_alerts": "search_alerts",
    "inspect_host_graph": "get_host_graph",
    "get_system_health": "system_status",
}


def _client(client: Optional[httpx.Client]):
    if client is not None:
        return client, False
    headers = {"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {}
    return httpx.Client(base_url=API_BASE_URL, timeout=30.0, headers=headers), True


def list_tools(client: Optional[httpx.Client] = None) -> List[Dict[str, Any]]:
    """The registry's tools in MCP form. Read tools are marked read-only and
    actions destructive, so MCP hosts (Claude Desktop, Cursor) ask the user
    before running one."""
    client, close = _client(client)
    try:
        res = client.get("/agent/tools")
        res.raise_for_status()
        return [{
            "name": t["name"],
            "description": t["description"],
            "inputSchema": t["inputSchema"],
            "annotations": {"readOnlyHint": t["kind"] == "read", "destructiveHint": t["kind"] == "action"},
        } for t in res.json()]
    finally:
        if close:
            client.close()


def execute_tool(name: str, arguments: Dict[str, Any], client: Optional[httpx.Client] = None) -> Dict[str, Any]:
    """Runs a registry tool through the backend. Actions arrive here only
    after the MCP host asked its user, so they're sent as approved."""
    client, close = _client(client)
    try:
        res = client.post(f"/agent/tools/{ALIASES.get(name, name)}",
                          json={"args": arguments or {}, "approved": True})
        res.raise_for_status()
        out = res.json()
        if not out.get("ok"):
            raise RuntimeError(out.get("summary") or f"tool '{name}' failed")
        return {"summary": out.get("summary", ""), "data": out.get("data")}
    finally:
        if close:
            client.close()


def handle_jsonrpc_message(msg: Dict[str, Any], client: Optional[httpx.Client] = None) -> Optional[Dict[str, Any]]:
    """Handles an individual JSON-RPC 2.0 message."""
    method = msg.get("method")
    msg_id = msg.get("id")

    # Notifications do not return responses
    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                },
                "serverInfo": {
                    "name": "omniguard-soc-mcp",
                    "version": "1.0.0",
                },
            },
        }

    if method == "tools/list":
        try:
            tools = list_tools(client=client)
        except Exception as e:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32603, "message": f"Can't reach the OmniGuard backend: {e}"}}
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": tools,
            },
        }

    if method == "tools/call":
        params = msg.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        try:
            result = execute_tool(tool_name, arguments, client=client)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    # a readable summary for the model, then the full data
                    "content": [
                        {"type": "text", "text": result["summary"]},
                        {"type": "text", "text": json.dumps(result["data"], indent=2, default=str)},
                    ],
                },
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error executing tool '{tool_name}': {e}",
                        }
                    ],
                },
            }

    # Unsupported method
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": -32601,
            "message": f"Method not found: {method}",
        },
    }


def run_stdio_server():
    """Reads JSON-RPC messages from stdin line by line and writes to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            resp = handle_jsonrpc_message(msg)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_server()

