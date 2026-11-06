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

TOOLS = [
    {
        "name": "get_active_alerts",
        "description": "Fetches active security alerts from the OmniGuard SOC backend with optional severity filtering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of alerts to return (default: 20)",
                    "default": 20,
                },
                "severity": {
                    "type": "string",
                    "description": "Optional filter by severity: low, medium, high, critical",
                    "enum": ["low", "medium", "high", "critical"],
                },
            },
        },
    },
    {
        "name": "inspect_host_graph",
        "description": "Queries the Neo4j/SOC attack graph for an individual host, returning connected users, domains, IPs, and flows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "The exact hostname of the target machine (e.g. WORKSTATION-CORP-01, LAPTOP-10)",
                },
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "isolate_host",
        "description": "Executes an immediate EDR network containment action, isolating the host from the corporate network.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "The exact hostname to isolate at the network layer",
                },
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "get_system_health",
        "description": "Checks the live connectivity status of the backend API, MongoDB, Neo4j, and Ollama triage model.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def execute_tool(name: str, arguments: Dict[str, Any], client: Optional[httpx.Client] = None) -> Any:
    """Dispatches tool execution against the OmniGuard SOC REST API."""
    should_close = False
    if client is None:
        headers = {"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {}
        client = httpx.Client(base_url=API_BASE_URL, timeout=10.0, headers=headers)
        should_close = True

    try:
        if name == "get_active_alerts":
            res = client.get("/alerts")
            res.raise_for_status()
            alerts = res.json()

            severity = arguments.get("severity")
            if severity:
                alerts = [a for a in alerts if a.get("severity") == severity]

            limit = arguments.get("limit", 20)
            return alerts[:limit]

        elif name == "inspect_host_graph":
            hostname = arguments["hostname"]
            res = client.get(f"/graph/host/{hostname}")
            res.raise_for_status()
            return res.json()

        elif name == "isolate_host":
            hostname = arguments["hostname"]
            res = client.post(f"/hosts/{hostname}/isolate")
            res.raise_for_status()
            return res.json()

        elif name == "get_system_health":
            res = client.get("/status")
            res.raise_for_status()
            return res.json()

        else:
            raise ValueError(f"Unknown tool: '{name}'")
    finally:
        if should_close:
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
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": TOOLS,
            },
        }

    if method == "tools/call":
        params = msg.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        try:
            result_data = execute_tool(tool_name, arguments, client=client)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result_data, indent=2),
                        }
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
