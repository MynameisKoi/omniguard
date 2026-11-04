# OmniGuard Model Context Protocol (MCP) Server

The **OmniGuard MCP Server** enables external AI environments—such as **Claude Desktop**, **Cursor**, **Continue**, and **Cody**—to directly interface with the OmniGuard SOC platform.

Security analysts and engineers can investigate active alerts, inspect graph nodes, check pipeline health, and trigger EDR network containment directly from their editor or conversational AI assistant without switching context to the web dashboard.

---

## 🛠️ Exposed MCP Tools

1. **`get_active_alerts`**:
   - Fetches active security telemetry from OmniGuard with optional severity filtering (`low`, `medium`, `high`, `critical`) and result limits.
2. **`inspect_host_graph`**:
   - Queries the Neo4j attack graph for a target hostname (`WORKSTATION-CORP-01`, `LAPTOP-10`), returning connected users, targeted phishing domains, C2 IPs, and flows.
3. **`isolate_host`**:
   - Triggers EDR containment action (`POST /hosts/{hostname}/isolate`), severing network egress to contain lateral movement or C2 exfiltration.
4. **`get_system_health`**:
   - Audits connectivity across the API backend, MongoDB, Neo4j, and local Ollama triage LLM.

---

## ⚙️ Configuration Setup

### 1. Claude Desktop (`claude_desktop_config.json`)
Add the following to your Claude Desktop configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "omniguard-soc": {
      "command": "/usr/bin/python3",
      "args": [
        "/home/koiisme/code/omniguard/mcp_server/server.py"
      ],
      "env": {
        "OMNIGUARD_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

### 2. Cursor IDE (`.cursor/mcp.json`)
Create or edit `.cursor/mcp.json` in your project or home directory:
```json
{
  "mcpServers": {
    "omniguard": {
      "command": "python3",
      "args": ["mcp_server/server.py"],
      "env": {
        "OMNIGUARD_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

---

## 🧪 Testing Locally via CLI

You can test the stdio server directly:
```bash
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}' | python3 mcp_server/server.py
```

