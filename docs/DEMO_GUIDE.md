# OmniGuard SOC — Live Demonstration Guide

This guide provides complete, step-by-step instructions for demonstrating the two primary defensive capabilities of the **OmniGuard SOC Platform**:

- **[Demo Flow 1: Interactive Browser Extension & Local AI Analyst](#-demo-flow-1-interactive-browser-extension--local-ai-analyst)**
  *Focus: Real-time client-side phishing interception, surgical form freezing, fake OAuth popup traps, live health telemetry, and zero-cloud-egress AI triage with Ollama.*
- **[Demo Flow 2: 4-Stage Adversary Simulation & Incident Containment](#-demo-flow-2-4-stage-adversary-simulation--soc-containment)**
  *Focus: End-to-end multi-vector intrusion narrative — from initial ingress (Flipper Zero / Mock Portal) to jittered encrypted C2 beaconing (SpectraC2 FFT engine), Neo4j multi-entity graph correlation, and 1-click EDR host quarantine.*

---

## 🛠️ Global Prerequisites & Baseline Setup

Before presenting either demo, ensure the foundational infrastructure is running.

### 1. Start Database Stores (Docker)
In your terminal, launch MongoDB and Neo4j containers:
```bash
docker compose up -d mongo neo4j
```
*Verify they are up:*
- MongoDB: `localhost:27017`
- Neo4j Web Browser: `http://localhost:7474` (User: `neo4j`, Password in `.env` e.g. `test_password_secret`)

### 2. Start OmniGuard Backend API
In a new terminal:
```bash
source .venv/bin/activate
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
*Verify:* Open `http://localhost:8000/health` (returns `{"status":"ok"}`) or `http://localhost:8000/docs`.

### 3. Start React SOC Dashboard
In another terminal:
```bash
cd frontend
npm run dev
```
*Verify:* Open `http://localhost:5173` in Google Chrome.

### 4. (Optional for AI Triage) Start Local Ollama
To demonstrate the on-device AI Analyst without cloud egress:
```bash
ollama run llama3.2:3b
```
*(Keep running in the background at `http://localhost:11434`)*

---

## 🌐 Demo Flow 1: Interactive Browser Extension & Local AI Analyst

```
┌────────────────────────┐      ┌───────────────────────────┐      ┌─────────────────────────┐      ┌───────────────────────┐
│ Fake Phishing Targets  │ ───► │ VerifyEye MV3 Extension   │ ───► │ Live React Dashboard    │ ───► │ Local AI Analyst      │
│ Ports 5500–6100        │      │ - Surgical form freeze    │      │ - Live WebSocket feed   │      │ - Ollama (llama3.2:3b)│
│ (Claude, Netflix, etc.)│      │ - Fake OAuth popup trap   │      │ - Real-time system /status│   │ - Auto SOC briefing   │
└────────────────────────┘      └───────────────────────────┘      └─────────────────────────┘      └───────────────────────┘
```

### Purpose & Talking Points
Traditional defenses (DNS blocklists, domain reputation) have a 12–48 hour lag, leaving organizations vulnerable to zero-hour credential lures. **VerifyEye** runs directly in the client browser, detecting visual brand impersonation on unverified domains, executing surgical DOM freezes, and streaming alerts to the SOC.

---

### Step-by-Step Execution

#### Step 1: Launch the Phishing Targets Suite
From the repository root, start the local phishing fixtures:
```bash
./fake_sites/serve.sh
```
**What to explain to the audience:**
> *"We are spinning up isolated local replicas of popular services (Claude, Netflix, TikTok, Amazon, Apple, and a counterfeit Google OAuth popup). None of these touch external networks — they serve as live test targets for our client-side detector."*

Port assignments:
- `http://localhost:5500`: Claude / Anthropic replica (with OAuth trigger)
- `http://localhost:5700`: Fake Google OAuth popup window
- `http://localhost:5800`: Netflix login replica
- `http://localhost:6000`: Amazon login replica
- `http://localhost:5600`: SPA late-injected Google form

---

#### Step 2: Load the VerifyEye Extension into Chrome
1. In Google Chrome, navigate to: `chrome://extensions/`
2. In the top-right corner, switch on **Developer mode**.
3. Click **Load unpacked** (top-left).
4. Browse to and select the directory:
   ```
   /home/koiisme/code/omniguard/verifyeye-ingress/extension
   ```
5. Confirm that **VerifyEye — Zero-Hour Phishing Guard** appears in your active extensions.

---

#### Step 3: Demonstrate Surgical Form Freeze (Inline Detection)
1. Open a new tab and navigate to: `http://localhost:5800` (Netflix fixture) or `http://localhost:5500` (Claude fixture).
2. **Observe the immediate DOM freeze:**
   - The email/password input fields are grayed out and locked (`disabled`).
   - The submit button displays a red locked shield indicator.
   - A warning banner appears explaining brand impersonation was detected on `localhost`.
3. **Highlight "Surgical Freeze":**
   - Type in the inputs — inputs are rejected.
   - Emphasize that legitimate non-credential navigation remains active while credential dispatch is blocked.

---

#### Step 4: Demonstrate the Fake OAuth Popup Interception
1. On `http://localhost:5500` (Claude fixture), look for the button: **"Continue with Google"**.
2. Click the button.
3. A popup window opens pointing to `http://localhost:5700` (a high-fidelity replica of Google Accounts sign-in).
4. **Observe the popup trap:**
   - The instant the popup spawns, VerifyEye inspects its origin, detects Google brand markers outside `google.com`, and **freezes the popup inputs before the user can type a single keystroke**.
   - Network exfiltration rules (`declarativeNetRequest`) immediately block outgoing POST requests.

---

#### Step 5: Demonstrate Single-Page App (SPA) Dynamic Injection
1. Navigate to: `http://localhost:5600` (`spa-test`).
2. This page loads blank and injects a login form dynamically after a 2-second JavaScript delay (common in modern Single Page Apps or Reddit-style comment lures).
3. **Observe:** VerifyEye’s `MutationObserver` catches the element the millisecond it is attached to the DOM and instantly neutralizes it.

---

#### Step 6: Verify Real-Time Dashboard Ingestion
1. Switch to the tab with the **React Dashboard** (`http://localhost:5173`).
2. **Show Live System Status:**
   - In the left sidebar or top overview, note the **System Status** panel.
   - It actively polls `/status`, showing green indicators for **Backend API**, **MongoDB**, **Neo4j**, and **AI Analysis**.
3. **Show Alerts Stream:**
   - Navigate to the **Alerts** tab.
   - The VerifyEye alerts appear at the very top (sorted newest-first), displaying:
     - `Source: verifyeye`
     - `Event: phishing_page_detected`
     - `Severity: high` / `critical`
     - `Brand Target: Google / Netflix / Claude`
     - `Target URL: http://localhost:5500...`

---

#### Step 7: Trigger the Local AI SOC Analyst Briefing
1. On the dashboard, navigate back to the **Overview** page.
2. Locate the **AI Analyst** panel (`llama3.2:3b · runs locally`).
3. Click the **"Generate briefing"** button.
4. **What to explain while it loads:**
   > *"Rather than shipping sensitive enterprise telemetry to an external cloud LLM (which violates compliance and risks data leaks), our backend routes the 50 most recent alerts through an on-premises Ollama instance."*
5. Once generated, point out the two markdown sections:
   - **1. Summary**: Concise 2-3 sentence overview of ongoing credential-harvesting patterns and impacted hosts.
   - **2. Next Steps**: Actionable, prioritized containment directives for the incident response team.

---

#### Step 8: Clean Up Flow 1
Stop the test sites when done:
```bash
./fake_sites/serve.sh stop
```

---

## 🛡️ Demo Flow 2: 4-Stage Adversary Simulation & SOC Containment

```
[ STAGE 1: INGRESS ] ────────► [ STAGE 2: EGRESS ] ────────► [ STAGE 3: CORRELATION ] ──► [ STAGE 4: CONTAINMENT ]
Flipper Zero / Mock Portal      Jittered C2 Beacon Loop         Neo4j Graph & WebSockets     1-Click EDR Host Isolation
- Workstation directed to       - Implant beacons with 25%      - Correlates Host + User     - Immediate network isolation
  credential harvester portal     randomized timing jitter        + Target URL + C2 IP         cuts C2 channel & saves host
- VerifyEye logs T1566          - SpectraC2 FFT flags T1071     - Cytoscape multi-entity     - Incident triaged
```

### Purpose & Talking Points
Demonstrates how OmniGuard breaks down the silos between disparate attack vectors. An adversary attempts credential access, establishes an encrypted C2 reverse shell using jitter to evade rule-based firewalls, but is automatically correlated in Neo4j and contained with one click.

---

### Option A: The 1-Command Automated Walkthrough (Recommended for Presentations)

For live presentations where you want zero terminal juggling, use the automated scenario orchestrator:

1. Open your terminal in the repository root:
   ```bash
   source .venv/bin/activate
   python3 adversary-simulation/run_live_demo.py
   ```
2. The orchestrator checks core service health and prompts:
   - `[Press Enter to launch Mock Phishing Portal & trigger VerifyEye inspection...]`
     *(Executes Stage 1 Ingress, dispatches `T1566` to Backend, updates Dashboard)*
   - `[Press Enter to start C2 Listener & execute Jittered Beacon Agent...]`
     *(Spawns C2 Listener, sends 10 jittered beacon pulses, invokes SpectraC2 FFT detection, dispatches Critical `T1071`)*
   - Displays retrieved Neo4j multi-relational graph topology in terminal:
     `User (maharjan) ──► Host (WORKSTATION-CORP-01) ──► URL ──► C2 IP`
   - `[Press Enter to execute 1-Click Host Isolation...]`
     *(Calls `/hosts/WORKSTATION-CORP-01/isolate` and confirms containment)*
3. Keep the React Dashboard (`http://localhost:5173`) visible on a split screen to watch the canvas and alerts update dynamically!

---

### Option B: The Detailed Step-by-Step Manual Demo

Use this option if presenting technical subsystem mechanics in detail.

#### Stage 1: Ingress & Credential Harvester Interception
1. Start the mock enterprise portal in a terminal:
   ```bash
   python3 adversary-simulation/portal/mock_portal.py --port 8080
   ```
   *(Serves a spoofed Microsoft 365 login page at `http://localhost:8080/login.html`)*
2. *(Optional Hardware Demonstration)*: If demonstrating with a physical **Flipper Zero**:
   - Plug the Flipper Zero into the test laptop.
   - Run `badusb_ingress_linux.txt` (or Windows) from the BadUSB menu.
   - Watch the Flipper simulate keystrokes to launch the browser straight to the portal.
3. Run the VerifyEye Ingress inspector:
   ```bash
   python3 verifyeye-ingress/main.py \
     --url http://127.0.0.1:8080/login.html \
     --host WORKSTATION-CORP-01 \
     --user maharjan \
     --api http://localhost:8000
   ```
4. **Dashboard Check:**
   - Look at `http://localhost:5173`.
   - Alert `T1566: Phishing Page Detected` appears in real time.
   - In Neo4j, `Host: WORKSTATION-CORP-01`, `User: maharjan`, and `URL: http://127.0.0.1:8080/login.html` nodes are created.

---

#### Stage 2: Post-Exploitation Egress (Jitter-Invariant C2 Beaconing)
1. Start the external Command & Control Listener (simulating an adversary's C2 server):
   ```bash
   python3 adversary-simulation/c2/listener.py --port 8443
   ```
2. Start the **SpectraC2 Engine** (if running separately from docker):
   ```bash
   cd spectrac2-engine
   source ../.venv/bin/activate
   uvicorn service.main:app --host 0.0.0.0 --port 8001 --reload
   ```
3. Run the emulated C2 Beacon Implant on the victim workstation:
   ```bash
   python3 adversary-simulation/c2/beacon_agent.py \
     --server http://localhost:8443 \
     --host WORKSTATION-CORP-01 \
     --user maharjan \
     --interval 10.0 \
     --jitter 0.25 \
     --forward-to-spectrac2 http://localhost:8001 \
     --forward-to-backend http://localhost:8000
   ```
4. **What to explain to the audience:**
   > *"The implant introduces 25% randomized jitter (each beacon varies between 7.5s and 12.5s). Traditional firewall rules looking for exact 10s intervals miss this completely. SpectraC2 uses Fast Fourier Transform (FFT) and Power Spectral Density (PSD) analysis across flow inter-arrival times, isolating the true 10.0s harmonic peak through the noise."*
5. **Dashboard Check:**
   - SpectraC2 pushes alert `T1071: C2 Beacon Detected (Confidence: 94%, Period: 10.0s, Jitter: 25%)`.

---

#### Stage 3: Neo4j Graph Correlation
1. On the React Dashboard, click into the **Graph** view or select `WORKSTATION-CORP-01`.
2. **Observe the Cytoscape Attack Canvas:**
   - Rather than isolated table rows, the graph correlates the entire incident:
     ```
     [User: maharjan]
            │
            ▼ (LOGGED_INTO)
     [Host: WORKSTATION-CORP-01] ────(ACCESSED_URL)────► [URL: mock-portal:8080]
            │
            ▼ (INITIATED_FLOW)
     [IP: 127.0.0.1:8443 (C2 Listener)]
     ```
   - Two completely independent detection systems (VerifyEye in the browser and SpectraC2 on the wire) merge seamlessly around the single compromised host.

---

#### Stage 4: 1-Click Incident Containment & EDR Quarantine
1. On the dashboard alert detail panel for `WORKSTATION-CORP-01`, click the **"Isolate Host"** action button.
   *(Or test via CLI: `curl -X POST http://localhost:8000/hosts/WORKSTATION-CORP-01/isolate`)*
2. **Observe the response:**
   - Status transitions to `202 Accepted` / `"isolated"`.
   - Message confirms: `Host 'WORKSTATION-CORP-01' successfully isolated from the corporate network.`
   - In the beacon agent terminal, observe the connection severed.
   - The intrusion chain is neutralized.

---

## ⚡ Quick Troubleshooting Cheat Sheet

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **Status panel shows red dots for Mongo or Neo4j** | Containers not running or bad credentials | Run `docker compose up -d mongo neo4j`. Check `NEO4J_PASSWORD` in `backend/.env`. |
| **AI Analyst says "Couldn't reach the model"** | Ollama not running locally | Run `ollama run llama3.2:3b` in a terminal. Check `curl http://localhost:11434/api/tags`. |
| **VerifyEye extension doesn't freeze fake sites** | Extension not loaded or ID mismatch | Reload extension at `chrome://extensions/`. Ensure backend CORS has `chrome-extension://.*`. |
| **Fake site ports already in use** | Stray Python servers from previous run | Run `./fake_sites/serve.sh stop` or kill ports: `lsof -ti :5500,:5700,:5800 \| xargs kill -9`. |
| **WebSocket live feed disconnected** | Backend restarted while dashboard open | Refresh dashboard browser tab (`Cmd/Ctrl + R`). |
