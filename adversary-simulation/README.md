# OmniGuard Adversary Simulation & Live Demo Suite

This directory contains the tools, payloads, and scripts to run a **live, real-time end-to-end intrusion & defense demo** on the OmniGuard SOC platform.

> 📖 **Comprehensive Live Demo Guide:** See [docs/DEMO_GUIDE.md](../docs/DEMO_GUIDE.md) for detailed presenter instructions covering both this 4-Stage Adversary Simulation and the VerifyEye Browser Extension & Local AI Analyst flow.

---

## 🎭 The 4-Stage Attack Narrative

```
[ STAGE 1: INGRESS ] ────────► [ STAGE 2: EGRESS ] ────────► [ STAGE 3: CORRELATION ] ──► [ STAGE 4: CONTAINMENT ]
Flipper Zero BadUSB / Portal    Staged C2 Beaconing Loop        Neo4j Graph & WebSockets     1-Click Host Isolation
- Injects keystrokes / opens    - Initiates HTTP/TLS beacon     - Correlates Host + URL      - EDR network quarantine
  credential harvest portal       with 20-30% timing jitter       + C2 Listener IP             cuts C2 channel & saves
- VerifyEye DOM parser locks    - SpectraC2 FFT flags           - Real-time Cytoscape          enterprise data
  credential dispatch (T1566)     periodicity (T1071)             canvas updates live
```

---

## 📁 Directory Structure

```
adversary-simulation/
├── flipper/
│   ├── badusb_ingress_linux.txt    # DuckyScript for Linux victim workstation
│   ├── badusb_ingress_windows.txt  # DuckyScript for Windows victim workstation
│   ├── badusb_ingress_mac.txt      # DuckyScript for macOS victim workstation
│   └── flipper_guide.md            # How to flash & execute via Flipper Zero
├── portal/
│   ├── mock_portal.py              # Lightweight credential harvest server for VerifyEye demo
│   └── templates/
│       └── login.html              # Spoofed Microsoft 365 SSO login page
├── c2/
│   ├── listener.py                 # Standalone C2 Listener (HTTP/HTTPS) with session logging
│   └── beacon_agent.py             # Emulated implant with configurable jitter (e.g. 10s ± 25%)
├── live_traffic_bridge.py          # Streams live network flow metadata into SpectraC2 / Backend
└── run_live_demo.py                # Automated 1-command orchestrator for stage presentations
```

---

## 🚀 Live Demo Walkthrough (Step-by-Step)

### Step 0: Ensure OmniGuard Services Are Running
In separate terminal tabs (or via `docker-compose up -d mongo neo4j`):

1. **Start Backend API** (Terminal 1):
   ```bash
   cd backend
   source ../.venv/bin/activate
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

2. **Start SpectraC2 Engine** (Terminal 2):
   ```bash
   cd spectrac2-engine
   source ../.venv/bin/activate
   uvicorn service.main:app --host 0.0.0.0 --port 8001 --reload
   ```

3. **Start React SOC Dashboard** (Terminal 3):
   ```bash
   cd frontend
   npm run dev
   ```
   Open `http://localhost:5173` in your browser. Notice the Attack Graph and Alerts feed are live via WebSocket.

---

### Step 1: Stage 1 Ingress (Flipper Zero & VerifyEye)

1. **Start the Mock Phishing Portal** (Terminal 4):
   ```bash
   cd adversary-simulation/portal
   python3 mock_portal.py --port 8080
   ```
   This runs an authentic-looking Microsoft 365 login portal at `http://<your-ip>:8080/login.html` with an external credential harvesting endpoint.

2. **Trigger with Flipper Zero BadUSB**:
   - Copy `adversary-simulation/flipper/badusb_ingress_linux.txt` (or Windows/Mac) to your Flipper Zero's SD card under `badusb/`.
   - Plug Flipper Zero via USB into the victim machine.
   - Run the BadUSB script. It automatically launches the browser to `http://<your-ip>:8080/login.html`.

3. **Run VerifyEye Ingress Inspection**:
   In your terminal (or automated via script):
   ```bash
   python3 verifyeye-ingress/main.py \
     --url http://localhost:8080/login.html \
     --host WORKSTATION-CORP-01 \
     --user maharjan \
     --api http://localhost:8000
   ```
   **What happens:**
   - VerifyEye inspects the DOM, extracts the form target, detects brand impersonation (Microsoft 365), flags `T1566`, and dispatches the alert to `POST /alerts`.
   - Instant WebSocket broadcast pushes the alert to your React Dashboard. The Attack Graph creates the `Host`, `User`, `Domain`, and `URL` nodes.

---

### Step 2: Stage 2 Egress (C2 Listener & Jittered Beacon)

1. **Start the C2 Listener** (Host on your server or test machine):
   ```bash
   python3 adversary-simulation/c2/listener.py --port 8443
   ```

2. **Run the Beaconing Agent** on the victim workstation:
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
   **What happens:**
   - The beacon sends periodic heartbeat requests with 25% randomized jitter (reproducing post-exploitation frameworks like Sliver or Cobalt Strike).
   - As flow packets accumulate, SpectraC2 performs Fast Fourier Transform (FFT) and Power Spectral Density (PSD) analysis.
   - Despite the 25% jitter, SpectraC2 detects the 10.0s dominant harmonic peak, calculates high periodicity confidence, and dispatches a Critical `T1071` alert to the backend.

---

### Step 3 & 4: Stage 3 Correlation & Stage 4 Containment

1. Look at `http://localhost:5173` on the React Dashboard:
   - The Cytoscape attack canvas automatically renders the correlated attack chain:
     `User (maharjan) -> Host (WORKSTATION-CORP-01) -> URL (evil-portal) -> IP (C2-listener)`.
   - The alerts drawer shows both `T1566` (Phishing) and `T1071` (Encrypted C2 Beacon).
2. Click **"Isolate Host"** on `WORKSTATION-CORP-01`:
   - Calls `POST /hosts/WORKSTATION-CORP-01/isolate`.
   - Simulates EDR quarantine, cutting network egress and mitigating the incident.
