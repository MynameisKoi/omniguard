# OmniGuard SOC — Live Closed-Network Demo Flow

This guide walks through the end-to-end **Attack → Detect → Investigate → Quarantine & Recover** live demo on a closed Wi-Fi hotspot using your real hardware.

---

## 1. Machine Roles & Network Topology

Run everything on **Khoi's Windows Hotspot** (closed LAN, no campus firewall blocking ports).

| Role | Machine | What Runs There |
| :--- | :--- | :--- |
| **Attacker / C2 + LLM Host** | **Windows Laptop** | • Ollama (`llama3.2:3b` on `:11434`)<br>• Mock Phishing & Fake CAPTCHA Portal (`mock_portal.py` on `:8080`)<br>• C2 Listener (`adversary-simulation/c2/listener.py` on `:9000` / `:4444`) |
| **Analyst / SOC Core** | **Debian VM** *(Bridged to Hotspot)* | • MongoDB (`:27017`) + Neo4j (`:7687`)<br>• OmniGuard Backend (`:8000`) + Frontend (`:5173`)<br>• VerifyEye (`:8001`) + SpectraC2 (`:8002`)<br>• Flipper Zero USB (`demo/flipper_badge_bridge.py`) |
| **Victim Endpoint** | **Kali / Raspberry Pi / Laptop** | • Browser with **VerifyEye Extension** pointed at `http://<SOC_IP>:8000`<br>• `demo/containment_agent.py` (run with `sudo` or Admin PowerShell) |
| **Analyst Mobile** | **Phone** *(on Hotspot)* | • `ntfy` app (or Telegram) subscribed to alert notifications<br>• Mobile browser pointed at `http://<SOC_IP>:5173` |

> **Important VirtualBox Check:** Set the Debian VM network adapter to **Bridged** on the hotspot (or forward ports `8000` and `5173` in NAT) so the Victim and Phone can reach the SOC.

---

## 2. Pre-Demo Setup (2 Minutes Before Presenting)

### A. On Debian VM (Analyst SOC)
1. Make sure port `8000` is free (`pkill -f uvicorn` if another app is on `8000`), then verify readiness:
   ```bash
   cd /home/koiisme/code/omniguard
   ./.venv/bin/python demo/check_demo_ready.py
   ```
2. Optional phone push notifications (set in `backend/.env` or export before starting `uvicorn`):
   ```bash
   export NTFY_TOPIC="omniguard-demo-soc"
   export DASHBOARD_PUBLIC_URL="http://<SOC_IP>:5173"
   ```
3. Start the SOC services in separate terminals:
   ```bash
   # Terminal 1: Backend API
   cd /home/koiisme/code/omniguard/backend && ../.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000

   # Terminal 2: Frontend Dashboard
   cd /home/koiisme/code/omniguard/frontend && npm run dev -- --host 0.0.0.0

   # Terminal 3: Flipper Zero 1-Tap Login Bridge (keep Flipper on Home screen)
   cd /home/koiisme/code/omniguard && ./.venv/bin/python demo/flipper_badge_bridge.py
   ```

### B. On Windows Host (Attacker / C2)
```powershell
# Terminal 1: Fake M365 Login + Fake CAPTCHA (ClickFix) Portal
python adversary-simulation\portal\mock_portal.py --port 8080 --demo-cmd "python3 demo/beacon_sim.py --host kali-victim"

# Terminal 2: C2 Listener (or nc -lvnp 4444)
python adversary-simulation\c2\listener.py --port 9000
```

### C. On Victim Machine (Kali / Pi / Teammate Laptop)
Set `ANALYST_IP` and `HOST` in environment (or edit top of `demo/containment_agent.py`):
```bash
export ANALYST_IP="<SOC_IP>"
export HOST="kali-victim"
export C2_IP="<WINDOWS_C2_IP>"
sudo -E python3 demo/containment_agent.py
```
*(Verify in the OmniGuard dashboard that `kali-victim` shows **agent online**.)*

---

## 3. Live 4-Act Demo Script (~5 Minutes)

### Act 1 — Physical 1-Tap Sign-In (30 sec)
1. Open `http://localhost:5173` on Debian → click **🐬 Flipper Zero / NFC**.
2. Tap your **HID H10301 (`FC: 46, Card: 46966` / `2E B7 76`)** card onto the back of the Flipper Zero.
   *(Backup if USB bridge isn't running: run **BadUSB → `omniguard_login.txt`** on the Flipper.)*
3. **Talk Track:** *"Analysts sign in passwordlessly with a physical badge tap, and OmniGuard immediately logs `BADGE_TAP_LOGIN` to our SHA-256 tamper-evident Decision Ledger."*

### Act 2 — Phishing Portal & Fake CAPTCHA Lure (90 sec)
1. On the Victim browser, open `http://<WINDOWS_C2_IP>:8080/login.html` (fake Microsoft 365 portal) or `http://<WINDOWS_C2_IP>:8080/captcha` (Fake CAPTCHA / ClickFix lure).
2. **VerifyEye Extension** flags/blocks the page and triggers **VerifyEye Service** to capture a live screenshot into OmniGuard.
3. Click the new alert in OmniGuard → show the **VerifyEye Screenshot Evidence** panel.
4. **Talk Track:** *"Even zero-hour fake portals and ClickFix CAPTCHA lures are caught by DOM + brand scoring, with live sandboxed screenshot proof attached to the alert."*

### Act 3 — C2 Reverse Shell / Beacon + Correlation + Phone Alert (90 sec)
1. On the Victim, click **"I am not a robot"** on `/captcha` (copies the command) and paste/run it in a terminal (or plug Flipper Zero into Victim and run **BadUSB → `omniguard_clickfix_demo.txt`**):
   ```bash
   python3 demo/beacon_sim.py --host kali-victim
   ```
2. **SpectraC2** detects the periodic C2 beaconing → OmniGuard correlates the VerifyEye phishing alert + SpectraC2 C2 alert on the **Neo4j Attack Graph** under `kali-victim`.
3. **Live AI** auto-reviews the alert and pushes a **Phone Notification** (`ntfy` / Telegram) to your phone.
4. **Talk Track:** *"Now two independent engines agree `kali-victim` is compromised. Live AI flags it immediately and alerts the on-call analyst's phone without auto-executing anything."*

### Act 4 — AI Investigation, Live DFIR & One-Click Quarantine (90 sec)
1. Open **Ask AI** → ask: *"Investigate kali-victim and check its DFIR snapshot"* (highlight **AI Transparency** logs showing latency, tokens, and tool calls).
2. On the `kali-victim` alert, click **Collect DFIR** → click **Inspect** to show the flagged `beacon_sim.py` PID and C2 socket.
3. Click **Quarantine & Kill** (or **Isolate host**).
   - `demo/containment_agent.py` blocks internet + drops same-subnet C2 traffic (`OmniGuard-BlockC2` / `iptables`) + **kills the suspicious beacon/shell PID**.
   - Show the Victim losing internet (`ping 8.8.8.8` fails) and the C2 process terminating immediately, while SOC `:8000` stays connected.
4. Click **Verify Ledger Integrity** (tamper-evident SHA-256 chain verified) and finally click **Release** to restore the Victim's network cleanly.

---

## 4. Quick Recovery Commands (If Needed During Demo)
* **Force-restore Victim network**: Press `Ctrl+C` in `demo/containment_agent.py` (auto-restores routes/firewall on exit) or click **Release** / **Cancel** in the dashboard.
* **Test Phone Push beforehand**: Open the Bell dropdown in OmniGuard → click **Phone push → Test →**.
