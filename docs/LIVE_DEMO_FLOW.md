# OmniGuard SOC — Live Closed-Network Demo Flow

This guide walks through the end-to-end **Attack → Detect → Investigate → Quarantine & Recover** live demo on a closed Wi-Fi hotspot using your real hardware.

---

## 1. Machine Roles & Network Topology (`Koii` Hotspot)

Connect your **Windows laptop** to **SFBU** (for internet) and enable **Windows Mobile Hotspot (`Koii`)**. All demo devices join **`Koii`** (`192.168.137.0/24`), bypassing SFBU client isolation while keeping internet working.

| Role | Machine | What Runs There |
| :--- | :--- | :--- |
| **Hotspot + Attacker / C2 + LLM** | **Windows Laptop** (`192.168.137.1`) | • Windows Mobile Hotspot **`Koii`** (`192.168.137.1/24`)<br>• Ollama (`llama3.2:3b` on `:11434`)<br>• Mock Phishing & Fake CAPTCHA Portal (`mock_portal.py` on `:8080`)<br>• C2 Listener (`adversary-simulation/c2/listener.py` on `:9000` / `:4444`)<br>• VirtualBox NAT forwarding `:8000` & `:5173` → Debian VM |
| **Analyst / SOC Core** | **Debian VM** *(VirtualBox NAT)* | • MongoDB (`:27017`) + Neo4j (`:7687`)<br>• OmniGuard Backend (`:8000`) + Frontend (`:5173`)<br>• VerifyEye (`:8001`) + SpectraC2 (`:8002`)<br>• Flipper Zero USB (`demo/flipper_badge_bridge.py`) |
| **Victim Endpoint** | **Kali / Pi / Laptop** (`192.168.137.x`) | • Browser with **VerifyEye Extension** pointed at `http://192.168.137.1:8000`<br>• `demo/containment_agent.py` (run with `sudo` or Admin PowerShell) |
| **Analyst Mobile** | **Phone** (`192.168.137.x`) | • `ntfy` app (or Telegram) subscribed to alert notifications<br>• Mobile browser pointed at `http://192.168.137.1:5173` |

> **VirtualBox NAT Port Forwarding (One-Time Setup on Windows):**
> Keep Debian on **NAT** (so `10.0.2.2:11434` Ollama works) and open *VM Settings → Network → Adapter 1 → Advanced → Port Forwarding*:
> - `SOC-API`: Host Port `8000` → Guest Port `8000`
> - `SOC-UI`: Host Port `5173` → Guest Port `5173`
>
> **Windows Firewall (One-Time Admin PowerShell on Windows):**
> ```powershell
> New-NetFirewallRule -DisplayName "OmniGuard-Demo-Ports" -Direction Inbound -Protocol TCP -LocalPort 8000,5173,8080,9000,4444 -Action Allow
> ```

---

## 2. Pre-Demo Setup (2 Minutes Before Presenting)

### A. On Debian VM (Analyst SOC — 1 Command)
```bash
cd /home/koiisme/code/omniguard
./.venv/bin/python demo/run_soc_demo.py
```
*(Starts Backend `:8000`, Frontend `:5173`, warms Ollama, and auto-starts Flipper Zero USB bridge if plugged in. Add `--ntfy-topic omniguard-demo-soc` for phone alerts.)*

### B. On Windows Host (Attacker / C2 — 1 Command in Admin PowerShell)
```powershell
python demo\run_soc_demo.py --role attacker
```
*(Auto-opens temporary Windows Firewall rule `OmniGuard-Demo-Ports` and removes it automatically on `Ctrl+C`. Starts Fake M365 + CAPTCHA Portal `:8080` and C2 Listener `:9000` with RMM/Telegram C2 emulation.)*

### C. On Victim Machine (Kali / Pi / Teammate Laptop on `Koii` — 1 Command)
```bash
sudo -E python3 demo/run_soc_demo.py --role victim --host kali-victim
```
*(Connects to `192.168.137.1:8000`, blocks `9000,4444,8080` on isolate, and auto-restores networking on `Ctrl+C`.)*

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

### Act 3 — C2 Beacon / RMM Watchdog + Correlation + Phone Alert (90 sec)
1. On the Victim, click **"I am not a robot"** on `/captcha` (copies the command) and paste/run it in a terminal (or plug Flipper Zero into Victim and run **BadUSB → `omniguard_clickfix_demo.txt`**):
   ```bash
   python3 demo/beacon_sim.py --host kali-victim
   # Or to demonstrate ScreenConnect / Telegram RMM-abuse C2 (T1219):
   python3 adversary-simulation/c2/beacon_agent.py --server http://192.168.137.1:9000 --api-url http://192.168.137.1:8000 --host kali-victim --mode rmm-watchdog --fast-mode
   ```
2. **SpectraC2** detects the periodic C2 / RMM-watchdog beaconing → OmniGuard correlates the VerifyEye phishing alert + SpectraC2 C2 alert on the **Neo4j Attack Graph** under `kali-victim`.
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

## 4. Safety Audit & Recovery Guarantees
* **Zero Real Malware / Persistence**: `beacon_agent.py --mode rmm-watchdog` only simulates ScreenConnect/Telegram C2 heartbeats against your local `listener.py` (`192.168.137.1:9000`) — it never runs `msiexec`, never modifies Registry/Services, and never contacts real `api.telegram.org`.
* **Safe Portal Stub**: `mock_portal.py` `/download/` serves a harmless `.txt` file (`OmniGuardDemoClient.txt`), never an executable.
* **No Self-Lockout During Containment**: `containment_agent.py` never kills PID 1 or itself, explicitly skips port `8000` so the SOC Release channel stays open, auto-restores if SOC becomes unreachable, auto-releases after `10 minutes`, and restores networking on `Ctrl+C`.
* **Clean Host Cleanup**: `run_soc_demo.py` kills all child process groups and deletes the temporary `OmniGuard-Demo-Ports` Windows Firewall rule on `Ctrl+C`.
* **Test Phone Push beforehand**: Open the Bell dropdown in OmniGuard → click **Phone push → Test →**.
