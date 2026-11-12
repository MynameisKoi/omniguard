# OmniGuard — demo runbook

A step-by-step guide to running the live demo across real machines: an **analyst**
machine (runs the whole app) and one or more **victim** machines (an employee's
laptop). Everyone is on the **same WiFi**.

The story: an employee is phished, then the machine beacons out to an attacker,
both detection engines agree it's compromised, the analyst investigates with the
local AI, and then **really isolates the machine from the network**.

---

## 1. Roles and machines

| Machine | Who | Runs |
|---|---|---|
| **Analyst** (1) | the SOC analyst | the whole project: backend, frontend dashboard, SpectraC2 engine, the VerifyEye service, MongoDB, Neo4j, Ollama |
| **Victim** (1+) | an "employee" | the VerifyEye browser extension + the two demo scripts |

---

## 2. One-time install

### Analyst machine (the full app)
```
git clone <repo>
cd omniguard
```
Install deps as per the main README (Python venvs, `npm install` in `frontend/`,
and have MongoDB, Neo4j and Ollama with `llama3.2:3b` available).

### Each victim machine
Needs only **Python 3** and these parts of the repo (simplest: just `git clone`
the whole thing and use only these):
- `verifyeye-ingress/extension/`  — the browser extension (load unpacked in Chrome)
- `demo/beacon_sim.py`            — the C2 beacon simulator
- `demo/containment_agent.py`     — the containment agent

No backend, frontend, databases or engine on the victim.

---

## 3. Setup on demo day

### Step A — find the analyst machine's IP
On the analyst machine (same WiFi as everyone):
- Mac: `ipconfig getifaddr en0`
- Windows (PowerShell): `Get-NetIPAddress -AddressFamily IPv4 | ? {$_.InterfaceAlias -like "*Wi-Fi*"}`

Write it down, e.g. **192.168.1.240**. This is the ANALYST IP. It changes on a
different WiFi, so check it every time.

### Step B — start the app on the analyst machine
Backend and engines must listen on all interfaces so victims can reach them:
```
cd backend          && source venv/bin/activate && uvicorn main:app          --host 0.0.0.0 --port 8000
cd verifyeye-ingress && source venv/bin/activate && uvicorn service:app        --host 0.0.0.0 --port 8100
cd spectrac2-engine  && source venv/bin/activate && uvicorn service.main:app   --host 0.0.0.0 --port 8001
```
Start the dashboard (`npm --prefix frontend run dev`), the fake sites
(`./fake_sites/serve.sh`), and make sure MongoDB, Neo4j and Ollama are up.
Open the dashboard on the analyst machine and log in.

Tip: ask the AI one question first so the model is warm (the first reply is slow).

### Step C — point each victim at the analyst IP
On the victim, set the ANALYST IP (use the one from Step A):
- `demo/beacon_sim.py`        -> `ANALYST_IP = "192.168.1.240"`, `HOST = "lenovo-10"`
- `demo/containment_agent.py` -> `ANALYST_IP = "192.168.1.240"`, `HOST = "lenovo-10"`
- `verifyeye-ingress/extension/background.js` -> `CORE` and `VERIFY` -> the analyst IP
- `verifyeye-ingress/extension/content.js`    -> `host: "lenovo-10"` (this machine's name)

Pick a distinct `HOST` per victim. Case doesn't matter (it's normalised), but keep
the extension host and the script HOST the same on one machine so phishing + beacon
land on the same host.

Load the extension: Chrome -> `chrome://extensions` -> Developer mode -> Load
unpacked -> pick `verifyeye-ingress/extension`.

Start the containment agent **as Administrator** (needed to change the firewall):
- Windows: open PowerShell **as Administrator** -> `python demo\containment_agent.py`
- Mac/Linux: `sudo python3 demo/containment_agent.py`
It should print the gateway and "waiting for commands from the SOC".

Quick check both machines can see each other: from the victim, `ping 192.168.1.240`.

---

## 4. The demo (what to say + what to do)

### Scene 1 — Phishing is caught
Say: *"Our software runs on every employee's browser. The attacker sends a fake
login link."*
- On the victim, open the phishing email and click the link (it points to a fake
  page served from the analyst, e.g. `http://192.168.1.240:5800`).
- Try to log in on the fake page.
- **On the analyst dashboard**: a critical phishing alert appears live for this host.

Say: *"Our extension caught the fake page and reported it to the SOC instantly."*

### Scene 2 — The machine beacons out (C2)
Say: *"Say the attacker also got malware on this machine. Malware phones home on a
regular heartbeat — and that timing is what our engine detects, even encrypted.
I'll run a safe simulator of that heartbeat."*
- On the victim: `python demo\beacon_sim.py` (keep the terminal visible — it prints
  each beacon).
- After ~50s it posts the alert. **On the dashboard**: a C2 beacon alert appears,
  and the host is now flagged by **both engines** = likely compromised.

Say: *"This is a benign simulator of the beacon pattern — in the real world that
traffic is the actual malware; the detection is identical. Our ML model flagged it."*

### Scene 3 — Investigate with the local AI
- Open the alert, click **Ask AI about this alert**, ask *"what happened to
  [host]?"*
- The AI answers in plain English from the real data.

Say: *"The AI runs entirely on this machine — no data leaves the building."*

### Scene 4 — Contain it (the key moment)
Say: *"Like real endpoint security, our agent is installed on every company machine
and runs in the background. Now that this host is confirmed compromised, the
analyst isolates it."*
- On the alert detail, in the **Containment** panel (top), click **Isolate host** ->
  **Confirm**.
- On the victim: the agent terminal prints `>> ISOLATED`, and **a website no longer
  loads** (try a fresh page, e.g. google.com).
- The dashboard shows the host **Isolated from the network**.

Say: *"The machine is cut off — the attacker's lost their foothold. The dashboard
still reaches it because the agent keeps one secure channel open."*

- Click **Release**: the agent prints internet restored, and the site loads again.

### Close
Say: *"Catch what humans miss, explain it in plain English, keep a person in
control of every action, record everything in a tamper-evident log — all running
privately on your own network."*

---

## 5. If something goes wrong

- **Victim can't reach the analyst** — both on the same WiFi? `ping` the analyst IP.
  Analyst firewall may block incoming (allow it, or turn it off for the demo).
- **IP changed (different WiFi)** — redo Step A and Step C. Only the analyst IP
  changes; host names stay. See `lan-demo-setup.md`.
- **Isolate says it worked but the site still loads** — the agent must run **as
  Administrator**. The terminal will say "NOT running as admin" if it isn't.
- **Stuck in isolating/releasing** — on the victim (admin PowerShell):
  `netsh advfirewall firewall delete rule name=OmniGuard-Isolate` and
  `netsh advfirewall firewall delete rule name=OmniGuard-Isolate-v6`, then restart
  the agent. Confirm a site loads.
- **First AI reply is slow** — warm the model with one question before the demo.
- **Backup** — record a screen capture of a full successful run the day before, in
  case the network misbehaves live.
```
