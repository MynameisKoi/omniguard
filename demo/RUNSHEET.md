# OmniGuard — Live Demo Run Sheet

Two laptops on **one closed network**. Mac plays **SOC + Attacker**; the
Windows laptop is the **Victim**. (On demo day Khoi's hotspot "Koii" is the
network; for a solo rehearsal just put both laptops on the same Wi‑Fi.)

---

## 0. Network & IPs

| Thing            | Value (fill in per network)                |
|------------------|--------------------------------------------|
| Mac (SOC) IP     | `192.168.1.234`  ← home Wi‑Fi today. Khoi hotspot = `192.168.137.x` |
| Find it          | `ipconfig getifaddr en0`                   |
| Windows (victim) | joins the **same** Wi‑Fi as the Mac        |

> Everything the victim talks to uses the **Mac IP**. Change it in one place:
> `verifyeye-ingress/extension/background.js` lines 9–10 (`CORE`, `VERIFY`).

---

## 1. SOC — on the Mac (do this first)

Already running: **MongoDB :27017**, **Neo4j :7687**, **Ollama :11434**.
(Start Neo4j in Neo4j Desktop; `ollama serve` if 11434 is down.)

Backend uses the non‑iCloud venv `~/omniguard-venv` (so iCloud can't offload it):

```bash
cd ~/Documents/SFBU/capstone_project/omniguard/backend
~/omniguard-venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --loop asyncio --http h11
```

Frontend (new terminal):

```bash
cd ~/Documents/SFBU/capstone_project/omniguard/frontend
npm run dev -- --host 0.0.0.0
```

VerifyEye visual-verify service — the Playwright screenshot engine on :8100
(runs from the non-iCloud venv; Chromium already downloaded):

```bash
cd ~/Documents/SFBU/capstone_project/omniguard/verifyeye-ingress
CORE_API_URL="http://127.0.0.1:8000" ~/omniguard-venv/bin/uvicorn service:app \
  --host 0.0.0.0 --port 8100 --loop asyncio --http h11
```

SOC dashboard: `http://192.168.1.234:5173`  (open on the Mac, big screen).

**Why `--loop asyncio --http h11`:** Python 3.14 + uvicorn's default
uvloop/httptools hang silently at startup. These flags use the stable stack.

---

## 2. Attacker — also on the Mac (second)

```bash
cd ~/Documents/SFBU/capstone_project/omniguard
python3 demo/run_soc_demo.py --role attacker      # fake portal :8080 + C2 :9000
```

Mail inbox (the victim's "email"):

```bash
cd ~/Documents/SFBU/capstone_project/omniguard/adversary-simulation/email
python3 mail_inbox.py --host 0.0.0.0              # SMTP :1025, web inbox :8025
```

Send the phish (pick a brand, point the CTA at the Mac IP):

```bash
cd ~/Documents/SFBU/capstone_project/omniguard/adversary-simulation/email
python3 phish_mailer.py --brand microsoft --send \
  --portal http://192.168.1.234:8080/login.html \
  --smtp-host 127.0.0.1 --smtp-port 1025 --to victim@lab.local
```

Brands available: microsoft, google, netflix, amazon, docusign, apple, github
(`--all` sends every brand; `--save` writes .html instead of sending).

---

## 3. Victim — on the Windows laptop (third)

Three commands, all with the **same `--soc-ip` and `--host`**. Pure stdlib —
Windows needs only plain Python 3, no pip installs.

1. Configure the VerifyEye extension (writes IP + host into background.js):

```bash
python demo\configure_verifyeye.py --soc-ip 192.168.1.234 --host WORKSTATION-CORP-01
```
   Then load it: Chrome → chrome://extensions → Load unpacked →
   `verifyeye-ingress/extension` (or reload if already loaded).

2. Start the containment/DFIR agent (the "antivirus/EDR" that must always run so
   the SOC can isolate & release) — **Admin PowerShell**:

```bash
python demo\run_soc_demo.py --role victim --soc-ip 192.168.1.234 --host WORKSTATION-CORP-01
```

3. Poll to confirm every service is reachable (regular shell is fine):

```bash
python demo\victim_preflight.py --soc-ip 192.168.1.234 --host WORKSTATION-CORP-01
```

> `--soc-ip` is a **bare IP** (your Mac), not a URL.
> `--host` is the name you'll click **Isolate** on in the dashboard. Keep it the
> SAME across all three commands. A second victim gets its own `--host` name.

---

## 4. The four POVs (demo flow)

1. **Attacker** — open the mail inbox `http://192.168.1.234:8025`, show the
   spoofed "Microsoft account team" email, click the CTA → fake portal.
2. **Victim** — VerifyEye flags the phishing page in‑browser; if they run the
   fake‑captcha "fix", the beacon calls the C2 → alert fires on the SOC.
3. **Email POV** — show how From is fully spoofed (no SPF/DKIM on a closed net).
4. **SOC** — alert appears on the dashboard; **Live AI** reviews it and proposes
   a triage; analyst clicks **Isolate**; victim loses the network except the SOC
   subnet; analyst clicks **Release** → victim restored.

---

## Quick health check (Mac)

```bash
for p in 27017 11434 7687 8000 5173 8080 9000 1025 8025; do lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1 && echo ":$p UP" || echo ":$p down"; done
```

Stop everything: `Ctrl‑C` each terminal. Mongo/Neo4j/Ollama can stay up.
