# OmniGuard — Live Demo Script (simple terms)

The story in one line: **show the attack winning when there's no protection,
then install our software and show it getting caught and contained.**

One name for the victim everywhere in this demo: **`WORKSTATION-CORP-01`**
(set in the extension's `background.js` and passed to the agent with `--host`).
Multiple victims? Give each its own name in both of those two places.

---

## PART 0 — Setup ("install the software")

Think of this like setting up a real company laptop: the security tools get
installed and we prove they can talk to the SOC *before* anything happens.

**On the SOC (your Mac) — start the services (by command):**
1. Backend + Frontend (the dashboard + brain)
2. Visual-verify `:8100` (the screenshot engine)
3. Attacker services: fake portal + C2 + mail inbox
   (see `RUNSHEET.md` for the exact commands)

**On the victim (Windows) — install the two tools:**
Rule: on one victim, use the **same `--soc-ip` and the same `--host`** in all
three commands. (Second victim? Give it its own `--host` name in all three.)

1. **VerifyEye extension** (the "browser security guard") — configure it by
   command (no file editing), then load it in Chrome:
   ```
   python demo\configure_verifyeye.py --soc-ip <MAC-IP> --host WORKSTATION-CORP-01
   ```
   Then: `chrome://extensions` → Load unpacked → `verifyeye-ingress/extension`
   (or just reload if already loaded).
2. **Containment agent** (the "EDR/antivirus") — by command, Admin PowerShell:
   ```
   python demo\run_soc_demo.py --role victim --soc-ip <MAC-IP> --host WORKSTATION-CORP-01
   ```

**Prove every service is reachable (the poll):**
   ```
   python demo\victim_preflight.py --soc-ip <MAC-IP> --host WORKSTATION-CORP-01
   ```
   All 4 green ✅ = the plumbing works. **Now we're ready to demo.**

---

## PART 1 — UNPROTECTED run (nothing is protecting the victim)

Turn VerifyEye **OFF** (disable it in `chrome://extensions`). This is a normal
laptop with no real protection. Watch the attack simply *work*:

1. **Fake website** — victim opens the email, clicks the link, lands on a page
   that looks exactly like Microsoft sign-in. Nothing warns them.
2. **Password harvested** — victim types their password and hits sign in. The
   password is sent straight to the attacker. On the **attacker's screen** you
   can see the stolen credentials arrive.
3. **Beacon** — the page shows a fake "verify you're human" step (ClickFix) that
   tells the victim to paste a command into PowerShell. They do it, and now the
   machine quietly calls home to the attacker's C2 over and over.
4. **SOC sees nothing** — the dashboard is dark. No protection is installed, so
   nobody knows this happened. **The attacker won.**

> Line to say: *"With no endpoint protection, the phish works, the password is
> stolen, the machine is beaconing to the attacker — and the SOC is blind."*

---

## PART 2 — PROTECTED run (our software is installed)

Turn VerifyEye **ON** (and the agent is running). Run the exact same attack:

1. **Fake website → BLOCKED** — the moment the fake Microsoft page loads,
   VerifyEye recognizes it's impersonating Microsoft on the wrong domain and
   **blocks it**. The victim can't submit anything.
2. **No password harvested** — because the page is blocked, the password is
   **never sent**. The crown jewel is safe.
3. **Alert on the SOC** — VerifyEye reports the catch to the dashboard: a
   **phishing alert for `WORKSTATION-CORP-01`**, with a **screenshot** of the
   fake page as evidence, and the local **AI reviews it** and proposes a triage.
4. **Beacon caught** — the ClickFix trick runs code *outside* the browser, which
   VerifyEye can't stop — but the **SOC's beacon detection** spots the repeated
   call-home pattern and raises a **beaconing alert** for the same host.
5. **Isolate** — the analyst clicks **Isolate** on `WORKSTATION-CORP-01`. The
   agent on the victim cuts its network — it loses the internet and the C2, but
   **stays reachable to the SOC** so we can undo it.
6. **Contained** — show the victim can no longer reach the internet / the C2 goes
   quiet. The attack is stopped.
7. **Release** — the analyst clicks **Release**. The agent restores the network
   and the victim is back to normal.

> Line to say: *"Two layers working together: VerifyEye blocks the phish in the
> browser, and when the attacker tries another trick, the SOC detects the beacon
> and the analyst isolates the machine in one click — then releases it when it's
> safe."*

---

## Why the two layers (if someone asks)

- **VerifyEye = prevention in the browser.** Stops phishing pages and credential
  theft before they happen.
- **Containment agent + SOC = detection and response.** Catches what gets past
  the browser (like a pasted command) and lets the analyst contain the host.

Real security is layered — no single tool catches everything. OmniGuard shows
prevention **and** response in one dashboard, running entirely on your own
machine (local AI, no cloud).
