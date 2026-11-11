#!/usr/bin/env python3
"""
CONTAINMENT AGENT  —  real host isolation for the OmniGuard demo.

Runs on a "victim" laptop. It polls the SOC and, when the analyst approves
isolation of this host, it actually cuts the machine off the internet; when the
analyst releases it, it restores it.

How the cut works (and why it's safe):
  * It removes the machine's DEFAULT ROUTE, so traffic to the internet has
    nowhere to go -- the machine is really offline. Same-subnet traffic still
    works, so the SOC (on the same WiFi) stays reachable and can release it.
  * The original gateway is saved first and restored on release. There are THREE
    ways it gets restored so you can never be stuck offline:
       - the analyst clicks Release on the dashboard,
       - an automatic timeout (AUTO_RELEASE_MINUTES),
       - closing this agent (Ctrl+C) or it crashing.

Requirements:
  * Run as Administrator (Windows) or with sudo (Mac/Linux) -- changing routes
    needs admin rights, like a real EDR tool.
  * The SOC must be on the SAME subnet as this machine (it is, on the demo WiFi).

Run it on the victim laptop:
  Windows (admin PowerShell):  python demo\\containment_agent.py
  Mac/Linux:                   sudo python3 demo/containment_agent.py
"""

import atexit
import ctypes
import json
import os
import platform
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import urllib.parse

# ── settings ─────────────────────────────────────────────────────────────────
ANALYST_IP = "192.168.1.234"   # the SOC machine
HOST       = "lenovo-10"       # this machine's name -- MATCH the extension /
                               # beacon host exactly, so isolate targets it.
POLL_SECONDS        = 2        # how often to check the SOC for a command
AUTO_RELEASE_MINUTES = 10      # safety net: auto-restore after this long isolated

CORE = f"http://{ANALYST_IP}:8000"
# ─────────────────────────────────────────────────────────────────────────────

IS_WIN = platform.system() == "Windows"
_state = {"isolated": False, "gateways": [], "timer": None}


# ── admin check ──────────────────────────────────────────────────────────────
def is_admin():
    try:
        if IS_WIN:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


# ── route control ────────────────────────────────────────────────────────────
def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def current_gateways():
    """The machine's current default gateway(s)."""
    gws = []
    try:
        if IS_WIN:
            out = _run(["route", "print", "0.0.0.0"]).stdout
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 3 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
                    if p[2].lower() != "on-link":
                        gws.append(p[2])
        else:
            out = _run(["route", "-n", "get", "default"]).stdout
            for line in out.splitlines():
                if "gateway:" in line:
                    gws.append(line.split(":", 1)[1].strip())
    except Exception as e:
        print(f"  ! could not read routes: {e}")
    # de-dupe, keep order
    seen, uniq = set(), []
    for g in gws:
        if g not in seen:
            seen.add(g); uniq.append(g)
    return uniq


def has_internet():
    """True if we can actually reach the public internet (no DNS needed)."""
    import socket
    for ip in ("8.8.8.8", "1.1.1.1"):
        try:
            s = socket.create_connection((ip, 53), timeout=2)
            s.close()
            return True
        except Exception:
            continue
    return False


def cut_network():
    """Remove the default route(s) -> internet is cut, LAN/SOC still reachable.
    VERIFIES the cut actually worked instead of trusting the command."""
    if not is_admin():
        return False, ("not running as admin -- route changes need elevation. "
                       "Windows: reopen PowerShell as Administrator. Mac/Linux: use sudo.")
    gws = current_gateways()
    if not gws:
        return False, "no default gateway found (already offline?)"
    _state["gateways"] = gws

    errs = []
    if IS_WIN:
        for cmd in ([["route", "delete", "0.0.0.0"]]
                    + [["route", "delete", "0.0.0.0", "mask", "0.0.0.0", gw] for gw in gws]):
            r = _run(cmd)
            if r.returncode != 0 and (r.stderr or r.stdout).strip():
                errs.append((r.stderr or r.stdout).strip())
    else:
        r = _run(["route", "delete", "default"])
        if r.returncode != 0 and (r.stderr or r.stdout).strip():
            errs.append((r.stderr or r.stdout).strip())

    time.sleep(1.2)  # let the routing table settle / any auto re-add happen

    # the real test: did we actually lose the internet?
    if has_internet() or current_gateways():
        detail = "default route still active after delete"
        if current_gateways():
            detail += f" (gateway still: {', '.join(current_gateways())})"
        if errs:
            detail += f"; command said: {' | '.join(errs)}"
        return False, detail
    return True, f"internet cut (removed default route via {', '.join(gws)}); SOC still on-subnet"


def restore_network():
    """Re-add the saved default route -> internet back. Verifies it returned."""
    gws = _state.get("gateways") or current_gateways()
    if not gws:
        return False, "no saved gateway to restore"
    for gw in gws:
        if IS_WIN:
            _run(["route", "add", "0.0.0.0", "mask", "0.0.0.0", gw])
        else:
            _run(["route", "add", "default", gw])
    time.sleep(1.2)
    back = has_internet()
    msg = f"default route restored via {', '.join(gws)}"
    return back, (msg if back else msg + " -- but internet not confirmed back yet")


# ── SOC channel ──────────────────────────────────────────────────────────────
def poll():
    url = f"{CORE}/agent/containment/poll?host={urllib.parse.quote(HOST)}"
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode())


def ack(action, ok, message=None):
    data = json.dumps({"host": HOST, "action": action, "ok": ok,
                       "message": message}).encode()
    req = urllib.request.Request(f"{CORE}/agent/containment/ack", data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read(1)
    except Exception as e:
        print(f"  ! could not ack to SOC: {e}")


# ── isolate / release ────────────────────────────────────────────────────────
def _cancel_timer():
    t = _state.get("timer")
    if t:
        t.cancel()
        _state["timer"] = None


def do_isolate():
    if _state["isolated"]:
        return
    print("\n  >> ISOLATE requested by the SOC")
    ok, msg = cut_network()
    if ok:
        _state["isolated"] = True
        print(f"  >> ISOLATED  ({msg})")
        print(f"     internet is cut. SOC still reachable. auto-release in "
              f"{AUTO_RELEASE_MINUTES} min if not released sooner.")
        ack("isolate", True, msg)
        _cancel_timer()
        t = threading.Timer(AUTO_RELEASE_MINUTES * 60, auto_release)
        t.daemon = True
        t.start()
        _state["timer"] = t
    else:
        print(f"  !! could not isolate: {msg}")
        ack("isolate", False, msg)


def do_release(reason="analyst"):
    if not _state["isolated"]:
        return
    print(f"\n  << RELEASE ({reason})")
    _cancel_timer()
    ok, msg = restore_network()
    _state["isolated"] = False
    print(f"  << {'RESTORED' if ok else 'RESTORE HAD ISSUES'}  ({msg})")
    ack("release", ok, f"{reason}: {msg}")


def auto_release():
    print("\n  (auto-release timeout reached)")
    do_release("auto-release timeout")


def _cleanup(*_):
    # runs on Ctrl+C / exit: never leave the machine offline
    if _state["isolated"]:
        print("\n  agent stopping -- restoring network first...")
        _cancel_timer()
        restore_network()
        _state["isolated"] = False
    sys.exit(0)


def main():
    print("=" * 62)
    print("  OmniGuard CONTAINMENT AGENT")
    print(f"  host : {HOST}")
    print(f"  SOC  : {CORE}")
    print("=" * 62)

    if not is_admin():
        print("  ! NOT running as admin. Route changes will fail.")
        print("    Windows: open PowerShell as Administrator.")
        print("    Mac/Linux: run with sudo.")
        print("    (The agent will still poll, but isolation won't apply.)")

    gws = current_gateways()
    print(f"  current default gateway: {', '.join(gws) if gws else 'none found'}")
    print("  waiting for commands from the SOC... (Ctrl+C to quit safely)\n")

    atexit.register(_cleanup)
    signal.signal(signal.SIGINT, _cleanup)
    try:
        signal.signal(signal.SIGTERM, _cleanup)
    except Exception:
        pass

    while True:
        try:
            cmd = poll().get("action")
            if cmd == "isolate":
                do_isolate()
            elif cmd == "release":
                do_release("analyst")
        except urllib.error.URLError:
            # SOC unreachable -- stay quiet, keep trying; safety timers still hold
            pass
        except Exception as e:
            print(f"  ! poll error: {e}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
