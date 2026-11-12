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
POLL_SECONDS        = 1        # how often to check the SOC for a command
AUTO_RELEASE_MINUTES = 10      # safety net: auto-restore after this long isolated
HARD_CUT            = False    # the firewall block alone (reliable) cuts all NEW
                               # connections; prove it with `ping 8.8.8.8` (times
                               # out) or a fresh Incognito tab. Set True to also
                               # bounce the adapter so already-open tabs drop too
                               # -- more dramatic, but can disrupt the adapter on
                               # some machines, so it's off by default.

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
            s = socket.create_connection((ip, 53), timeout=1)
            s.close()
            return True
        except Exception:
            continue
    return False


def can_reach_soc():
    import socket
    try:
        s = socket.create_connection((ANALYST_IP, 8000), timeout=2)
        s.close()
        return True
    except Exception:
        return False


def flush_connections():
    """Hard cut (Windows): drop connections that are ALREADY open, so even tabs
    loaded before isolation die -- not just new connections. Briefly bounces the
    active network adapter; the firewall rule stays in place across it, and the
    SOC (same subnet) comes back reachable so we can still be released."""
    if not (IS_WIN and HARD_CUT):
        return
    ps = ("$a = Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} | "
          "Select-Object -First 1 -ExpandProperty Name; "
          "if ($a) { Disable-NetAdapter -Name $a -Confirm:$false; Start-Sleep -Seconds 2; "
          "Enable-NetAdapter -Name $a -Confirm:$false }")
    _run(["powershell", "-NoProfile", "-Command", ps])
    # wait for the adapter / DHCP to come back so we can still reach the SOC to ack
    for _ in range(25):
        time.sleep(1)
        if can_reach_soc():
            break


FW_RULE = "OmniGuard-Isolate"          # IPv4 rule name
FW_RULE6 = "OmniGuard-Isolate-v6"      # IPv6 rule name


def _soc_block_ranges():
    """IPv4 ranges covering everything EXCEPT the SOC's /24, so we block the
    internet but keep the SOC (and gateway) reachable for the release command."""
    import ipaddress
    a, b, c, _ = ANALYST_IP.split(".")
    net = ipaddress.ip_network(f"{a}.{b}.{c}.0/24")
    first, last = int(net.network_address), int(net.broadcast_address)
    ranges = []
    if first > 0:
        ranges.append(f"0.0.0.0-{ipaddress.ip_address(first - 1)}")
    if last < 2**32 - 1:
        ranges.append(f"{ipaddress.ip_address(last + 1)}-255.255.255.255")
    return ",".join(ranges)


def ensure_firewall_on():
    """The whole cut depends on Windows Firewall being ON. Turn it on if it's off
    (the block rules do nothing while it's disabled)."""
    if IS_WIN:
        _run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])


def print_diagnostics(tag=""):
    """Print what's actually true right now, so there's no guessing."""
    print(f"  --- diagnostics ({tag}) ---")
    if IS_WIN:
        st = (_run(["netsh", "advfirewall", "show", "allprofiles", "state"]).stdout or "")
        for line in st.splitlines():
            t = line.strip()
            if t and ("Profile Settings" in t or t.startswith("State")):
                print(f"    firewall: {t}")
        rule = (_run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={FW_RULE}"]).stdout or "")
        print(f"    block rule present: {'No rules match' not in rule}")
    print(f"    can reach internet (8.8.8.8): {has_internet()}")
    print(f"    can reach SOC ({ANALYST_IP}): {can_reach_soc()}")
    print(f"  --- end diagnostics ---")


def cut_network():
    """Cut the host off the internet, keeping the SOC subnet reachable so the
    analyst can still release it. VERIFIES the cut actually worked.

    Windows: a firewall rule (reliable; route delete gets auto-undone by Windows).
    Mac/Linux: remove the default route."""
    if not is_admin():
        return False, ("not running as admin -- this needs elevation. "
                       "Windows: reopen PowerShell as Administrator. Mac/Linux: use sudo.")

    errs = []
    if IS_WIN:
        ensure_firewall_on()   # the block does nothing if the firewall is off
        # clear any leftover rules from a previous run so they don't stack
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE}"])
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE6}"])
        block = _soc_block_ranges()
        r1 = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={FW_RULE}", "dir=out", "action=block",
                   f"remoteip={block}", "enable=yes"])
        # also block all IPv6 outbound so sites can't sneak out over v6
        r2 = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={FW_RULE6}", "dir=out", "action=block",
                   "remoteip=::/0", "enable=yes"])
        for r in (r1, r2):
            if r.returncode != 0 and (r.stderr or r.stdout).strip():
                errs.append((r.stderr or r.stdout).strip())
        # hard cut: also drop connections that are already open
        if HARD_CUT:
            print("     dropping open connections (brief network reset)...")
            flush_connections()
    else:
        gws = current_gateways()
        _state["gateways"] = gws
        r = _run(["route", "delete", "default"])
        if r.returncode != 0 and (r.stderr or r.stdout).strip():
            errs.append((r.stderr or r.stdout).strip())

    time.sleep(0.8)  # let the firewall / routing table settle

    if has_internet():
        detail = "internet is still reachable after applying the block"
        if errs:
            detail += f"; command said: {' | '.join(errs)}"
        restore_network()  # don't leave a half-applied state
        return False, detail
    return True, "internet cut; SOC subnet still reachable"


def restore_network():
    """Undo the cut -> internet back. Verifies connectivity returned."""
    if IS_WIN:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE}"])
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE6}"])
    else:
        for gw in (_state.get("gateways") or current_gateways()):
            _run(["route", "add", "default", gw])
    time.sleep(1.5)
    back = has_internet()
    return back, ("internet restored" if back else "block removed -- internet not confirmed back yet")


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
        # already in the target state — confirm it so the SOC stops re-sending
        print("  (already isolated — confirming to SOC)")
        ack("isolate", True, "already isolated")
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
    print_diagnostics("after isolate")


def do_release(reason="analyst"):
    if not _state["isolated"]:
        # already released — confirm it so the SOC stops re-sending the command
        print(f"  (not isolated — confirming released to SOC [{reason}])")
        ack("release", True, "already released")
        return
    print(f"\n  << RELEASE ({reason})")
    _cancel_timer()
    ok, msg = restore_network()
    _state["isolated"] = False
    print(f"  << {'RESTORED' if ok else 'RESTORE HAD ISSUES'}  ({msg})")
    ack("release", ok, f"{reason}: {msg}")
    print_diagnostics("after release")


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
    print_diagnostics("startup")
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
            if cmd:
                print(f"  (SOC command received: {cmd})")
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
