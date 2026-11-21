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
ANALYST_IP = os.getenv("ANALYST_IP", "192.168.1.234").strip()   # the SOC machine
HOST       = os.getenv("HOST", "lenovo-10").strip()             # this machine's name -- MATCH the extension /
                                                                # beacon host exactly, so isolate targets it.
C2_IP      = os.getenv("C2_IP", "").strip()                     # optional same-subnet C2 IP to explicitly block
C2_PORTS   = [
    int(p.strip()) for p in os.getenv("C2_PORTS", "4444,9000,1337").split(",")
    if p.strip().isdigit()
]
DEFAULT_KILL_PATTERNS = [
    p.strip() for p in os.getenv("QUARANTINE_PATTERNS", "beacon_sim.py,beacon_agent.py").split(",")
    if p.strip()
]
POLL_SECONDS        = 1        # how often to check the SOC for a command
AUTO_RELEASE_MINUTES = 10      # safety net: auto-restore after this long isolated
HARD_CUT            = False    # the firewall block alone (reliable) cuts all NEW
                               # connections; prove it with `ping 8.8.8.8` (times
                               # out) or a fresh Incognito tab. Set True to also
                               # bounce the adapter so already-open tabs drop too
                               # -- more dramatic, but can disrupt the adapter on
                               # some machines, so it's off by default.

CORE = f"http://{ANALYST_IP}:8000"
AGENT_KEY = os.getenv("CONTAINMENT_AGENT_KEY", "").strip()
# ─────────────────────────────────────────────────────────────────────────────

IS_WIN = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
_state = {"isolated": False, "gateways": [], "timer": None, "c2_blocks": []}


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
        elif IS_LINUX:
            out = _run(["ip", "route", "show", "default"]).stdout
            for line in out.splitlines():
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        gws.append(parts[idx + 1])
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


FW_RULE = "OmniGuard-Isolate"          # old IPv4 remoteip rule (cleaned up)
FW_RULE6 = "OmniGuard-Isolate-v6"      # old IPv6 rule (cleaned up)
FW_ALLOW = "OmniGuard-AllowSOC"        # allow-local rule used with the block policy
FW_BLOCK_C2 = "OmniGuard-BlockC2"      # explicit block for same-subnet C2 IP/ports


def block_c2_target(c2_ip="", c2_ports=None):
    """Explicitly block a same-subnet C2 server/ports so an active reverse shell
    drops immediately even when the C2 shares the hotspot /24 with the SOC.
    Safety: never blocks ANALYST_IP:8000."""
    target_ip = (c2_ip or C2_IP or "").strip()
    ports = [int(p) for p in (c2_ports if c2_ports is not None else C2_PORTS) if int(p) != 8000]
    applied = []
    if not target_ip and not ports:
        return applied

    if IS_WIN:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_BLOCK_C2}"])
        if target_ip and target_ip != ANALYST_IP:
            _run(["netsh", "advfirewall", "firewall", "add", "rule",
                  f"name={FW_BLOCK_C2}", "dir=out", "action=block",
                  f"remoteip={target_ip}", "enable=yes"])
            applied.append(f"win-block-ip:{target_ip}")
        elif ports:
            port_csv = ",".join(str(p) for p in ports)
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={FW_BLOCK_C2}", "dir=out", "action=block",
                   "protocol=TCP", f"remoteport={port_csv}", "enable=yes"]
            if target_ip:
                cmd.append(f"remoteip={target_ip}")
            _run(cmd)
            applied.append(f"win-block-ports:{port_csv}")
    elif IS_LINUX:
        if target_ip and target_ip != ANALYST_IP:
            r = _run(["iptables", "-I", "OUTPUT", "1", "-d", target_ip, "-j", "DROP"])
            if r.returncode == 0:
                _state["c2_blocks"].append(["-d", target_ip, "-j", "DROP"])
                applied.append(f"iptables-ip:{target_ip}")
        else:
            for p in ports:
                rule = ["-p", "tcp", "--dport", str(p), "-j", "DROP"]
                if target_ip:
                    rule = ["-d", target_ip] + rule
                r = _run(["iptables", "-I", "OUTPUT", "1"] + rule)
                if r.returncode == 0:
                    _state["c2_blocks"].append(rule)
                    applied.append(f"iptables-port:{p}")
    return applied


def unblock_c2_target():
    if IS_WIN:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_BLOCK_C2}"])
    elif IS_LINUX:
        for rule in list(_state.get("c2_blocks") or []):
            _run(["iptables", "-D", "OUTPUT"] + rule)
        _state["c2_blocks"] = []


def kill_suspicious_processes(kill_pids=None, kill_patterns=None):
    """Terminate demo reverse-shell / C2 beacon processes during quarantine.
    Never kills this containment agent itself or PID 1."""
    my_pid = os.getpid()
    patterns = [p.lower() for p in (kill_patterns or DEFAULT_KILL_PATTERNS) if p]
    target_pids = {int(p) for p in (kill_pids or []) if str(p).isdigit() and int(p) not in (1, my_pid)}

    # Discover processes matching patterns
    if patterns:
        for proc in _collect_processes():
            pid = proc.get("pid")
            if not pid or pid in (1, my_pid):
                continue
            cmd = f"{proc.get('name', '')} {proc.get('cmdline', '')}".lower()
            if "containment_agent" in cmd:
                continue
            if any(pat in cmd for pat in patterns):
                target_pids.add(int(pid))

    killed = []
    for pid in sorted(target_pids):
        try:
            if IS_WIN:
                r = _run(["taskkill", "/F", "/PID", str(pid)])
                if r.returncode == 0:
                    killed.append(pid)
            else:
                os.kill(pid, signal.SIGKILL)
                killed.append(pid)
        except Exception:
            continue
    return killed


def _collect_processes():
    procs = []
    try:
        if IS_WIN:
            ps = ("Get-CimInstance Win32_Process | Select-Object -First 80 ProcessId,Name,CommandLine | "
                  "ConvertTo-Json -Compress")
            out = _run(["powershell", "-NoProfile", "-Command", ps]).stdout.strip()
            if out:
                raw = json.loads(out)
                if isinstance(raw, dict):
                    raw = [raw]
                for item in raw:
                    procs.append({
                        "pid": item.get("ProcessId"),
                        "name": item.get("Name") or "",
                        "cmdline": (item.get("CommandLine") or "")[:240],
                        "user": "",
                    })
        else:
            out = _run(["ps", "-eo", "pid=,user=,comm=,args="]).stdout
            for line in out.splitlines()[:100]:
                parts = line.strip().split(None, 3)
                if len(parts) >= 3 and parts[0].isdigit():
                    procs.append({
                        "pid": int(parts[0]),
                        "user": parts[1],
                        "name": parts[2],
                        "cmdline": (parts[3] if len(parts) > 3 else parts[2])[:240],
                    })
    except Exception:
        pass
    return procs


def _collect_connections():
    conns = []
    try:
        if IS_WIN:
            out = _run(["netstat", "-ano"]).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0].upper() in ("TCP", "UDP"):
                    local, remote = parts[1], parts[2]
                    state = parts[3] if parts[0].upper() == "TCP" else "STATELESS"
                    pid = parts[4] if parts[0].upper() == "TCP" else parts[3]
                    rip, _, rport = remote.rpartition(":")
                    conns.append({
                        "proto": parts[0].lower(),
                        "local": local,
                        "remote_ip": rip.strip("[]"),
                        "remote_port": int(rport) if rport.isdigit() else None,
                        "state": state,
                        "pid": int(pid) if pid.isdigit() else None,
                        "process": "",
                    })
        elif IS_LINUX:
            out = _run(["ss", "-tupn"]).stdout
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    proto, state, local, remote = parts[0], parts[1], parts[4], parts[5]
                    proc_info = " ".join(parts[6:]) if len(parts) > 6 else ""
                    rip, _, rport = remote.rpartition(":")
                    conns.append({
                        "proto": proto,
                        "local": local,
                        "remote_ip": rip.strip("[]"),
                        "remote_port": int(rport) if rport.isdigit() else None,
                        "state": state,
                        "process": proc_info[:120],
                    })
        else:
            out = _run(["lsof", "-i", "-n", "-P"]).stdout
            for line in out.splitlines()[1:80]:
                parts = line.split()
                if len(parts) >= 9:
                    conns.append({
                        "proto": parts[7].lower(),
                        "local": parts[8],
                        "remote_ip": "",
                        "remote_port": None,
                        "state": parts[9] if len(parts) > 9 else "",
                        "process": f"{parts[0]}({parts[1]})",
                    })
    except Exception:
        pass
    return conns[:80]


def _collect_hosts_entries():
    path = r"C:\Windows\System32\drivers\etc\hosts" if IS_WIN else "/etc/hosts"
    entries = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    entries.append(s[:160])
    except Exception:
        pass
    return entries[:40]


def collect_dfir_snapshot():
    """Gather a point-in-time forensic snapshot (processes, sockets, hosts)."""
    return {
        "host": HOST,
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "is_admin": is_admin(),
        "gateways": current_gateways(),
        "processes": _collect_processes(),
        "connections": _collect_connections(),
        "hosts_entries": _collect_hosts_entries(),
    }


def report_dfir():
    snap = collect_dfir_snapshot()
    data = json.dumps(snap).encode()
    req = urllib.request.Request(
        f"{CORE}/agent/dfir/report",
        data=data,
        headers=_agent_headers({"Content-Type": "application/json"}),
        method="POST",
    )
    try:
        with _direct.open(req, timeout=8) as r:
            r.read(1)
        print(f"  >> DFIR snapshot uploaded ({len(snap['processes'])} procs, {len(snap['connections'])} sockets)")
    except Exception as e:
        print(f"  ! could not upload DFIR snapshot: {e}")


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
        rule = (_run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={FW_ALLOW}"]).stdout or "")
        print(f"    cut applied (allow-SOC rule present): {'No rules match' not in rule}")
    print(f"    can reach internet (8.8.8.8): {has_internet()}")
    print(f"    can reach SOC ({ANALYST_IP}): {can_reach_soc()}")
    print(f"  --- end diagnostics ---")


def cut_network(quarantine=None):
    """Cut the host off the internet, keeping the SOC subnet reachable so the
    analyst can still release it. Also kills reverse-shell/beacon processes and
    explicitly blocks same-subnet C2 targets when configured."""
    if not is_admin():
        return False, ("not running as admin -- this needs elevation. "
                       "Windows: reopen PowerShell as Administrator. Mac/Linux: use sudo.")

    q = quarantine or {}
    killed_pids = kill_suspicious_processes(q.get("kill_pids"), q.get("kill_patterns"))
    c2_rules = block_c2_target(q.get("c2_ip"), q.get("c2_ports"))

    errs = []
    if IS_WIN:
        ensure_firewall_on()   # the block does nothing if the firewall is off
        a, b, c, _ = ANALYST_IP.split(".")
        soc_net = f"{a}.{b}.{c}.0/24"   # the SOC's subnet -- must stay reachable
        for rn in (FW_RULE, FW_RULE6, FW_ALLOW, f"{FW_ALLOW}-in"):
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rn}"])
        # keep the SOC subnet reachable BOTH ways (so the agent can still poll and
        # be released), then block everything else outbound -- IPv4 AND IPv6.
        r1 = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={FW_ALLOW}", "dir=out", "action=allow",
                   f"remoteip={soc_net},LocalSubnet", "enable=yes"])
        rin = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={FW_ALLOW}-in", "dir=in", "action=allow",
                    f"remoteip={soc_net},LocalSubnet", "enable=yes"])
        r2 = _run(["netsh", "advfirewall", "set", "allprofiles",
                   "firewallpolicy", "blockinbound,blockoutbound"])
        for r in (r1, rin, r2):
            if r.returncode != 0 and (r.stderr or r.stdout).strip():
                errs.append((r.stderr or r.stdout).strip())
        # hard cut: also drop connections that are already open
        if HARD_CUT:
            print("     dropping open connections (brief network reset)...")
            flush_connections()
    else:
        gws = current_gateways()
        _state["gateways"] = gws
        r = _run(["ip", "route", "del", "default"] if IS_LINUX else ["route", "delete", "default"])
        if r.returncode != 0 and (r.stderr or r.stdout).strip():
            errs.append((r.stderr or r.stdout).strip())

    time.sleep(0.8)  # let the firewall / routing table settle

    # SAFETY: if the cut also severed the SOC, the analyst could never release us
    # remotely -- so undo it and report, rather than trapping the host.
    if not can_reach_soc():
        restore_network()
        detail = (f"the SOC ({ANALYST_IP}) is NOT reachable after the cut, so a "
                  f"remote release would be impossible -- not isolating. Check the "
                  f"SOC IP and that it's on this machine's subnet.")
        if errs:
            detail += f" (command said: {' | '.join(errs)})"
        return False, detail

    if has_internet():
        detail = "internet is still reachable after applying the block"
        if errs:
            detail += f"; command said: {' | '.join(errs)}"
        restore_network()  # don't leave a half-applied state
        return False, detail
    notes = ["internet cut; SOC subnet still reachable"]
    if c2_rules:
        notes.append(f"C2 blocked ({', '.join(c2_rules)})")
    if killed_pids:
        notes.append(f"killed suspicious PIDs {killed_pids}")
    return True, "; ".join(notes)


def restore_network():
    """Undo the cut -> internet back. Verifies connectivity returned."""
    unblock_c2_target()
    if IS_WIN:
        # restore the normal default (outbound allowed) and remove our rules
        _run(["netsh", "advfirewall", "set", "allprofiles",
              "firewallpolicy", "blockinbound,allowoutbound"])
        for rn in (FW_ALLOW, f"{FW_ALLOW}-in", FW_RULE, FW_RULE6):
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rn}"])
    else:
        for gw in (_state.get("gateways") or current_gateways()):
            _run(["ip", "route", "add", "default", "via", gw] if IS_LINUX else ["route", "add", "default", gw])
    time.sleep(1.0)
    back = has_internet()
    return back, ("internet restored" if back else "block removed -- internet not confirmed back yet")


# ── SOC channel ──────────────────────────────────────────────────────────────
# Talk to the SOC DIRECTLY, never through a system/WPAD proxy: a proxy sits on the
# internet, which is blocked during isolation, so a proxied request would fail even
# though the SOC itself is reachable. This is what kept Release from arriving.
_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _agent_headers(extra=None):
    hdrs = dict(extra or {})
    if AGENT_KEY:
        hdrs["X-Agent-Key"] = AGENT_KEY
    return hdrs


def poll():
    url = f"{CORE}/agent/containment/poll?host={urllib.parse.quote(HOST)}"
    req = urllib.request.Request(url, headers=_agent_headers())
    with _direct.open(req, timeout=5) as r:
        return json.loads(r.read().decode())


def ack(action, ok, message=None):
    data = json.dumps({"host": HOST, "action": action, "ok": ok,
                       "message": message}).encode()
    req = urllib.request.Request(f"{CORE}/agent/containment/ack", data=data,
                                 headers=_agent_headers({"Content-Type": "application/json"}),
                                 method="POST")
    try:
        with _direct.open(req, timeout=5) as r:
            r.read(1)
    except Exception as e:
        print(f"  ! could not ack to SOC: {e}")


# ── isolate / release ────────────────────────────────────────────────────────
def _cancel_timer():
    t = _state.get("timer")
    if t:
        t.cancel()
        _state["timer"] = None


def do_isolate(quarantine=None):
    if _state["isolated"]:
        # already in the target state — confirm it so the SOC stops re-sending
        print("  (already isolated — confirming to SOC)")
        ack("isolate", True, "already isolated")
        return
    print("\n  >> ISOLATE requested by the SOC")
    ok, msg = cut_network(quarantine=quarantine)
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
            resp = poll()
            if resp.get("dfir_requested"):
                print("  (SOC requested live DFIR snapshot)")
                report_dfir()
            cmd = resp.get("action")
            if cmd:
                print(f"  (SOC command received: {cmd})")
            if cmd == "isolate":
                do_isolate(quarantine=resp.get("quarantine"))
            elif cmd == "release":
                do_release("analyst")
        except urllib.error.URLError as e:
            # can't reach the SOC -- surface it (esp. while isolated: the channel
            # must stay open or release can't arrive), but keep trying
            _state["poll_fails"] = _state.get("poll_fails", 0) + 1
            if _state["poll_fails"] % 5 == 1:
                print(f"  ! cannot reach the SOC to get commands ({e.reason}) — "
                      f"{'STILL ISOLATED, release cannot arrive' if _state['isolated'] else 'retrying'}")
        except Exception as e:
            print(f"  ! poll error: {e}")
        else:
            _state["poll_fails"] = 0
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
