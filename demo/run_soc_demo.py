#!/usr/bin/env python3
"""
OmniGuard SOC — Single-File Live Demo Launcher & Clean Teardown.

Starts all services needed for your role in one command and cleanly terminates
every child process group (and restores network/ports) on Ctrl+C / exit.

Roles:
  --role soc        (Default, Debian VM) Starts Backend (:8000), Frontend (:5173),
                    and Flipper Zero 1-Tap Badge Bridge (auto-detected on USB).
                    Use --with-attacker to also run mock_portal + C2 listener locally.
  --role attacker   (Windows / C2 Host) Starts Mock M365 + ClickFix CAPTCHA Portal
                    (:8080) and C2 Listener (:9000).
  --role victim     (Kali / Pi / Laptop) Starts Containment & DFIR Agent pointing
                    at 192.168.137.1 (Koii hotspot). Auto-restores network on exit.

Examples:
  ./.venv/bin/python demo/run_soc_demo.py
  ./.venv/bin/python demo/run_soc_demo.py --with-attacker
  python demo/run_soc_demo.py --role attacker
  sudo -E python3 demo/run_soc_demo.py --role victim --host kali-victim
"""

from __future__ import annotations

import argparse
import atexit
import glob
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IS_WIN = platform.system() == "Windows"


def _venv_python() -> str:
    candidates = [
        os.path.join(REPO_ROOT, ".venv", "Scripts", "python.exe") if IS_WIN
        else os.path.join(REPO_ROOT, ".venv", "bin", "python"),
        sys.executable,
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return sys.executable


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _find_flipper() -> str | None:
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            desc = f"{p.description or ''} {p.manufacturer or ''} {p.hwid or ''}".lower()
            if "flipper" in desc or (p.vid == 0x0483 and p.pid == 0x5740):
                return p.device
    except Exception:
        pass
    by_id = sorted(glob.glob("/dev/serial/by-id/*Flipper*"))
    if by_id:
        return by_id[0]
    acms = sorted(glob.glob("/dev/ttyACM*"))
    return acms[0] if acms else None


def _ensure_docker_dbs() -> None:
    """Start MongoDB / Neo4j Docker containers if they exist and aren't listening yet."""
    if _port_open("127.0.0.1", 27017) and _port_open("127.0.0.1", 7687):
        return
    for name in ("omniguard-mongo", "omniguard-neo4j"):
        try:
            subprocess.run(["docker", "start", name], capture_output=True, timeout=8)
        except Exception:
            pass


def _warm_ollama() -> None:
    ollama_url = os.getenv("OLLAMA_URL", "http://10.0.2.2:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    try:
        req = urllib.request.Request(
            f"{ollama_url}/api/generate",
            data=json.dumps({"model": model, "prompt": "ok", "stream": False, "keep_alive": "30m",
                             "options": {"num_predict": 1}}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8):
            print(f"[warmup] Ollama model '{model}' warmed at {ollama_url}")
    except Exception as e:
        print(f"[warmup] Ollama warm-up skipped ({e})")


FW_DEMO_RULE = "OmniGuard-Demo-Ports"


def _win_is_admin() -> bool:
    if not IS_WIN:
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _setup_win_firewall(ports: list[int], remote_ip: str = "192.168.137.0/24") -> bool:
    """Create temporary Windows Firewall rule scoped to the hotspot subnet."""
    if not IS_WIN:
        return False
    if not _win_is_admin():
        print("[firewall] Not running as Administrator — skipping auto Windows Firewall rule.")
        print(f"           If hotspot clients can't connect, run PowerShell as Admin or open TCP {','.join(map(str, ports))}.")
        return False
    port_csv = ",".join(str(p) for p in ports)
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_DEMO_RULE}"],
        capture_output=True,
    )
    res = subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={FW_DEMO_RULE}", "dir=in", "action=allow",
         "protocol=TCP", f"localport={port_csv}", f"remoteip={remote_ip}"],
        capture_output=True, text=True,
    )
    if res.returncode == 0:
        print(f"[firewall] Opened Windows Firewall TCP {port_csv} ONLY for {remote_ip} ({FW_DEMO_RULE}) — auto-removes on exit.")
        return True
    print(f"[firewall] Could not add rule ({res.stderr.strip() or res.stdout.strip()})")
    return False


def _cleanup_win_firewall() -> None:
    if not IS_WIN:
        return
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_DEMO_RULE}"],
        capture_output=True,
    )
    print(f"[cleanup] Removed Windows Firewall rule '{FW_DEMO_RULE}'.")


class ProcessSupervisor:
    """Starts child processes in their own process group and cleans all of them up."""

    def __init__(self) -> None:
        self.procs: list[tuple[str, subprocess.Popen]] = []
        self._cleaned = False
        self.win_firewall_added = False

    def start(self, name: str, cmd: list[str], cwd: str | None = None, env: dict | None = None) -> subprocess.Popen:
        full_env = os.environ.copy()
        if env:
            full_env.update(env)

        kwargs: dict = {
            "cwd": cwd or REPO_ROOT,
            "env": full_env,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "bufsize": 1,
        }
        if IS_WIN:
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True

        proc = subprocess.Popen(cmd, **kwargs)
        self.procs.append((name, proc))

        def _pump():
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    print(f"[{name}] {line}", end="", flush=True)
            except Exception:
                pass

        t = threading.Thread(target=_pump, daemon=True)
        t.start()
        return proc

    def cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        if not self.procs:
            return
        print("\n[cleanup] Stopping all demo processes cleanly...")
        # Signal graceful stop first (so containment_agent restores network, Flipper releases ttyACM0)
        for name, proc in reversed(self.procs):
            if proc.poll() is not None:
                continue
            try:
                if IS_WIN:
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    os.killpg(proc.pid, signal.SIGINT)
            except Exception:
                try:
                    proc.terminate()
                except Exception:
                    pass

        deadline = time.time() + 5.0
        for name, proc in reversed(self.procs):
            remaining = max(0.1, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
                print(f"[cleanup] {name} stopped (code {proc.returncode})")
            except subprocess.TimeoutExpired:
                try:
                    if IS_WIN:
                        proc.kill()
                    else:
                        os.killpg(proc.pid, signal.SIGKILL)
                    print(f"[cleanup] {name} force-killed")
                except Exception:
                    pass
        if self.win_firewall_added:
            _cleanup_win_firewall()
        print("[cleanup] All demo processes cleaned up.")


def run_soc_role(sup: ProcessSupervisor, args: argparse.Namespace) -> None:
    py = _venv_python()
    _ensure_docker_dbs()

    if _port_open("127.0.0.1", args.backend_port):
        print(f"[!] Port {args.backend_port} is already in use! Free it first (e.g., `pkill -f uvicorn`) or pass --backend-port.")
        sys.exit(1)

    if not args.skip_warmup:
        threading.Thread(target=_warm_ollama, daemon=True).start()

    env_extra = {}
    if args.ntfy_topic:
        env_extra["NTFY_TOPIC"] = args.ntfy_topic
    if args.dashboard_url:
        env_extra["DASHBOARD_PUBLIC_URL"] = args.dashboard_url

    sup.start(
        "backend",
        [py, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", str(args.backend_port)],
        cwd=os.path.join(REPO_ROOT, "backend"),
        env=env_extra,
    )

    npm_bin = "npm.cmd" if IS_WIN else "npm"
    sup.start(
        "frontend",
        [npm_bin, "run", "dev", "--", "--host", "0.0.0.0", "--port", str(args.frontend_port)],
        cwd=os.path.join(REPO_ROOT, "frontend"),
    )

    # Wait briefly for backend to listen before starting Flipper bridge
    for _ in range(20):
        if _port_open("127.0.0.1", args.backend_port, timeout=0.5):
            break
        time.sleep(0.5)

    flipper_port = _find_flipper()
    if flipper_port:
        sup.start(
            "flipper",
            [py, os.path.join(REPO_ROOT, "demo", "flipper_badge_bridge.py"),
             "--port", flipper_port, "--url", f"http://127.0.0.1:{args.backend_port}"],
        )
    else:
        print("[notice] Flipper Zero not attached via USB — skipping 1-tap bridge (BadUSB/manual input still active).")

    if args.with_attacker:
        run_attacker_role(sup, args, wait=False)

    print("\n" + "=" * 62)
    print("  OmniGuard SOC Demo Stack is LIVE (Ctrl+C to stop & clean up)")
    print(f"  Dashboard : http://localhost:{args.frontend_port}")
    print(f"  API Docs  : http://localhost:{args.backend_port}/docs")
    print("=" * 62 + "\n")


def run_attacker_role(sup: ProcessSupervisor, args: argparse.Namespace, wait: bool = True) -> None:
    py = _venv_python()
    if IS_WIN and not sup.win_firewall_added:
        demo_ports = sorted({args.backend_port, args.frontend_port, args.portal_port, args.c2_port, 4444})
        sup.win_firewall_added = _setup_win_firewall(demo_ports)
    sup.start(
        "portal",
        [py, os.path.join(REPO_ROOT, "adversary-simulation", "portal", "mock_portal.py"),
         "--port", str(args.portal_port)],
    )
    sup.start(
        "c2",
        [py, os.path.join(REPO_ROOT, "adversary-simulation", "c2", "listener.py"),
         "--port", str(args.c2_port)],
    )
    if wait:
        print("\n" + "=" * 62)
        print("  OmniGuard Attacker/C2 Demo is LIVE (Ctrl+C to stop)")
        print(f"  Fake Portal  : http://0.0.0.0:{args.portal_port}/login.html")
        print(f"  Fake CAPTCHA : http://0.0.0.0:{args.portal_port}/captcha")
        print(f"  C2 Listener  : 0.0.0.0:{args.c2_port}")
        print("=" * 62 + "\n")


def run_victim_role(sup: ProcessSupervisor, args: argparse.Namespace) -> None:
    py = _venv_python()
    sup.start(
        "containment-agent",
        [py, os.path.join(REPO_ROOT, "demo", "containment_agent.py")],
        env={
            "ANALYST_IP": args.soc_ip,
            "HOST": args.host,
            "C2_PORTS": args.c2_ports,
        },
    )
    print("\n" + "=" * 62)
    print("  OmniGuard Victim Containment Agent is LIVE (Ctrl+C restores net & exits)")
    print(f"  Host Name : {args.host}")
    print(f"  SOC IP    : {args.soc_ip}:{args.backend_port}")
    print("=" * 62 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Single-file OmniGuard Live Demo Launcher & Cleaner")
    parser.add_argument("--role", choices=["soc", "attacker", "victim"], default="soc",
                        help="Which machine role to run (default: soc)")
    parser.add_argument("--with-attacker", action="store_true",
                        help="When --role soc, also launch mock_portal + C2 listener locally")
    parser.add_argument("--backend-port", type=int, default=8000)
    parser.add_argument("--frontend-port", type=int, default=5173)
    parser.add_argument("--portal-port", type=int, default=8080)
    parser.add_argument("--c2-port", type=int, default=9000)
    parser.add_argument("--soc-ip", default="192.168.137.1", help="SOC IP for --role victim (default: 192.168.137.1)")
    parser.add_argument("--host", default="kali-victim", help="Victim hostname (default: kali-victim)")
    parser.add_argument("--c2-ports", default="9000,4444,8080", help="C2 ports to block on isolate")
    parser.add_argument("--ntfy-topic", default=os.getenv("NTFY_TOPIC", ""), help="Optional ntfy.sh topic for phone alerts")
    parser.add_argument("--dashboard-url", default=os.getenv("DASHBOARD_PUBLIC_URL", "http://192.168.137.1:5173"))
    parser.add_argument("--skip-warmup", action="store_true", help="Skip Ollama warmup ping")
    args = parser.parse_args()

    sup = ProcessSupervisor()
    atexit.register(sup.cleanup)

    def _on_signal(signum, frame):
        sup.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, _on_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _on_signal)

    if args.role == "soc":
        run_soc_role(sup, args)
    elif args.role == "attacker":
        run_attacker_role(sup, args, wait=True)
    else:
        run_victim_role(sup, args)

    # Keep supervisor alive while child processes run
    while True:
        alive = any(p.poll() is None for _, p in sup.procs)
        if not alive:
            print("[supervisor] All child processes exited.")
            break
        time.sleep(0.5)


if __name__ == "__main__":
    main()
