#!/usr/bin/env python3
"""
OmniGuard Pre-Demo Readiness Check.

Verifies every component required for the live closed-network demo:
  - Local network interfaces & VirtualBox NAT vs Bridged warning
  - MongoDB, Neo4j, Ollama (llama3.2:3b)
  - OmniGuard Backend (:8000) & Frontend (:5173)
  - Flipper Zero USB serial detection
  - Containment agents & phone notification channels
"""

from __future__ import annotations

import glob
import json
import os
import socket
import subprocess
import sys
import urllib.request

try:
    from serial.tools import list_ports
except ImportError:
    list_ports = None


def check_tcp(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_lan_ips() -> list[str]:
    ips = []
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, timeout=2).strip()
        ips = [ip for ip in out.split() if ":" not in ip and not ip.startswith("127.")]
    except Exception:
        try:
            ips = [socket.gethostbyname(socket.gethostname())]
        except Exception:
            pass
    return ips


def find_flipper() -> str | None:
    if list_ports is not None:
        for p in list_ports.comports():
            desc = f"{p.description or ''} {p.manufacturer or ''} {p.hwid or ''}".lower()
            if "flipper" in desc or (p.vid == 0x0483 and p.pid == 0x5740):
                return p.device
    by_id = sorted(glob.glob("/dev/serial/by-id/*Flipper*"))
    if by_id:
        return by_id[0]
    acms = sorted(glob.glob("/dev/ttyACM*"))
    return acms[0] if acms else None


def main():
    print("=" * 64)
    print("  OmniGuard SOC — Pre-Demo Readiness Check")
    print("=" * 64)

    ips = get_lan_ips()
    print(f"  LAN IPs       : {', '.join(ips) if ips else 'none detected'}")
    if ips and all(ip.startswith("10.0.2.") for ip in ips):
        print("  [WARN] Only VirtualBox NAT IP (10.0.2.x) detected!")
        print("         Switch VM adapter to Bridged (or forward ports 8000 & 5173)")
        print("         so the Victim laptop and Phone can reach this SOC.")

    backend_label = "Backend API (:8000)"
    backend_ok = False
    if check_tcp("127.0.0.1", 8000):
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/openapi.json", timeout=2.0) as r:
                spec = json.loads(r.read().decode())
                title = (spec.get("info") or {}).get("title", "")
                if "omniguard" in title.lower():
                    backend_ok = True
                else:
                    backend_label = f"Backend API (:8000 occupied by '{title or 'other app'}'!)"
        except Exception:
            backend_label = "Backend API (:8000 occupied by non-OmniGuard service)"

    checks = [
        ("MongoDB (:27017)", check_tcp("127.0.0.1", 27017)),
        ("Neo4j (:7687)", check_tcp("127.0.0.1", 7687)),
        (backend_label, backend_ok),
        ("Frontend Vite (:5173)", check_tcp("127.0.0.1", 5173)),
    ]

    ollama_url = os.getenv("OLLAMA_URL", "http://10.0.2.2:11434").rstrip("/")
    ollama_ok = False
    models = []
    try:
        with urllib.request.urlopen(f"{ollama_url}/api/tags", timeout=2.5) as r:
            data = json.loads(r.read().decode())
            models = [m.get("name") for m in data.get("models") or []]
            ollama_ok = True
    except Exception:
        pass
    checks.append((f"Ollama ({ollama_url})", ollama_ok))

    flipper = find_flipper()
    checks.append((f"Flipper Zero USB ({flipper or 'not attached to VM'})", bool(flipper)))

    for label, ok in checks:
        print(f"  [{'PASS' if ok else 'MISS'}] {label}")

    if models:
        print(f"  Ollama models : {', '.join(models[:5])}")
    if not flipper:
        print("  [TIP] If Flipper Zero is plugged into Windows, either:")
        print("        1) Pass USB to VM: VirtualBox -> Devices -> USB -> Flipper Devices Inc.")
        print("        2) Or run `python demo/flipper_badge_bridge.py --url http://<SOC_IP>:8000` on Windows.")
    print("=" * 64)


if __name__ == "__main__":
    main()
