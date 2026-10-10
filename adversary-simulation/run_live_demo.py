#!/usr/bin/env python3
"""OmniGuard Live Demo Scenario Orchestrator

Runs an automated or step-by-step demonstration of the full 4-stage OmniGuard SOC pipeline:
  Stage 1: Ingress (VerifyEye intercepts phishing credential harvester)
  Stage 2: Egress (SpectraC2 detects jittered encrypted C2 beaconing)
  Stage 3: Graph Correlation (Neo4j multi-entity attack topology)
  Stage 4: Triage & Containment (1-click EDR host isolation)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from urllib.parse import urlparse
import httpx

BACKEND_URL = "http://localhost:8000"
SPECTRAC2_URL = "http://localhost:8001"
MOCK_PORTAL_PORT = 8080
C2_PORT = 8443
VICTIM_HOST = "WORKSTATION-CORP-01"
VICTIM_USER = "maharjan"

def banner():
    print("""
========================================================================
   🛡️  OMNIGUARD SOC: LIVE ADVERSARY SIMULATION & DEFENSE DEMO  🛡️
========================================================================
    """)

def check_services():
    print("[*] Checking OmniGuard core services...")
    with httpx.Client(timeout=3.0) as client:
        # Backend
        try:
            r = client.get(f"{BACKEND_URL}/health")
            if r.status_code == 200:
                print(f"  [✓] OmniGuard Backend API: OK ({BACKEND_URL})")
            else:
                print(f"  [!] Backend responded with status {r.status_code}")
        except Exception:
            print(f"  [❌] OmniGuard Backend is NOT reachable at {BACKEND_URL}")
            print(f"       Please run: uvicorn backend.main:app --port 8000")
            return False

        # SpectraC2
        try:
            r = client.get(f"{SPECTRAC2_URL}/health")
            if r.status_code == 200:
                print(f"  [✓] SpectraC2 Engine API: OK ({SPECTRAC2_URL})")
            else:
                print(f"  [!] SpectraC2 responded with status {r.status_code}")
        except Exception:
            print(f"  [❌] SpectraC2 Engine is NOT reachable at {SPECTRAC2_URL}")
            print(f"       Please run: uvicorn spectrac2-engine.service.main:app --port 8001")
            return False

    return True

def run_stage_1(interactive=True):
    print("\n------------------------------------------------------------------------")
    print("STAGE 1: PHYSICAL INGRESS & ZERO-HOUR CREDENTIAL HARVEST INTERCEPTION")
    print("------------------------------------------------------------------------")
    print(f"Vector: Flipper Zero BadUSB keystroke injects browser to fake SSO portal.")
    print(f"Target: http://localhost:{MOCK_PORTAL_PORT}/login.html")
    print(f"Defense: VerifyEye analyzes DOM, identifies brand spoofing & steals form action.")
    
    if interactive:
        input("\n[Press Enter to launch Mock Phishing Portal & trigger VerifyEye inspection...]")

    # Start mock portal in background
    portal_proc = subprocess.Popen(
        [sys.executable, "adversary-simulation/portal/mock_portal.py", "--port", str(MOCK_PORTAL_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)

    try:
        # Run VerifyEye CLI against the mock portal
        verifyeye_cmd = [
            sys.executable,
            "verifyeye-ingress/main.py",
            "--url", f"http://127.0.0.1:{MOCK_PORTAL_PORT}/login.html",
            "--host", VICTIM_HOST,
            "--user", VICTIM_USER,
            "--api", BACKEND_URL,
        ]
        res = subprocess.run(verifyeye_cmd, capture_output=True, text=True)
        print(res.stdout)
        if res.returncode != 0:
            print(f"[!] VerifyEye error: {res.stderr}")
    finally:
        portal_proc.terminate()

def run_stage_2(interactive=True):
    print("\n------------------------------------------------------------------------")
    print("STAGE 2: POST-EXPLOITATION EGRESS & ENCRYPTED C2 BEACONING DETECTION")
    print("------------------------------------------------------------------------")
    print(f"Vector: Compromised host ({VICTIM_HOST}) dials external C2 listener.")
    print(f"Evasion: Implant injects 25% randomized timing jitter to bypass static rules.")
    print(f"Defense: SpectraC2 computes FFT & Power Spectral Density to extract period.")

    if interactive:
        input("\n[Press Enter to start C2 Listener & execute Jittered Beacon Agent...]")

    # Start C2 listener in background
    listener_proc = subprocess.Popen(
        [sys.executable, "adversary-simulation/c2/listener.py", "--port", str(C2_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)

    try:
        # Run beacon agent in fast-mode (demo accelerated) for 10 beacons
        beacon_cmd = [
            sys.executable,
            "adversary-simulation/c2/beacon_agent.py",
            "--server", f"http://127.0.0.1:{C2_PORT}",
            "--host", VICTIM_HOST,
            "--user", VICTIM_USER,
            "--interval", "5.0",
            "--jitter", "0.25",
            "--count", "10",
            "--fast-mode",
            "--spectrac2-url", SPECTRAC2_URL,
            "--api-url", BACKEND_URL,
        ]
        res = subprocess.run(beacon_cmd, text=True)
    finally:
        listener_proc.terminate()

def run_stage_3():
    print("\n------------------------------------------------------------------------")
    print("STAGE 3: MULTI-RELATIONAL GRAPH CORRELATION IN NEO4J")
    print("------------------------------------------------------------------------")
    print(f"Retrieving unified attack graph for victim host: {VICTIM_HOST}...")

    with httpx.Client(timeout=5.0) as client:
        try:
            r = client.get(f"{BACKEND_URL}/graph/host/{VICTIM_HOST}")
            if r.status_code == 200:
                data = r.json()
                nodes = data.get("nodes", [])
                edges = data.get("edges", [])
                node_map = {}
                for n in nodes:
                    d = n.get("data", {})
                    nid = d.get("id")
                    disp = d.get("display") or d.get("label") or nid
                    node_map[nid] = (d.get("label", "Entity"), disp)

                print(f"[✓] Correlated Attack Subgraph retrieved from Neo4j:")
                print(f"    ├─ Entities ({len(nodes)}):")
                for nid, (lbl, disp) in node_map.items():
                    print(f"    │   • [{lbl}] {disp}")
                print(f"    └─ Attack Relationships ({len(edges)}):")
                for e in edges:
                    d = e.get("data", {})
                    src_id = d.get("source")
                    tgt_id = d.get("target")
                    rel_type = d.get("type", "CONNECTED_TO")
                    src_name = node_map.get(src_id, ("?", src_id))[1]
                    tgt_name = node_map.get(tgt_id, ("?", tgt_id))[1]
                    print(f"        • ({src_name}) ──[{rel_type}]──► ({tgt_name})")
            else:
                print(f"[!] Could not retrieve host subgraph: {r.status_code} {r.text}")
        except Exception as e:
            print(f"[!] Graph query failed: {e}")

def run_stage_4(interactive=True):
    print("\n------------------------------------------------------------------------")
    print("STAGE 4: AUTONOMOUS INCIDENT TRIAGE & 1-CLICK HOST CONTAINMENT")
    print("------------------------------------------------------------------------")
    print(f"Target: {VICTIM_HOST}")
    print(f"Action: Trigger EDR network containment to sever C2 channel.")

    if interactive:
        input("\n[Press Enter to execute 1-Click Host Isolation...]")

    with httpx.Client(timeout=5.0) as client:
        try:
            r = client.post(f"{BACKEND_URL}/hosts/{VICTIM_HOST}/isolate")
            if r.status_code in (200, 202):
                res = r.json()
                print(f"[✓] Host Isolation Action Confirmed!")
                print(f"    Status:  {res.get('status')}")
                print(f"    Message: {res.get('message')}")
                print(f"[🛡️] Intrusion chain successfully terminated. Demo complete!")
            else:
                print(f"[!] Host isolation failed: {r.status_code} {r.text}")
        except Exception as e:
            print(f"[!] Host isolation request error: {e}")

def main():
    parser = argparse.ArgumentParser(description="OmniGuard End-to-End Live Demo Runner")
    parser.add_argument("--non-interactive", action="store_true", help="Run without pausing between stages")
    args = parser.parse_args()

    banner()
    if not check_services():
        print("\n[!] Please ensure all backend microservices are up before running demo.")
        sys.exit(1)

    interactive = not args.non_interactive

    run_stage_1(interactive)
    run_stage_2(interactive)
    run_stage_3()
    run_stage_4(interactive)

if __name__ == "__main__":
    main()
