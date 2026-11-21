#!/usr/bin/env python3
"""OmniGuard Adversary Simulation: Beaconing Implant Agent

Simulates an in-memory post-exploitation implant (e.g. Sliver or Cobalt Strike)
maintaining an outbound HTTP/TLS beacon loop with configurable randomized timing jitter.
Integrates live flow reporting directly with the SpectraC2 engine and OmniGuard SOC API.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from urllib.parse import urlparse
import httpx

def main():
    parser = argparse.ArgumentParser(description="OmniGuard Emulated C2 Beaconing Agent")
    parser.add_argument("--server", default="http://127.0.0.1:8443", help="Target C2 listener URL")
    parser.add_argument("--host", default="WORKSTATION-CORP-01", help="Affected host name")
    parser.add_argument("--user", default="maharjan", help="Target user account")
    parser.add_argument("--process", default="sliver-agent.elf", help="Process name")
    parser.add_argument("--interval", type=float, default=10.0, help="Base beacon interval in seconds (default: 10.0)")
    parser.add_argument("--jitter", type=float, default=0.25, help="Timing jitter ratio 0.0 - 0.5 (default: 0.25 = 25%)")
    parser.add_argument("--count", type=int, default=12, help="Number of beacons to send (default: 12, 0 for infinite)")
    parser.add_argument("--spectrac2-url", default="http://localhost:8001", help="SpectraC2 classification engine URL")
    parser.add_argument("--api-url", default="http://localhost:8000", help="OmniGuard backend API URL")
    parser.add_argument("--mode", choices=["classic", "rmm-watchdog"], default="classic",
                        help="C2 emulation profile: classic HTTP beacon or safe ScreenConnect/Telegram RMM watchdog")
    parser.add_argument("--fast-mode", action="store_true", help="Scale timing down 5x for high-speed live demo testing")

    args = parser.parse_args()

    base_interval = args.interval / 5.0 if args.fast_mode else args.interval
    jitter_pct = max(0.0, min(0.5, args.jitter))

    parsed = urlparse(args.server)
    dst_ip = parsed.hostname or "127.0.0.1"
    dst_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    domain = parsed.hostname

    print("==================================================")
    print("   OmniGuard Adversary Simulation: Beacon Agent   ")
    print("==================================================")
    print(f"[+] Target C2 Listener: {args.server}")
    print(f"[+] Workstation Entity: {args.host} ({args.user})")
    print(f"[+] Base Interval:     {base_interval:.1f}s (Jitter: ±{jitter_pct*100:.0f}%)")
    print(f"[+] SpectraC2 Engine:   {args.spectrac2_url}")
    print(f"[+] OmniGuard Backend:  {args.api_url}")
    print(f"[+] Emulation Profile:  {args.mode} (100% safe local lab simulation)")
    print("==================================================\n")

    if args.mode == "rmm-watchdog":
        print("[SIM] RMM Watchdog Check: simulating service check ('ScreenConnect Client') & MotW Unblock-File telemetry (no real MSI/install executed).")

    timestamps: list[float] = []
    packet_sizes: list[int] = []
    directions: list[str] = []
    beacon_idx = 0
    alerted = False

    client = httpx.Client(timeout=10.0)

    try:
        while True:
            beacon_idx += 1
            now = time.time()
            timestamps.append(now)

            # Randomize packet size between 200-500 bytes (typical C2 profile)
            req_size = random.randint(220, 480)
            packet_sizes.append(req_size)
            directions.append("fwd")

            # Execute beacon request to listener
            try:
                if args.mode == "rmm-watchdog":
                    endpoint = f"{args.server.rstrip('/')}/botDEMO_LAB_TOKEN/sendMessage"
                    body_json = {
                        "chat_id": "demo-c2-channel",
                        "text": f"ScreenConnect Watchdog | Computer: {args.host} | User: {args.user} | Heartbeat #{beacon_idx} (Simulated RMM T1219/T1102)",
                    }
                else:
                    endpoint = f"{args.server.rstrip('/')}/api/v1/heartbeat"
                    body_json = {"implant_id": "imp-01", "host": args.host, "user": args.user, "seq": beacon_idx}
                resp = client.post(
                    endpoint,
                    json=body_json,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                )
                status_code = resp.status_code
                resp_size = len(resp.content)
            except Exception as e:
                status_code = "ERR"
                resp_size = 0

            print(f"[{time.strftime('%H:%M:%S')}] Beacon #{beacon_idx:02d} -> {args.server} (HTTP {status_code}, {req_size}B)")

            # Check if we have enough flow events to trigger SpectraC2 FFT evaluation (>= 8 packets)
            if len(timestamps) >= 8 and not alerted:
                print(f"\n[🔬] Evaluating sliding window ({len(timestamps)} flow packets) with SpectraC2...")
                try:
                    payload = {
                        "timestamps": timestamps,
                        "packet_sizes": packet_sizes,
                        "directions": directions,
                        "host": args.host,
                        "user": args.user,
                        "src_ip": "10.0.1.15",
                        "dst_ip": dst_ip,
                        "domain": domain,
                    }
                    eval_resp = client.post(
                        f"{args.spectrac2_url.rstrip('/')}/api/v1/classify-flow",
                        json=payload,
                        timeout=5.0,
                    )
                    if eval_resp.status_code == 200:
                        data = eval_resp.json()
                        dom_period = data.get("dominant_period", 0.0)
                        threat_score = data.get("threat_score", 0.0)
                        is_beacon = data.get("is_beacon", False)
                        severity = data.get("severity", "high")

                        print(f"    ├─ Is Beacon:         {is_beacon}")
                        print(f"    ├─ Threat Score:      {threat_score:.3f}")
                        print(f"    ├─ Dominant Period:   {dom_period:.2f}s (Target: ~{base_interval:.1f}s)")
                        print(f"    └─ Periodicity Score: {data.get('periodicity_score', 0.0):.3f}")

                        if is_beacon:
                            print(f"[🚨] Periodic beaconing confirmed! SpectraC2 generating alert...")
                            is_rmm = args.mode == "rmm-watchdog"
                            alert_payload = {
                                "source": "spectrac2",
                                "event_type": "rmm_watchdog_c2_beaconing" if is_rmm else "encrypted_c2_beaconing",
                                "severity": severity,
                                "host": args.host,
                                "user": args.user,
                                "src_ip": "10.0.1.15",
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "domain": domain,
                                "beacon_interval": dom_period,
                                "mean_jitter": float(jitter_pct * base_interval),
                                "process_name": "powershell-rmm-watchdog-sim" if is_rmm else args.process,
                                "mitre_technique": "T1219" if is_rmm else "T1071",
                                "confidence": threat_score,
                                "description": (
                                    f"Abuse of RMM/Telegram C2 watchdog pattern detected to {dst_ip}:{dst_port} ({dom_period:.1f}s periodicity)."
                                    if is_rmm else
                                    f"Encrypted C2 beacon detected to {dst_ip}:{dst_port} with {dom_period:.1f}s dominant periodicity."
                                ),
                            }

                            backend_resp = client.post(
                                f"{args.api_url.rstrip('/')}/alerts",
                                json=alert_payload,
                                timeout=5.0,
                            )
                            if backend_resp.status_code == 201:
                                created_alert = backend_resp.json()
                                print(f"[✓] Alert ingested into OmniGuard SOC! Alert ID: {created_alert.get('alert_id')}")
                                print(f"[✓] Attack Graph node correlated on dashboard via WebSocket!\n")
                                alerted = True
                    else:
                        print(f"[!] SpectraC2 returned {eval_resp.status_code}: {eval_resp.text}")
                except Exception as eval_err:
                    print(f"[!] SpectraC2 evaluation query failed: {eval_err}")

            if args.count > 0 and beacon_idx >= args.count:
                print(f"[+] Completed {args.count} beacons. Exiting simulation.")
                break

            # Calculate sleep duration with jitter
            jitter_offset = base_interval * random.uniform(-jitter_pct, jitter_pct)
            sleep_duration = max(0.5, base_interval + jitter_offset)
            time.sleep(sleep_duration)

    except KeyboardInterrupt:
        print("\n[-] Beacon loop interrupted by user.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
