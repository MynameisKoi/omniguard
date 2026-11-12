#!/usr/bin/env python3
"""
C2 BEACON SIMULATOR  —  benign demo tool for the OmniGuard closed-network demo.

What this is (and is NOT):
  * It makes a small HTTP request to the analyst machine every few seconds and
    records when it sent each one and when the reply came back. That regular
    timing is the ONLY thing a real C2 beacon and this script have in common --
    and regular timing is exactly what the SpectraC2 engine detects.
  * It hands those real timestamps to SpectraC2's ML model
    (/api/v1/classify-flow). The model decides on its own whether this looks
    like a beacon and, if so, returns an alert, which we post to the SOC.
  * It is NOT malware. It downloads nothing, installs nothing, hides nothing,
    steals nothing, and does not survive a reboot. It runs in plain sight in a
    terminal and stops when you close it. A teammate runs it knowingly as the
    "attacker" side of the demo.

Run it on the "victim" laptop:
    python3 beacon_sim.py

Everything you'd normally change is right below.
"""

import json
import random
import time
import urllib.request
import urllib.error

# ── settings ─────────────────────────────────────────────────────────────────
ANALYST_IP = "192.168.1.234"   # the SOC machine (runs the backend + SpectraC2)
HOST       = "VICTIM-WIN-01"   # this machine's name -- MATCH the name your
                               # VerifyEye extension uses, so the phishing alert
                               # and this beacon land on the same host and the
                               # dashboard correlates them into one compromise.
USER       = None              # optional account name, or leave as None
DST_IP     = ANALYST_IP        # the "listener" this victim beacons to
INGEST_KEY = ""                # only needed if the SOC sets INGEST_API_KEYS

BEATS      = 20                # beacons to send (gives 40 packets; needs >= 3)
INTERVAL   = 2.5               # seconds between beacons (the beacon period)
JITTER     = 0.2               # +/- 20% random wobble, like a real beacon

CORE    = f"http://{ANALYST_IP}:8000"   # SOC core API
SPECTRA = f"http://{ANALYST_IP}:8001"   # SpectraC2 engine
# ─────────────────────────────────────────────────────────────────────────────


def _post(url, payload):
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if INGEST_KEY:
        headers["X-Ingest-Key"] = INGEST_KEY
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def _ping(url):
    """One real request to the listener, so traffic actually crosses the LAN."""
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            r.read(1)
    except Exception:
        pass  # a failed beat is fine -- we only need the timing


def main():
    print("=" * 62)
    print("  C2 BEACON SIMULATOR  (benign demo -- visible, no payload)")
    print(f"  victim host : {HOST}")
    print(f"  listener    : {DST_IP}  (the analyst machine)")
    print(f"  pattern     : every ~{INTERVAL}s, {BEATS} beacons")
    print("=" * 62)

    # 1. Beacon loop. Each beat = a real request (fwd) and its reply (bwd),
    #    then a sleep -- the same request/ACK/sleep shape a real beacon has.
    timestamps, sizes, directions = [], [], []
    for i in range(1, BEATS + 1):
        timestamps.append(time.time())          # fwd: beacon check-in sent
        sizes.append(random.randint(80, 260))
        directions.append("fwd")

        _ping(f"{CORE}/health")                  # real round trip over the LAN

        timestamps.append(time.time())          # bwd: listener's reply
        sizes.append(random.randint(60, 150))
        directions.append("bwd")

        print(f"  beacon {i:>2}/{BEATS}  -> heartbeat to {DST_IP}  "
              f"(simulated exfil: 'chunk {i}')")
        if i < BEATS:
            time.sleep(max(0.0, INTERVAL * (1.0 + random.uniform(-JITTER, JITTER))))

    # 2. Hand the real timing to SpectraC2's ML model for a verdict.
    print("\n  sending flow timing to SpectraC2 for ML analysis...")
    try:
        result = _post(f"{SPECTRA}/api/v1/classify-flow", {
            "timestamps": timestamps,
            "packet_sizes": sizes,
            "directions": directions,
            "host": HOST,
            "user": USER,
            "dst_ip": DST_IP,
        })
    except urllib.error.URLError as e:
        print(f"  ! could not reach SpectraC2 at {SPECTRA}: {e}")
        print(f"    is the engine running on {ANALYST_IP}:8001, and are both")
        print("    machines on the same WiFi?")
        return

    print(f"  SpectraC2 verdict: is_beacon={result.get('is_beacon')}  "
          f"threat_score={result.get('threat_score')}  "
          f"period=~{result.get('dominant_period')}s  "
          f"severity={result.get('severity')}")

    alert = result.get("alert")
    if not alert:
        print("\n  model did not flag this as a beacon -- raise BEATS or lower")
        print("  JITTER and run it again.")
        return

    # 3. Post the model's alert to the SOC -- it shows up live on the dashboard.
    posted = _post(f"{CORE}/alerts", alert)
    print(f"\n  ALERT RAISED on the SOC dashboard  (id: {posted.get('alert_id', '?')})")
    print(f"  -> host {HOST} now has a C2 beacon detection.")
    print("  -> if this host was also phished, the dashboard will correlate")
    print("     the two into a likely-compromised machine.")
    print("\n  switch to the analyst dashboard to see it.")


if __name__ == "__main__":
    main()
