#!/usr/bin/env python3
"""OmniGuard — Victim Preflight Connectivity Check.

Run this ON THE VICTIM MACHINE *before* the demo. It proves the victim can
reach the SOC on BOTH paths the demo depends on:

  1. VerifyEye extension path   -> SOC :8000  GET /brands   (and :8100 /verify)
  2. Containment agent  path    -> SOC :8000  GET /agent/containment/poll

If every required check is GREEN, the plumbing is good and you can start the
real test. If anything is RED, it tells you the likely fix (almost always a
wrong SOC IP in the extension / agent, or the SOC not running / a firewall).

Zero dependencies — pure stdlib, same as the containment agent. Runs on
Windows / Mac / Linux with just Python 3.

Usage:
    python demo/victim_preflight.py --soc-ip 192.168.1.234
    python demo/victim_preflight.py --soc-ip 192.168.137.50 --host windows-victim

On Khoi's hotspot, --soc-ip is your MAC's .137.x address (NOT Khoi's .137.1,
that's the attacker). Find it on the Mac with:  ipconfig getifaddr en0
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

OK = "\033[92m"   # green
BAD = "\033[91m"  # red
WARN = "\033[93m" # yellow
DIM = "\033[2m"
END = "\033[0m"


def _supports_color() -> bool:
    return sys.stdout.isatty()


def c(code: str, s: str) -> str:
    return f"{code}{s}{END}" if _supports_color() else s


def _get(url: str, timeout: float = 4.0):
    """GET a URL. Returns (status_code, body_text) or raises."""
    req = urllib.request.Request(url, headers={"User-Agent": "omniguard-preflight"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "ignore")


def check(label: str, url: str, parse=None):
    """Run one GET check. Returns (ok: bool, optional: bool, detail: str)."""
    try:
        status, body = _get(url)
        if status == 200:
            detail = parse(body) if parse else "200 OK"
            return True, f"{c(OK, '✅')} {detail}"
        return False, f"{c(BAD, '❌')} got HTTP {status}"
    except urllib.error.HTTPError as e:
        # reached the server but it answered non-2xx -- still proves connectivity
        return False, f"{c(WARN, '⚠️')}  reached server but HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        reason = getattr(e, "reason", e)
        return False, f"{c(BAD, '❌')} cannot connect ({reason})"


def _brands_summary(body: str) -> str:
    try:
        data = json.loads(body)
        names = [b.get("name", "?") for b in data]
        has_ms = "Microsoft" in names
        tag = "" if has_ms else c(WARN, "  (note: Microsoft not in list!)")
        return f"200 OK — {len(names)} brands: {', '.join(names[:6])}{'...' if len(names) > 6 else ''}{tag}"
    except Exception:
        return "200 OK (could not parse brand JSON)"


def main() -> int:
    p = argparse.ArgumentParser(description="Victim-side connectivity preflight for the OmniGuard demo.")
    p.add_argument("--soc-ip", default="192.168.1.234",
                   help="SOC machine IP = your Mac (NOT the attacker). Default 192.168.1.234")
    p.add_argument("--host", default="windows-victim",
                   help="This victim's host name (must match the --host you give the agent)")
    p.add_argument("--backend-port", type=int, default=8000)
    p.add_argument("--verify-port", type=int, default=8100)
    p.add_argument("--polls", type=int, default=3, help="How many times to poll the agent endpoint")
    args = p.parse_args()

    soc = args.soc_ip
    base = f"http://{soc}:{args.backend_port}"
    verify = f"http://{soc}:{args.verify_port}"

    print("=" * 64)
    print("  OmniGuard — Victim Preflight Connectivity Check")
    print("=" * 64)
    print(f"  SOC (backend) : {c(DIM, base)}")
    print(f"  Host identity : {c(DIM, args.host)}")
    print(f"  {c(DIM, '(On Khoi hotspot, SOC IP is your Mac .137.x — not Khoi .137.1)')}")
    print("-" * 64)

    required_ok = True

    # 1. Backend alive at all
    ok, detail = check("backend", f"{base}/health", lambda b: "200 OK " + b.strip()[:40])
    print(f"  [1/4] Backend reachable  (/health)        {detail}")
    required_ok = required_ok and ok

    # 2. VerifyEye path -- the exact call the extension makes on startup
    ok, detail = check("brands", f"{base}/brands", _brands_summary)
    print(f"  [2/4] VerifyEye -> SOC   (/brands)        {detail}")
    required_ok = required_ok and ok

    # 3. Containment agent path -- poll a few times like the real agent does
    poll_url = f"{base}/agent/containment/poll?host={args.host}"
    results = []
    for _ in range(max(1, args.polls)):
        ok_i, _d = check("poll", poll_url)
        results.append(ok_i)
    poll_ok = all(results)
    codes = ", ".join("200" if r else "FAIL" for r in results)
    mark = c(OK, "✅") if poll_ok else c(BAD, "❌")
    print(f"  [3/4] Containment agent  (/agent/.../poll) {mark} x{len(results)} -> [{codes}]")
    required_ok = required_ok and poll_ok

    # 4. Visual verify agent -- OPTIONAL (demo works without it)
    ok_v, detail_v = check("verify", f"{verify}/", lambda b: "200 OK")
    if ok_v:
        print(f"  [4/4] Visual verify      (:{args.verify_port})           {c(OK, '✅')} running (optional)")
    else:
        print(f"  [4/4] Visual verify      (:{args.verify_port})           {c(WARN, '⚠️  not running — optional, OK to skip')}")

    print("-" * 64)
    if required_ok:
        print(f"  RESULT: {c(OK, '✅ VICTIM CAN CONNECT TO THE SOC.')}")
        print(f"          Both VerifyEye and the containment agent can reach the")
        print(f"          backend. Plumbing is GREEN — you can start the test.")
        print("=" * 64)
        return 0
    else:
        print(f"  RESULT: {c(BAD, '❌ VICTIM CANNOT FULLY CONNECT.')}")
        print(f"          Most likely causes:")
        print(f"            • Wrong SOC IP — you used {c(WARN, soc)}. Is that your Mac's")
        print(f"              current IP?  On the Mac run:  ipconfig getifaddr en0")
        print(f"            • SOC not running — start the backend on the Mac.")
        print(f"            • Firewall on the Mac blocking the LAN — allow :8000.")
        print(f"            • Both laptops must be on the SAME Wi-Fi / hotspot.")
        print("=" * 64)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
