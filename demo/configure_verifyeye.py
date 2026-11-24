#!/usr/bin/env python3
"""OmniGuard — Configure the VerifyEye extension (no hand-editing).

Sets the three per-machine values at the top of the extension's background.js
so you don't have to open the file by hand:

  * CORE    -> the SOC backend  (http://<soc-ip>:8000)
  * VERIFY  -> the screenshot service (http://<soc-ip>:8100)
  * HOST    -> this victim's name (must match the containment agent)

Run it BEFORE you load / reload the extension in Chrome. Pure stdlib, so it
runs on the Windows victim with just Python 3.

Usage (mirrors the agent command):
    python demo/configure_verifyeye.py --soc-ip 192.168.1.234
    python demo/configure_verifyeye.py --soc-ip 192.168.137.50 --host FINANCE-WS-07

Then in Chrome: chrome://extensions -> reload the extension (or Load unpacked
the verifyeye-ingress/extension folder the first time).
"""
from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BG_JS = os.path.normpath(os.path.join(HERE, "..", "verifyeye-ingress", "extension", "background.js"))


def _replace_value(text: str, const_name: str, new_value: str) -> tuple[str, bool]:
    """Replace the string literal assigned to `const <const_name> = "..."`,
    keeping everything else on the line (comments included). Returns (text, changed)."""
    pattern = re.compile(r'(const\s+' + re.escape(const_name) + r'\s*=\s*")[^"]*(")')
    new_text, n = pattern.subn(lambda m: m.group(1) + new_value + m.group(2), text, count=1)
    return new_text, (n > 0)


def main() -> int:
    p = argparse.ArgumentParser(description="Configure the VerifyEye extension's background.js for this machine.")
    p.add_argument("--soc-ip", required=True, help="SOC machine IP = the Mac (NOT the attacker)")
    p.add_argument("--host", default="WORKSTATION-CORP-01",
                   help="This victim's name; MUST match the agent's --host (default: WORKSTATION-CORP-01)")
    p.add_argument("--backend-port", type=int, default=8000)
    p.add_argument("--verify-port", type=int, default=8100)
    p.add_argument("--file", default=BG_JS, help="Path to background.js (default: auto-detected)")
    args = p.parse_args()

    if not os.path.exists(args.file):
        print(f"ERROR: could not find background.js at:\n  {args.file}\n"
              f"Run this from the repo root, or pass --file <path>.", file=sys.stderr)
        return 2

    with open(args.file, "r", encoding="utf-8") as f:
        text = f.read()

    core = f"http://{args.soc_ip}:{args.backend_port}"
    verify = f"http://{args.soc_ip}:{args.verify_port}"

    changes = []
    for name, value in (("CORE", core), ("VERIFY", verify), ("HOST", args.host)):
        text, ok = _replace_value(text, name, value)
        changes.append((name, value, ok))

    missing = [n for n, _, ok in changes if not ok]
    if missing:
        print(f"ERROR: couldn't find these consts in background.js: {', '.join(missing)}.\n"
              f"The file format may have changed — open it and check lines near the top.",
              file=sys.stderr)
        return 3

    with open(args.file, "w", encoding="utf-8") as f:
        f.write(text)

    print("=" * 60)
    print("  VerifyEye extension configured ✅")
    print("=" * 60)
    print(f"  CORE   (alerts/brands) : {core}")
    print(f"  VERIFY (screenshots)   : {verify}")
    print(f"  HOST   (this victim)   : {args.host}")
    print(f"  file                   : {args.file}")
    print("-" * 60)
    print("  NEXT: Chrome -> chrome://extensions -> reload the extension")
    print("        (first time: 'Load unpacked' -> verifyeye-ingress/extension)")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
