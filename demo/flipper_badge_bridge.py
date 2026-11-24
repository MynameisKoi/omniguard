#!/usr/bin/env python3
"""
Flipper Zero Live 1-Tap RFID/NFC Login Bridge for OmniGuard SOC.

Connects to a USB-attached Flipper Zero (/dev/ttyACM0 or Flipper serial ID),
continuously runs `rfid read` (125 kHz HID / EM4100), extracts the card hex UID
(e.g. `2E B7 76` for HID H10301), and posts it to `POST /auth/badge-tap` so
the Login UI logs the analyst in automatically on a single physical card tap.

Usage:
    ./.venv/bin/python demo/flipper_badge_bridge.py
    ./.venv/bin/python demo/flipper_badge_bridge.py --port /dev/ttyACM0 --url http://localhost:8000
"""

import argparse
import glob
import json
import re
import signal
import sys
import time
import urllib.error
import urllib.request

import serial
from serial.tools import list_ports

# Matches 3+ space- or colon-separated hex bytes like "2E B7 76" or "7A:39:B1:04"
HEX_UID_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?:[\s:][0-9A-Fa-f]{2}){2,7})\b")
FC_RE = re.compile(r"\bFC\s*:\s*(\d+)\b", re.IGNORECASE)
CARD_RE = re.compile(r"\bCard\s*:\s*(\d+)\b", re.IGNORECASE)


def hid_fc_card_to_hex(fc: int, card: int) -> str:
    """Convert HID H10301 Facility Code (8-bit) + Card Number (16-bit) to hex UID."""
    return f"{fc & 0xFF:02X}{card & 0xFFFF:04X}"


def find_flipper_port() -> str | None:
    for p in list_ports.comports():
        desc = f"{p.description or ''} {p.manufacturer or ''} {p.hwid or ''}".lower()
        if "flipper" in desc or (p.vid == 0x0483 and p.pid == 0x5740):
            return p.device
    by_id = sorted(glob.glob("/dev/serial/by-id/*Flipper*"))
    if by_id:
        return by_id[0]
    acms = sorted(glob.glob("/dev/ttyACM*"))
    return acms[0] if acms else None


def post_badge_tap(api_url: str, badge_uid: str) -> tuple[bool, str]:
    body = json.dumps({"badge_uid": badge_uid}).encode()
    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/auth/badge-tap",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return True, f"Authenticated {data.get('email')} (badge {data.get('badge_uid')})"
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="ignore")
        return False, f"HTTP {e.code}: {detail}"
    except Exception as e:
        return False, str(e)


def run_bridge(port: str, api_url: str) -> None:
    print("=" * 60)
    print("  OmniGuard Flipper Zero 1-Tap Badge Bridge")
    print(f"  Flipper Port : {port}")
    print(f"  Backend URL  : {api_url}")
    print("  Note: Keep Flipper on its Home screen (exit any open app).")
    print("  Tap your HID H10301 / RFID card on the Flipper to sign in.")
    print("=" * 60)

    ser = serial.Serial(port, 230400, timeout=0.25)
    ser.dtr = True
    ser.rts = True

    def _shutdown(*_):
        try:
            ser.write(b"\x03\r\n")
            ser.close()
        except Exception:
            pass
        print("\nBridge stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Clear any pending CLI state and enter rfid read loop
    ser.write(b"\x03\r\n")
    time.sleep(0.3)
    ser.reset_input_buffer()
    ser.write(b"rfid read\r\n")

    last_uid = None
    last_time = 0.0
    pending_fc = None
    buf = ""

    while True:
        try:
            n = ser.in_waiting
            if not n:
                time.sleep(0.05)
                continue
            chunk = ser.read(n).decode(errors="ignore")
        except serial.SerialException as e:
            print(f"  ! Serial read hiccup ({e}); reopening {port}...")
            try:
                ser.close()
            except Exception:
                pass
            time.sleep(1.0)
            ser = serial.Serial(port, 230400, timeout=0.1)
            ser.dtr = True
            ser.rts = True
            time.sleep(0.3)
            ser.write(b"\x03\r\n")
            time.sleep(0.2)
            ser.write(b"rfid read\r\n")
            buf = ""
            continue

        buf += chunk
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            clean = line.strip()
            if not clean:
                continue

            if clean.endswith(">:") or ("Reading" not in clean and "could not" in clean.lower()):
                if ">:" in clean:
                    time.sleep(0.2)
                    ser.write(b"rfid read\r\n")
                continue

            uid = None
            fc_m = FC_RE.search(clean)
            if fc_m:
                pending_fc = int(fc_m.group(1))
                continue

            card_m = CARD_RE.search(clean)
            if card_m and pending_fc is not None:
                uid = hid_fc_card_to_hex(pending_fc, int(card_m.group(1)))
                pending_fc = None
            else:
                m = HEX_UID_RE.search(clean)
                if m:
                    uid = m.group(1).replace(" ", "").replace(":", "").upper()

            if uid:
                now = time.time()
                if uid == last_uid and (now - last_time) < 3.0:
                    continue
                last_uid = uid
                last_time = now
                print(f"\n[RFID TAP] Detected UID: {uid} ({clean})")
                ok, msg = post_badge_tap(api_url, uid)
                print(f"[SOC AUTH] {'OK' if ok else 'REJECTED'}: {msg}")
                time.sleep(0.4)
                ser.write(b"\x03\r\n")
                time.sleep(0.2)
                ser.write(b"rfid read\r\n")


def main():
    parser = argparse.ArgumentParser(description="Flipper Zero 1-Tap RFID Login Bridge")
    parser.add_argument("--port", default=None, help="Serial port (default: auto-detect Flipper)")
    parser.add_argument("--url", default="http://localhost:8000", help="OmniGuard backend URL")
    args = parser.parse_args()

    port = args.port or find_flipper_port()
    if not port:
        print("Error: Flipper Zero USB serial device not found. Connect Flipper via USB.", file=sys.stderr)
        sys.exit(1)
    run_bridge(port, args.url)


if __name__ == "__main__":
    main()

