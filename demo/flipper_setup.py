#!/usr/bin/env python3
"""
Cross-platform Flipper Zero BadUSB Uploader for OmniGuard SOC.

Uploads OmniGuard's BadUSB scripts directly to the connected Flipper Zero SD
card (`/ext/badusb/`) over USB Serial (works on Linux /dev/ttyACM* and Windows
COM* ports).

Usage:
    python demo/flipper_setup.py
    python demo/flipper_setup.py --port COM4
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
import time

import serial
from serial.tools import list_ports

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS = [
    (
        os.path.join(REPO_ROOT, "adversary-simulation", "flipper", "badge_login_tap.txt"),
        "/ext/badusb/omniguard_login.txt",
    ),
    (
        os.path.join(REPO_ROOT, "adversary-simulation", "flipper", "badusb_clickfix_demo.txt"),
        "/ext/badusb/omniguard_clickfix_demo.txt",
    ),
]


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


def _read_until(ser: serial.Serial, marker: bytes, timeout: float = 3.0) -> str:
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        chunk = ser.read(ser.in_waiting or 1)
        if chunk:
            buf += chunk
            if marker in buf:
                break
    return buf.decode(errors="ignore")


def upload_file(ser: serial.Serial, local_path: str, remote_path: str) -> bool:
    if not os.path.exists(local_path):
        print(f"  ! Missing local file: {local_path}")
        return False
    data = open(local_path, "rb").read()

    ser.write(f"storage remove {remote_path}\r\n".encode())
    _read_until(ser, b">: ", 2.0)

    # Flipper CLI `storage write_chunk <path> <size>` prints "Ready" before reading <size> bytes
    ser.write(f"storage write_chunk {remote_path} {len(data)}\r\n".encode())
    ready_out = _read_until(ser, b"Ready", 2.5)
    if "Ready" not in ready_out:
        print(f"  [FAIL] {os.path.basename(local_path)} -> Flipper did not print Ready: {ready_out.strip()}")
        return False

    # Send in small chunks so USB CDC buffer never drops bytes
    for i in range(0, len(data), 64):
        ser.write(data[i:i + 64])
        time.sleep(0.02)
    resp = _read_until(ser, b">: ", 3.0)

    ser.write(f"storage stat {remote_path}\r\n".encode())
    stat_out = _read_until(ser, b">: ", 2.0)
    ok = "File, size:" in stat_out
    print(f"  [{'OK' if ok else 'FAIL'}] {os.path.basename(local_path)} -> {remote_path} ({len(data)} bytes)")
    if not ok:
        print(f"       write resp: {resp.strip()} | stat: {stat_out.strip()}")
    return ok


def main():
    parser = argparse.ArgumentParser(description="Upload OmniGuard BadUSB scripts to Flipper Zero")
    parser.add_argument("--port", default=None, help="Flipper serial port (auto-detected if omitted)")
    args = parser.parse_args()

    port = args.port or find_flipper_port()
    if not port:
        print("Error: Flipper Zero not detected on USB serial.")
        print("  - If running inside VirtualBox Debian VM: Devices -> USB -> Flipper Devices Inc.")
        print("  - Make sure qFlipper is closed and Flipper is on its Home screen.")
        sys.exit(1)

    print(f"Connecting to Flipper Zero on {port}...")
    ser = serial.Serial(port, 230400, timeout=0.2)
    ser.dtr = True
    ser.rts = True
    time.sleep(0.3)
    # Send Ctrl+C twice without CRLF to cleanly abort any running CLI command (e.g. rfid read)
    for _ in range(2):
        ser.write(b"\x03")
        time.sleep(0.25)
    ser.reset_input_buffer()
    ser.write(b"\r\n")
    prompt = _read_until(ser, b">: ", 2.0)
    if ">:" not in prompt:
        print("Warning: Flipper CLI prompt not detected. Ensure Flipper is on its Home screen (no app open).")

    all_ok = True
    for local_path, remote_path in SCRIPTS:
        all_ok = upload_file(ser, local_path, remote_path) and all_ok

    ser.close()
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
