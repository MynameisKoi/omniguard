#!/usr/bin/env python3
"""
OmniGuard Cyber-Physical OT Controller for Raspberry Pi 5.

Drives physical hardware (RGB LED, DC Fan via L293D, I2C LCD1602, Active Buzzer,
and DS18B20 / CPU temperature sensor) in sync with OmniGuard's attack & containment
lifecycle:

  - NORMAL      : Green LED, Fan ON,  LCD -> "SYS: NORMAL" / "FAN:ON T:xx.xC"
  - COMPROMISED : Flashing Red, Fan OFF, LCD -> "YOU ARE HACKED!!" + gibberish, 2 chirps
  - ISOLATED    : Blue LED, Fan OFF,   LCD -> "HOST ISOLATED" / "C2 KILLED BY SOC", 1 beep
  - CURED       : Green LED, Fan ON,   LCD -> "SYSTEM CURED" -> returns to NORMAL

Uses `gpiozero` (lgpio backend on Pi 5) and `smbus2` for I2C LCD1602 (0x27/0x3f).

Usage:
  python3 demo/pi_ot_controller.py                # Live mode (watches C2 + containment)
  python3 demo/pi_ot_controller.py --test-cycle   # 12s hardware wiring test
  python3 demo/pi_ot_controller.py --simulate     # Console-only dry run (no GPIO)
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import random
import signal
import subprocess
import sys
import time

STATE_FILE = "/tmp/omniguard_ot_state.json"
ROGUE_PATTERNS = ("rmm_watchdog_sim.py", "beacon_sim.py", "beacon_agent.py")
GIBBERISH_LINES = (
    "TEMP RISING >60C!",
    "#@!$ C2 :9000 !?",
    "TEMP: 64.8C WARN",
    "*%^& SHELL OPEN!",
    "!! RMM OVERRIDE !",
)

# Default BCM GPIO pin mapping (non-overlapping on Raspberry Pi 5)
DEFAULT_PINS = {
    "red": 17,      # Physical Pin 11
    "green": 27,    # Physical Pin 13
    "blue": 22,     # Physical Pin 15
    "buzzer": 23,   # Physical Pin 16
    "fan_in1": 24,  # Physical Pin 18 (L293D IN1)
    "fan_en": 25,   # Physical Pin 22 (L293D EN1)
}


class I2CLCD1602:
    """Minimal PCF8574 I2C 16x2 LCD driver using smbus2 (no RPLCD needed)."""

    LCD_CHR = 1
    LCD_CMD = 0
    LINE_1 = 0x80
    LINE_2 = 0xC0
    BACKLIGHT = 0x08
    ENABLE = 0x04

    def __init__(self, bus_num: int = 1, addr: int | None = None) -> None:
        self.bus = None
        self.addr = addr
        try:
            from smbus2 import SMBus
            self.bus = SMBus(bus_num)
            if self.addr is None:
                for cand in (0x27, 0x3F):
                    try:
                        self.bus.write_quick(cand)
                        self.addr = cand
                        break
                    except Exception:
                        continue
            if self.addr is not None:
                self._init_lcd()
        except Exception as e:
            print(f"[LCD] Disabled ({e})")
            self.bus = None
            self.addr = None

    @property
    def available(self) -> bool:
        return self.bus is not None and self.addr is not None

    def _write_byte(self, bits: int) -> None:
        if not self.available:
            return
        self.bus.write_byte(self.addr, bits | self.BACKLIGHT)

    def _toggle_enable(self, bits: int) -> None:
        time.sleep(0.0005)
        self._write_byte(bits | self.ENABLE)
        time.sleep(0.0005)
        self._write_byte(bits & ~self.ENABLE)
        time.sleep(0.0005)

    def _send(self, value: int, mode: int) -> None:
        high = mode | (value & 0xF0)
        low = mode | ((value << 4) & 0xF0)
        self._write_byte(high)
        self._toggle_enable(high)
        self._write_byte(low)
        self._toggle_enable(low)

    def _init_lcd(self) -> None:
        for cmd in (0x33, 0x32, 0x06, 0x0C, 0x28, 0x01):
            self._send(cmd, self.LCD_CMD)
            time.sleep(0.005)

    def display(self, line1: str, line2: str = "") -> None:
        if not self.available:
            return
        for addr, text in ((self.LINE_1, line1), (self.LINE_2, line2)):
            self._send(addr, self.LCD_CMD)
            padded = (text or "")[:16].ljust(16)
            for ch in padded:
                self._send(ord(ch), self.LCD_CHR)

    def clear(self) -> None:
        if self.available:
            self._send(0x01, self.LCD_CMD)
            time.sleep(0.005)

    def close(self) -> None:
        if self.bus is not None:
            try:
                self.clear()
                self.bus.close()
            except Exception:
                pass


def read_temperature_c() -> float | None:
    """Read DS18B20 1-Wire sensor on GPIO4 if wired, else Pi SoC thermal zone."""
    for dev in glob.glob("/sys/bus/w1/devices/28-*/w1_slave"):
        try:
            raw = open(dev, "r", encoding="utf-8").read()
            if "YES" in raw and "t=" in raw:
                milli = int(raw.split("t=", 1)[1].strip())
                return round(milli / 1000.0, 1)
        except Exception:
            pass
    try:
        milli = int(open("/sys/class/thermal/thermal_zone0/temp", "r").read().strip())
        return round(milli / 1000.0, 1)
    except Exception:
        return None


def _rogue_beacon_running() -> bool:
    try:
        out = subprocess.check_output(["ps", "-eo", "args="], text=True, timeout=2)
        for line in out.splitlines():
            if "pi_ot_controller" in line:
                continue
            if any(pat in line for pat in ROGUE_PATTERNS):
                return True
    except Exception:
        pass
    return False


def _read_containment_state() -> str:
    try:
        if os.path.exists(STATE_FILE):
            data = json.load(open(STATE_FILE, "r", encoding="utf-8"))
            return str(data.get("state", "normal")).lower()
    except Exception:
        pass
    return "normal"


class OTHardware:
    """Controls RGB LED, DC Fan (via Relay or L293D), Active Buzzer, and I2C LCD1602."""

    def __init__(self, simulate: bool = False, common_anode: bool = False,
                 fan_active_low: bool = False, quiet: bool = False) -> None:
        self.simulate = simulate
        self.quiet = quiet
        self.lcd = None
        self.rgb = None
        self.fan_in1 = None
        self.fan_en = None
        self.buzzer = None

        if simulate:
            return

        from gpiozero import Buzzer, DigitalOutputDevice, RGBLED
        self.rgb = RGBLED(
            red=DEFAULT_PINS["red"],
            green=DEFAULT_PINS["green"],
            blue=DEFAULT_PINS["blue"],
            active_high=not common_anode,
        )
        self.fan_in1 = DigitalOutputDevice(DEFAULT_PINS["fan_in1"], active_high=not fan_active_low)
        self.fan_en = DigitalOutputDevice(DEFAULT_PINS["fan_en"], active_high=not fan_active_low)
        self.buzzer = Buzzer(DEFAULT_PINS["buzzer"])
        self.lcd = I2CLCD1602(bus_num=1)

    def set_led(self, color: tuple[float, float, float]) -> None:
        if self.rgb is not None:
            self.rgb.color = color

    def set_fan(self, on: bool) -> None:
        if self.fan_in1 is not None and self.fan_en is not None:
            if on:
                self.fan_in1.on()
                self.fan_en.on()
            else:
                self.fan_en.off()
                self.fan_in1.off()

    def chirp(self, count: int = 1, duration: float = 0.12) -> None:
        if self.quiet or self.buzzer is None:
            return
        for i in range(count):
            self.buzzer.on()
            time.sleep(duration)
            self.buzzer.off()
            if i + 1 < count:
                time.sleep(0.08)

    def show_lcd(self, line1: str, line2: str) -> None:
        if self.lcd is not None and self.lcd.available:
            self.lcd.display(line1, line2)

    def cleanup(self) -> None:
        self.set_fan(False)
        self.set_led((0, 0, 0))
        if self.buzzer is not None:
            self.buzzer.off()
        if self.lcd is not None:
            self.lcd.close()
        for dev in (self.rgb, self.fan_in1, self.fan_en, self.buzzer):
            if dev is not None:
                try:
                    dev.close()
                except Exception:
                    pass


def run_test_cycle(hw: OTHardware) -> None:
    print("[TEST] Cycling hardware states (Normal -> Compromised -> Isolated -> Cured)...")
    for state, dur in (("normal", 3.0), ("compromised", 4.0), ("isolated", 3.0), ("cured", 2.0), ("normal", 2.0)):
        temp = read_temperature_c()
        t_str = f"{temp:.1f}C" if temp is not None else "--.-C"
        if state == "normal":
            hw.set_led((0, 1, 0))
            hw.set_fan(True)
            hw.show_lcd("SYS: NORMAL", f"FAN:ON  T:{t_str}")
            print(f"[OT] STATE=NORMAL      | LED=GREEN        | FAN=ON  | LCD='SYS: NORMAL / FAN:ON T:{t_str}'")
            time.sleep(dur)
        elif state == "compromised":
            hw.set_fan(False)
            hw.chirp(2, 0.1)
            end = time.time() + dur
            toggle = False
            while time.time() < end:
                toggle = not toggle
                hw.set_led((1, 0, 0) if toggle else (0, 0, 0))
                gib = random.choice(GIBBERISH_LINES)
                hw.show_lcd("YOU ARE HACKED!!", gib)
                print(f"[OT] STATE=COMPROMISED | LED={'RED ' if toggle else 'OFF '} (FLASH) | FAN=OFF | LCD='YOU ARE HACKED!! / {gib}'")
                time.sleep(0.35)
        elif state == "isolated":
            hw.set_led((0, 0, 1))
            hw.set_fan(False)
            hw.chirp(1, 0.12)
            hw.show_lcd("HOST ISOLATED", "C2 KILLED BY SOC")
            print("[OT] STATE=ISOLATED    | LED=BLUE         | FAN=OFF | LCD='HOST ISOLATED / C2 KILLED BY SOC'")
            time.sleep(dur)
        elif state == "cured":
            hw.set_led((0, 1, 0))
            hw.set_fan(True)
            hw.show_lcd("SYSTEM CURED", f"FAN:ON  T:{t_str}")
            print(f"[OT] STATE=CURED       | LED=GREEN        | FAN=ON  | LCD='SYSTEM CURED / FAN:ON T:{t_str}'")
            time.sleep(dur)
    print("[TEST] Hardware cycle complete.")


def run_live(hw: OTHardware) -> None:
    print("=" * 60)
    print("  OmniGuard Cyber-Physical OT Controller (Live)")
    print(f"  LCD I2C : {'0x' + format(hw.lcd.addr, '02x') if hw.lcd and hw.lcd.available else 'simulated/not detected'}")
    print("  Watching: C2/RMM processes & /tmp/omniguard_ot_state.json")
    print("=" * 60)

    prev_state = None
    flash = False
    cured_until = 0.0

    while True:
        cont = _read_containment_state()
        compromised = _rogue_beacon_running()

        if cont == "isolated":
            state = "isolated"
        elif compromised:
            state = "compromised"
        elif time.time() < cured_until:
            state = "cured"
        else:
            state = "normal"

        if prev_state in ("isolated", "compromised") and state == "normal":
            cured_until = time.time() + 4.0
            state = "cured"

        temp = read_temperature_c()
        t_str = f"{temp:.1f}C" if temp is not None else "--.-C"

        if state != prev_state:
            print(f"[OT] Transition: {prev_state} -> {state} (temp={t_str})")
            if state == "compromised":
                hw.set_fan(False)
                hw.chirp(2, 0.1)
            elif state == "isolated":
                hw.set_led((0, 0, 1))
                hw.set_fan(False)
                hw.show_lcd("HOST ISOLATED", "C2 KILLED BY SOC")
                hw.chirp(1, 0.12)
            elif state == "cured":
                hw.set_led((0, 1, 0))
                hw.set_fan(True)
                hw.show_lcd("SYSTEM CURED", f"FAN:ON  T:{t_str}")
            elif state == "normal":
                hw.set_led((0, 1, 0))
                hw.set_fan(True)
                hw.show_lcd("SYS: NORMAL", f"FAN:ON  T:{t_str}")
            prev_state = state

        if state == "compromised":
            flash = not flash
            hw.set_led((1, 0, 0) if flash else (0, 0, 0))
            hw.show_lcd("YOU ARE HACKED!!", random.choice(GIBBERISH_LINES))
            time.sleep(0.3)
        else:
            if state == "normal":
                hw.show_lcd("SYS: NORMAL", f"FAN:ON  T:{t_str}")
            time.sleep(0.5)


def main() -> None:
    parser = argparse.ArgumentParser(description="OmniGuard Raspberry Pi 5 OT Hardware Controller")
    parser.add_argument("--simulate", action="store_true", help="Console-only simulation (no GPIO required)")
    parser.add_argument("--test-cycle", action="store_true", help="Run a 12-second Normal/Hacked/Isolated/Cured cycle")
    parser.add_argument("--common-anode", action="store_true", help="Set if your RGB LED is common-anode (VCC -> 3.3V)")
    parser.add_argument("--fan-active-low", action="store_true", help="Set if your relay module triggers ON when IN is LOW")
    parser.add_argument("--quiet", action="store_true", help="Mute active buzzer alerts")
    args = parser.parse_args()

    hw = OTHardware(
        simulate=args.simulate,
        common_anode=args.common_anode,
        fan_active_low=args.fan_active_low,
        quiet=args.quiet,
    )

    def _stop(*_):
        hw.cleanup()
        print("\n[OT] Hardware reset & cleaned up.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    try:
        if args.test_cycle:
            run_test_cycle(hw)
        else:
            run_live(hw)
    finally:
        hw.cleanup()


if __name__ == "__main__":
    main()
