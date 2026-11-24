# Raspberry Pi 5 Cyber-Physical OT Demo — HiPi + 2-Wire Fan Guide

This turns your **Raspberry Pi 5 (`192.168.137.32`)** into a physical OT target controlled by OmniGuard's attack & one-click isolation lifecycle.

> **Safety Rule:** Always shut down and unplug the Pi 5 (`sudo shutdown -h now`) before wiring GPIO pins.

---

## 1. Visual Breadboard Layout (HiPi Modules + 2-Wire SunFounder Fan)

Plug the **T-GPIO Extension Board** across the center groove at the top of your breadboard:
* **Left `+` (Red) Rail** = **`3.3V`** (Pin 1)
* **Right `+` (Red) Rail** = **`5V`** (Pin 2)
* **Both `-` (Blue) Rails** = **`GND`** (linked together with one jumper wire)

```text
  LEFT  [+] 3.3V RAIL <── (Pin 1: 3V3)       RIGHT [+] 5V RAIL <── (Pin 2: 5V)
  LEFT  [-] GND  RAIL <── (Pin 9: GND) ───── RIGHT [-] GND RAIL <─ (Pin 6/14/20: GND)

               ┌─────────────────────────────┬─────────────────────────────┐
               │       T-GPIO EXTENSION BOARD (40-Pin, Notch at Top)       │
               ├─────────────────────────────┬─────────────────────────────┤
  LEFT [+] ──> │  1: 3V3   (3.3V Rail)       │  2: 5V    ──> RIGHT [+] 5V  │
  LCD SDA  ──> │  3: SDA   (LCD SDA)         │  4: 5V    (spare 5V)        │
  LCD SCL  ──> │  5: SCL   (LCD SCL)         │  6: GND   ──> RIGHT [-] GND │
               │  7: G4    (unused)          │  8: TXD   (unused)          │
  LEFT [-] ──> │  9: GND   (GND Rail)        │ 10: RXD   (unused)          │
  RGB R    ──> │ 11: G17   (HiPi RGB R)      │ 12: G18   (unused)          │
  RGB G    ──> │ 13: G27   (HiPi RGB G)      │ 14: GND   ──> RIGHT [-] GND │
  RGB B    ──> │ 15: G22   (HiPi RGB B)      │ 16: G23   ──> HiPi Buzzer   │
               │ 17: 3V3   (spare 3.3V)      │ 18: G24   ──> Relay IN      │
               │ 19: MOSI  (unused)          │ 20: GND   ──> RIGHT [-] GND │
               │ 21: MISO  (unused)          │ 22: G25   ──> (L293D EN1)   │
               └─────────────────────────────┴─────────────────────────────┘

  === MODULE CONNECTIONS ===

  1. HiPi RGB LED Module (4 pins: VCC, R, G, B — Common Anode, built-in resistors)
     • VCC ──> LEFT [+] 3.3V RAIL
     • R   ──> G17 (Pin 11)
     • G   ──> G27 (Pin 13)
     • B   ──> G22 (Pin 15)

  2. HiPi I2C LCD1602 Module (4 pins: VCC, GND, SDA, SCL)
     • VCC ──> RIGHT [+] 5V RAIL
     • GND ──> RIGHT [-] GND RAIL
     • SDA ──> SDA (Pin 3)
     • SCL ──> SCL (Pin 5)

  3. HiPi Active Buzzer Module (3 pins: VCC, GND, S — or 2 pins: +, -)
     • VCC ──> LEFT [+] 3.3V RAIL   (if 3-pin)
     • GND ──> [-] GND RAIL
     • S   ──> G23 (Pin 16)         (or + to G23, - to GND if 2-pin)

  4. SunFounder 2-Wire Fan (Red + Black) via Relay Module
     *(A relay acts as a safe ON/OFF switch so the motor doesn't overload the GPIO pin!)*
     • Control side (3 pins):
         VCC ──> RIGHT [+] 5V RAIL
         GND ──> RIGHT [-] GND RAIL
         IN  ──> G24 (Pin 18)
     • Screw terminals (COM / NO):
         RIGHT [+] 5V RAIL ──> Relay COM
         Relay NO          ──> Fan RED wire
         Fan BLACK wire    ──> RIGHT [-] GND RAIL
     *(If the fan runs when it should be OFF, pass `--fan-active-low`!)*

  5. Temperature Display
     • No external sensor needed: LCD reads Pi 5 thermal sensor in Normal mode and
       flashes `YOU ARE HACKED!!` + `TEMP RISING >60C!` when the attacker stops the fan.
```

---

## 2. One-Time Raspberry Pi OS Setup (I2C)

```bash
sudo raspi-config nonint do_i2c 0
sudo reboot
# After reboot, confirm LCD appears at 0x27 or 0x3f:
i2cdetect -y 1
```

---

## 3. Test & Run [`demo/pi_ot_controller.py`](../demo/pi_ot_controller.py)

```bash
# 12-second wiring test (add --fan-active-low if your relay is active-low):
python3 ~/omniguard/demo/pi_ot_controller.py --common-anode --test-cycle

# Live demo mode (alongside run_soc_demo.py --role victim):
python3 ~/omniguard/demo/pi_ot_controller.py --common-anode
```
