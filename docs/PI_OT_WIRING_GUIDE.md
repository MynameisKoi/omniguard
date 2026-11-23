# Raspberry Pi 5 Cyber-Physical OT Demo — HiPi Wiring & Setup Guide

This turns your **Raspberry Pi 5 (`192.168.137.32`)** with your **HiPi.io sensor kit** into a physical OT target controlled by OmniGuard's attack & one-click isolation lifecycle.

> **Safety Rule:** Always shut down and unplug the Pi 5 (`sudo shutdown -h now`) before wiring GPIO pins.

---

## 1. Visual Breadboard Layout (HiPi Modules + T-GPIO Extension Board)

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
  Temp DAT ──> │  7: G4    (HiPi Temp DAT)   │  8: TXD   (unused)          │
  LEFT [-] ──> │  9: GND   (GND Rail)        │ 10: RXD   (unused)          │
  RGB R    ──> │ 11: G17   (HiPi RGB R)      │ 12: G18   (unused)          │
  RGB G    ──> │ 13: G27   (HiPi RGB G)      │ 14: GND   ──> RIGHT [-] GND │
  RGB B    ──> │ 15: G22   (HiPi RGB B)      │ 16: G23   ──> HiPi Buzzer   │
               │ 17: 3V3   (spare 3.3V)      │ 18: G24   ──> Fan / Relay   │
               │ 19: MOSI  (unused)          │ 20: GND   ──> RIGHT [-] GND │
               │ 21: MISO  (unused)          │ 22: G25   ──> Fan EN / INB  │
               └─────────────────────────────┴─────────────────────────────┘

  === HiPi.io MODULE CONNECTIONS (No External Resistors Needed) ===

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

  3. HiPi Active Buzzer Module (3 pins: VCC, GND, S/IO — or 2 pins: +, -)
     • VCC ──> LEFT [+] 3.3V RAIL   (if 3-pin module)
     • GND ──> [-] GND RAIL
     • S   ──> G23 (Pin 16)         (or + to G23, - to GND if 2-pin)

  4. HiPi Fan / Relay Module (works with L9110S Fan Module OR Relay Module)
     • Option A (L9110S Fan Module: VCC, GND, INA, INB):
         VCC ──> RIGHT [+] 5V RAIL | GND ──> RIGHT [-] GND | INA ──> G24 (Pin 18) | INB ──> RIGHT [-] GND
     • Option B (Relay Module: VCC, GND, IN controlling Fan 5V):
         VCC ──> RIGHT [+] 5V RAIL | GND ──> RIGHT [-] GND | IN  ──> G24 (Pin 18)

  5. HiPi Temp Sensor Module (Optional DS18B20 3-pin: VCC, GND, DAT — built-in pull-up)
     • VCC ──> LEFT [+] 3.3V RAIL
     • GND ──> LEFT [-] GND RAIL
     • DAT ──> G4 (Pin 7)
     *(If omitted, pi_ot_controller.py automatically reads the Pi 5 CPU thermal sensor.)*
```

---

## 2. One-Time Raspberry Pi OS Setup (I2C)

Run on the Raspberry Pi (`ssh pi@192.168.137.32`):
```bash
sudo raspi-config nonint do_i2c 0
# Optional if wiring DS18B20 on G4:
sudo raspi-config nonint do_onewire 0
sudo reboot
```
After rebooting, verify the LCD1602 appears at `0x27` or `0x3f`:
```bash
i2cdetect -y 1
```

---

## 3. Test & Run [`demo/pi_ot_controller.py`](../demo/pi_ot_controller.py)

1. **Test all 4 states in 12 seconds** *(Green/Fan ON → Flashing Red/Fan OFF/Hacked LCD → Blue/Isolated → Cured)*:
   ```bash
   python3 ~/omniguard/demo/pi_ot_controller.py --common-anode --test-cycle
   ```
   *(If the LCD lights up without text, gently turn the blue contrast screw on the back of the I2C backpack.)*

2. **Run Live Alongside the Containment Agent**:
   * **Terminal 1 (OT Hardware Controller):**
     ```bash
     python3 ~/omniguard/demo/pi_ot_controller.py --common-anode
     ```
   * **Terminal 2 (Containment & DFIR Agent):**
     ```bash
     cd ~/omniguard && sudo -E python3 demo/run_soc_demo.py --role victim --host raspberrypi
     ```
