# Raspberry Pi 5 Cyber-Physical OT Demo — Wiring & Setup Guide

This turns your **Raspberry Pi 5 (`192.168.137.32`)** with the **SunFounder Da Vinci** + **HiPi.io** kits into a physical OT target controlled by OmniGuard's attack & one-click isolation lifecycle.

---

## 1. Exact Breadboard Pinout (Non-Overlapping BCM Pins)

> **Safety Rule:** Always power off or unplug the Pi 5 before wiring, and **never** connect the DC fan directly to a GPIO pin (use the **L293D** motor driver IC from your Da Vinci kit).

---

## Visual Breadboard Layout (SunFounder T-GPIO Extension Board)

Plug the **T-shaped GPIO Extension Board** across the center groove at the top of your breadboard, and wire **Left `+` = `3.3V`**, **Right `+` = `5V`**, and **Both `-` = `GND`** (bridged together):

```text
  LEFT  [+] 3.3V RAIL <── (Pin 1: 3V3)       RIGHT [+] 5V RAIL <── (Pin 2: 5V)
  LEFT  [-] GND  RAIL <── (Pin 9: GND) ───── RIGHT [-] GND RAIL <─ (Pin 6/14/20: GND)
               ┌─────────────────────────────┴─────────────────────────────┐
               │       SUNFOUNDER T-GPIO EXTENSION BOARD (40-Pin)          │
               │        (Ribbon cable notch facing Pi / top)               │
               ├─────────────────────────────┬─────────────────────────────┤
  Optional     │  1: 3V3   (DS18B20 VCC)     │  2: 5V    ──> [+] 5V RAIL   │
  I2C LCD ───> │  3: SDA   (LCD SDA)         │  4: 5V    (spare 5V)        │
  I2C LCD ───> │  5: SCL   (LCD SCL)         │  6: GND   ──> LCD GND       │
  Optional ──> │  7: G4    (DS18B20 DATA)    │  8: TXD   (unused)          │
  [-] Rail ──> │  9: GND   ──> [-] GND RAIL  │ 10: RXD   (unused)          │
  RGB Red  ──> │ 11: G17 ─[220Ω]─> LED R     │ 12: G18   (unused)          │
  RGB Grn  ──> │ 13: G27 ─[220Ω]─> LED G     │ 14: GND   ──> [-] GND RAIL  │
  RGB Blu  ──> │ 15: G22 ─[220Ω]─> LED B     │ 16: G23   ──> Buzzer (+)    │
               │ 17: 3V3   (DS18B20 pullup)  │ 18: G24   ──> L293D Pin 2   │
               │ 19: MOSI  (unused)          │ 20: GND   ──> [-] GND RAIL  │
               │ 21: MISO  (unused)          │ 22: G25   ──> L293D Pin 1   │
               └─────────────────────────────┴─────────────────────────────┘
                             │   (center groove)   │
                             ▼                     ▼

  === LOWER BREADBOARD: L293D MOTOR DRIVER (straddling center groove) ===

                          ┌──────╲__/──────┐
       G25 (Pin 22) ─────>│ 1 EN1    VCC1 16│<───── [+] 5V RAIL
       G24 (Pin 18) ─────>│ 2 IN1     IN4 15│  (unused)
       Fan Wire A   <─────│ 3 OUT1   OUT4 14│  (unused)
       [-] GND RAIL ─────>│ 4 GND     GND 13│<───── [-] GND RAIL
       [-] GND RAIL ─────>│ 5 GND     GND 12│<───── [-] GND RAIL
       Fan Wire B   <─────│ 6 OUT2   OUT3 11│  (unused)
       [-] GND RAIL ─────>│ 7 IN2     IN3 10│  (unused)
       [+] 5V RAIL  ─────>│ 8 VCC2   EN2   9│  (unused)
                          └─────────────────┘

  === COMPONENTS ON BREADBOARD ===
  • HiPi RGB LED Module (VCC, R, G, B — built-in resistors, Common Anode):
      VCC -> LEFT [+] 3.3V RAIL | R -> G17 (Pin 11) | G -> G27 (Pin 13) | B -> G22 (Pin 15)
      (Run pi_ot_controller.py with --common-anode!)
  • Bare RGB LED (if using Da Vinci 4-leg LED): R <- G17 (220Ω) | G <- G27 (220Ω) | B <- G22 (220Ω) | Longest leg -> [-] GND RAIL
  • Active Buzzer: (+) <- G23 | (-) -> [-] GND RAIL
  • I2C LCD1602 (4-pin header): VCC -> [+] 5V RAIL | GND -> [-] GND RAIL | SDA -> SDA (Pin 3) | SCL -> SCL (Pin 5)
  • Optional DS18B20: VCC -> 3V3 (Pin 1) | GND -> [-] GND RAIL | DATA -> G4 (Pin 7) + [4.7kΩ resistor to 3V3]
```

---

| Component | Module Pin | Raspberry Pi 5 Pin (BCM / Physical) | Notes |
| :--- | :--- | :--- | :--- |
| **I2C LCD1602** | `VCC` | **5V** (Pin 2) | Standard 5V logic |
| *(4 wires)* | `GND` | **GND** (Pin 6) | Shared ground rail |
| | `SDA` | **GPIO 2** (Pin 3) | Hardware I2C1 SDA |
| | `SCL` | **GPIO 3** (Pin 5) | Hardware I2C1 SCL |
| **RGB LED** | `Red` | **GPIO 17** (Pin 11) | Through **220Ω resistor** |
| *(Common Cathode)* | `Green` | **GPIO 27** (Pin 13) | Through **220Ω resistor** |
| | `Blue` | **GPIO 22** (Pin 15) | Through **220Ω resistor** |
| | `Longest leg (-)` | **GND** (Pin 14) | *(If Common Anode, connect to 3.3V & pass `--common-anode`)* |
| **Active Buzzer** | `+` | **GPIO 23** (Pin 16) | Optional (`--quiet` to mute) |
| | `-` | **GND** (Pin 20) | |
| **DC Fan (L293D)** | `Pin 1 (EN1)` | **GPIO 25** (Pin 22) | Enable pin |
| *(Motor Driver IC)* | `Pin 2 (IN1)` | **GPIO 24** (Pin 18) | Drive pin |
| | `Pin 7 (IN2)` | **GND** | Single-direction fan control |
| | `Pin 3 & 6 (OUT1/2)` | **DC Fan wires** | Motor power outputs |
| | `Pin 8 (VCC2)` & `16 (VCC1)` | **5V** (Pin 4) | Motor + logic 5V supply |
| | `Pin 4, 5, 12, 13` | **GND** | Ground pins on L293D |
| **DS18B20 Temp** *(Optional)* | `VCC` / `GND` / `DATA` | **3.3V** (Pin 1) / **GND** (Pin 9) / **GPIO 4** (Pin 7) | 4.7kΩ–10kΩ pull-up between DATA & 3.3V *(auto-falls back to Pi CPU temp if omitted)* |

---

## 2. One-Time Raspberry Pi OS Setup (I2C & 1-Wire)

Run on the Raspberry Pi (`ssh pi@192.168.137.32`):
```bash
sudo raspi-config nonint do_i2c 0
# Optional if wiring DS18B20 on GPIO4:
sudo raspi-config nonint do_onewire 0
sudo reboot
```
After rebooting, verify the LCD1602 is detected at `0x27` or `0x3f`:
```bash
i2cdetect -y 1
```

---

## 3. Test & Run [`demo/pi_ot_controller.py`](../demo/pi_ot_controller.py)

1. **Test all 4 states in 12 seconds** *(Green/Fan ON → Flashing Red/Fan OFF/Hacked LCD → Blue/Isolated → Cured)*:
   ```bash
   python3 ~/omniguard/demo/pi_ot_controller.py --test-cycle
   ```
   *(Add `--simulate` to test in terminal without hardware attached.)*

2. **Run Live Alongside the Containment Agent**:
   * **Terminal 1 (OT Hardware Controller):**
     ```bash
     python3 ~/omniguard/demo/pi_ot_controller.py
     ```
   * **Terminal 2 (Containment & DFIR Agent):**
     ```bash
     cd ~/omniguard && sudo -E python3 demo/run_soc_demo.py --role victim --host raspberrypi
     ```
   * **What happens automatically during the demo:**
     - **Normal:** Green LED on, Fan spinning, LCD shows `SYS: NORMAL` & live temp.
     - **Attack starts (`/tmp/rmm_watchdog_sim.py`):** Controller detects the rogue beacon process → **Fan stops**, **Red LED flashes**, **Buzzer chirps**, LCD glitches (`YOU ARE HACKED!!` + gibberish).
     - **Analyst clicks `Quarantine & Kill`:** `containment_agent.py` kills the beacon PID, drops C2 traffic, and signals `isolated` → **Blue LED**, LCD shows `HOST ISOLATED / C2 KILLED BY SOC`.
     - **Analyst clicks `Release`:** `containment_agent.py` restores networking and signals `normal` → **Green LED**, **Fan spins back up**, LCD shows `SYSTEM CURED` then `SYS: NORMAL`.
