# Raspberry Pi 5 Cyber-Physical OT Demo — Wiring & Setup Guide

This turns your **Raspberry Pi 5 (`192.168.137.32`)** with the **SunFounder Da Vinci** + **HiPi.io** kits into a physical OT target controlled by OmniGuard's attack & one-click isolation lifecycle.

---

## 1. Exact Breadboard Pinout (Non-Overlapping BCM Pins)

> **Safety Rule:** Always power off or unplug the Pi 5 before wiring, and **never** connect the DC fan directly to a GPIO pin (use the **L293D** motor driver IC from your Da Vinci kit).

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
