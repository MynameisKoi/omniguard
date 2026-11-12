# Flipper Zero Setup & Execution Guide for OmniGuard Demo

## 1. Preparing the Flipper Zero

1. Remove the MicroSD card from your Flipper Zero or connect the Flipper Zero via USB using the **qFlipper** desktop application.
2. Navigate to the `badusb/` directory on the SD card:
   ```
   SD Card /
   └── badusb /
       ├── omniguard_linux.txt
       └── omniguard_windows.txt
   ```
3. Copy `badusb_ingress_linux.txt` (or Windows) into that folder.
4. If your demo workstation has a specific IP on your LAN/Wi-Fi (instead of `localhost:8080`), change `http://localhost:8080/login.html` to `http://<TARGET_IP>:8080/login.html`.

## 2. Running BadUSB in the Demo (Adversary Stage 1 Ingress)

1. On the Flipper Zero, open the **Bad USB** app from the main menu.
2. Select `omniguard_linux` (or Windows).
3. Connect the Flipper Zero via USB to the demonstration laptop.
4. Press the center **OK / Run** button on the Flipper.
5. The Flipper acts as a human interface device (keyboard), instantly opening the browser to the credential harvesting page.
6. VerifyEye will then intercept the page and trigger the SOC alert!

---

## 3. Running Analyst Hardware Fast-Login (Flipper Zero Badge / Tap)

The Flipper Zero can also act as the SOC Analyst's **physical hardware security key**:

1. Copy `badge_login_tap.txt` into the `badusb/` directory on your Flipper Zero SD card as `soc_analyst_key.txt`.
2. Open the OmniGuard SOC login page in your browser (`http://localhost:5174` or `http://localhost:8080`).
3. Select the **"🐬 Flipper Zero / NFC"** login mode tab.
4. Connect the Flipper Zero via USB and launch the **Bad USB** app -> `soc_analyst_key`.
5. Press **OK / Run**:
   - The Flipper Zero types the analyst badge key token and hits Enter.
   - The dashboard validates the physical key, commits an immutable audit record to the **Investigation Decision Ledger**, and signs the analyst in instantly with zero password typing.
6. **Physical NFC Card Tap Option**:
   - Alternatively, if you have an NFC smartcard or RFID tag, read the UID on your Flipper Zero under the **NFC -> Read** app (e.g. `7A:39:B1:04`), enter it into the dashboard, and subsequent taps log you in seamlessly.
