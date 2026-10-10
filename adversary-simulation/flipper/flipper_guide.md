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

## 2. Running BadUSB in the Demo

1. On the Flipper Zero, open the **Bad USB** app from the main menu.
2. Select `omniguard_linux` (or Windows).
3. Connect the Flipper Zero via USB to the demonstration laptop.
4. Press the center **OK / Run** button on the Flipper.
5. The Flipper acts as a human interface device (keyboard), instantly opening the browser to the credential harvesting page.
6. VerifyEye will then intercept the page and trigger the SOC alert!
