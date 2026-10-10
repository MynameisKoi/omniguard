#!/usr/bin/env python3
"""OmniGuard Adversary Simulation: C2 Listener

A lightweight, standalone Command & Control listener that accepts and logs
incoming beacon check-ins from simulated victim implants.
"""

import argparse
import http.server
import json
import socketserver
import time

class C2ListenerHandler(http.server.SimpleHTTPRequestHandler):
    checkin_count = 0

    def do_GET(self):
        self.handle_beacon("GET")

    def do_POST(self):
        self.handle_beacon("POST")

    def handle_beacon(self, method: str):
        C2ListenerHandler.checkin_count += 1
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]
        client_port = self.client_address[1]

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="ignore") if content_len > 0 else ""

        print(f"[{now}] [BEACON #{C2ListenerHandler.checkin_count}] {method} {self.path} from {client_ip}:{client_port} ({content_len} bytes)")

        # Send response simulating C2 tasking payload
        resp_data = json.dumps({
            "status": "active",
            "session_id": f"sess-{C2ListenerHandler.checkin_count:04d}",
            "tasks": [],
            "next_beacon_ms": 10000,
        }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")  # Emulate standard web server camouflage
        self.send_header("Content-Length", str(len(resp_data)))
        self.end_headers()
        self.wfile.write(resp_data)

    def log_message(self, format, *args):
        # Override to suppress default noisy stdout
        pass


def main():
    parser = argparse.ArgumentParser(description="OmniGuard Mock C2 Listener")
    parser.add_argument("--host", default="0.0.0.0", help="Listener bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8443, help="Listener port (default: 8443)")
    args = parser.parse_args()

    server_address = (args.host, args.port)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(server_address, C2ListenerHandler) as httpd:
        print(f"==================================================")
        print(f"   OmniGuard Adversary Simulation: C2 Listener    ")
        print(f"==================================================")
        print(f"[+] Listening on http://{args.host}:{args.port}")
        print(f"[+] Ready to receive implant beaconing loops.")
        print(f"[+] Press Ctrl+C to terminate listener.")
        print(f"==================================================\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down C2 listener.")


if __name__ == "__main__":
    main()
