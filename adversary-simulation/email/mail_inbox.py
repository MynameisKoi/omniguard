#!/usr/bin/env python3
"""OmniGuard Adversary Simulation — Local Mail Server + Web Inbox.

A self-contained, zero-dependency SMTP server + webmail viewer for the closed
demo network. The attacker sends phishing mail here (phish_mailer.py --send);
the victim opens the web inbox in a browser, sees a real-looking inbox, clicks
the email, and clicks the CTA → the mock phishing portal.

Why local: on a closed network there's no SPF/DKIM/DMARC, so the spoofed
"Microsoft account team <...@microsoft.com>" From shows verbatim — exactly what
makes the lesson land.

Run (on the attacker machine, e.g. your Mac):
    python3 mail_inbox.py                 # SMTP :1025, web inbox :8025 on all interfaces
    python3 mail_inbox.py --smtp-port 1025 --web-port 8025

Then send mail to it:
    python3 phish_mailer.py --brand microsoft --send \
        --portal http://<MAC-IP>:8080/login.html \
        --smtp-host 127.0.0.1 --smtp-port 1025 --to victim@lab.local

Victim opens:  http://<MAC-IP>:8025
"""
from __future__ import annotations

import argparse
import asyncio
import email
import html as html_mod
import threading
import time
from email.header import decode_header, make_header
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# newest-first store of received messages: {"from","to","subject","date","html","text"}
INBOX: list[dict] = []
_LOCK = threading.Lock()


def _dec(v: str | None) -> str:
    if not v:
        return ""
    try:
        return str(make_header(decode_header(v)))
    except Exception:
        return v


def _store_raw(raw: bytes) -> None:
    try:
        msg = email.message_from_bytes(raw)
    except Exception:
        return
    htmlp = textp = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/html" and not htmlp:
                htmlp = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "ignore")
            elif ctype == "text/plain" and not textp:
                textp = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "ignore")
    else:
        body = msg.get_payload(decode=True)
        body = body.decode(msg.get_content_charset() or "utf-8", "ignore") if body else ""
        if msg.get_content_type() == "text/html":
            htmlp = body
        else:
            textp = body
    rec = {
        "from": _dec(msg.get("From")), "to": _dec(msg.get("To")),
        "subject": _dec(msg.get("Subject")) or "(no subject)",
        "date": time.strftime("%H:%M"), "html": htmlp, "text": textp,
    }
    with _LOCK:
        INBOX.insert(0, rec)
    print(f"[mail] received: {rec['from']}  ->  {rec['to']}  |  {rec['subject']}", flush=True)


# ── minimal SMTP server (asyncio, stdlib only) ──────────────────────────────
async def _handle_smtp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    async def send(line: str) -> None:
        writer.write((line + "\r\n").encode()); await writer.drain()

    await send("220 omniguard-lab ESMTP ready")
    try:
        while True:
            raw_line = await reader.readline()
            if not raw_line:
                break
            cmd = raw_line.decode("utf-8", "ignore").strip()
            up = cmd.upper()
            if up.startswith(("HELO", "EHLO")):
                await send("250-omniguard-lab"); await send("250 OK")
            elif up.startswith(("MAIL", "RCPT")):
                await send("250 OK")
            elif up.startswith("DATA"):
                await send("354 End data with <CR><LF>.<CR><LF>")
                buf = bytearray()
                while True:
                    chunk = await reader.readline()
                    if not chunk or chunk in (b".\r\n", b".\n"):
                        break
                    if chunk.startswith(b".."):          # de-dot-stuff
                        chunk = chunk[1:]
                    buf += chunk
                _store_raw(bytes(buf))
                await send("250 OK: queued")
            elif up.startswith("RSET"):
                await send("250 OK")
            elif up.startswith("QUIT"):
                await send("221 Bye"); break
            else:
                await send("250 OK")
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── web inbox (http.server) ─────────────────────────────────────────────────
INBOX_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mail</title><style>
 body{{margin:0;font-family:Segoe UI,Helvetica,Arial,sans-serif;background:#f3f3f3;color:#1b1b1b}}
 .bar{{background:#0b1420;color:#fff;padding:14px 22px;font-size:18px;font-weight:600}}
 .bar span{{opacity:.6;font-weight:400;font-size:13px;margin-left:8px}}
 .wrap{{max-width:760px;margin:0 auto;padding:18px 14px}}
 a.row{{display:block;text-decoration:none;color:inherit;background:#fff;border:1px solid #e5e5e5;
        border-radius:8px;padding:14px 16px;margin-bottom:10px}}
 a.row:hover{{border-color:#c9c9c9;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
 .from{{font-weight:600;font-size:14.5px}} .subj{{font-size:14px;margin-top:3px}}
 .time{{float:right;font-size:12px;color:#999}} .empty{{color:#888;text-align:center;padding:50px}}
</style></head><body>
<div class="bar">📥 Inbox <span>victim@lab.local</span></div>
<div class="wrap">{rows}</div></body></html>"""


def _inbox_html() -> str:
    with _LOCK:
        items = list(enumerate(INBOX))
    if not items:
        rows = '<div class="empty">No messages yet.</div>'
    else:
        rows = "".join(
            f'<a class="row" href="/mail/{i}"><span class="time">{html_mod.escape(m["date"])}</span>'
            f'<div class="from">{html_mod.escape(m["from"])}</div>'
            f'<div class="subj">{html_mod.escape(m["subject"])}</div></a>'
            for i, m in items
        )
    return INBOX_PAGE.format(rows=rows)


class InboxHandler(BaseHTTPRequestHandler):
    def _send(self, body: str, code: int = 200) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/inbox"):
            self._send(_inbox_html())
        elif path.startswith("/mail/"):
            try:
                idx = int(path.rsplit("/", 1)[-1])
                with _LOCK:
                    m = INBOX[idx]
            except (ValueError, IndexError):
                self._send("<p>Not found</p>", 404); return
            back = '<div style="padding:10px 16px;background:#0b1420;"><a href="/" style="color:#9fd3ff;text-decoration:none;">&larr; Back to inbox</a></div>'
            body = m["html"] or f"<pre style='padding:20px;white-space:pre-wrap'>{html_mod.escape(m['text'])}</pre>"
            self._send(back + body)
        else:
            self._send("<p>Not found</p>", 404)

    def log_message(self, *a):  # quiet
        pass


def _run_web(host: str, port: int) -> None:
    ThreadingHTTPServer((host, port), InboxHandler).serve_forever()


async def main_async(args) -> None:
    threading.Thread(target=_run_web, args=(args.host, args.web_port), daemon=True).start()
    server = await asyncio.start_server(_handle_smtp, args.host, args.smtp_port)
    print("=" * 58)
    print("  OmniGuard Lab Mail — closed-network awareness demo")
    print(f"  SMTP  (attacker sends here) : {args.host}:{args.smtp_port}")
    print(f"  INBOX (victim opens this)   : http://{args.host}:{args.web_port}")
    print("=" * 58, flush=True)
    async with server:
        await server.serve_forever()


def main() -> None:
    p = argparse.ArgumentParser(description="Local SMTP + web inbox for the closed-network phishing demo.")
    p.add_argument("--host", default="0.0.0.0", help="bind interface (default all)")
    p.add_argument("--smtp-port", type=int, default=1025)
    p.add_argument("--web-port", type=int, default=8025)
    args = p.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[mail] stopped.")


if __name__ == "__main__":
    main()
