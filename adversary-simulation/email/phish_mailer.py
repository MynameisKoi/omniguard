#!/usr/bin/env python3
"""OmniGuard Adversary Simulation — Phishing Email Generator / Sender.

Closed-network security-AWARENESS lab fixture. Builds a convincing, brand-styled
phishing email whose ONE call-to-action link points at the local mock portal
(mock_portal.py), while every other link is the brand's real site. The teaching
point: "everything looks real except where it counts — the sender domain and the
one link you're asked to click."

SAFETY / SCOPE
  - For a CLOSED demo network, to people who have agreed to the demo.
  - The portal it links to is a labeled benign simulation that NEVER stores a
    real password (it just triggers VerifyEye / SOC detection).
  - On a closed network with a local SMTP server the From can be fully spoofed
    (no SPF/DKIM to block it). Over the real internet that spoof is rejected —
    which is itself part of the lesson.

USAGE
  # write every brand's email to ./out as .html + .eml (open in a browser)
  python phish_mailer.py --all --save --portal http://192.168.137.1:8080/login.html

  # one brand, sent via a local SMTP (e.g. `python -m aiosmtpd -n -l :1025`)
  python phish_mailer.py --brand microsoft --to victim@lab.local \
      --portal http://192.168.137.1:8080/login.html \
      --send --smtp-host 192.168.137.1 --smtp-port 1025

  # via a real SMTP that needs auth (use a look-alike FROM you control)
  python phish_mailer.py --brand google --to you@gmail.com --send \
      --smtp-host smtp.gmail.com --smtp-port 587 --smtp-user X --smtp-pass Y --tls
"""
from __future__ import annotations

import argparse
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

# ── per-brand look & copy ────────────────────────────────────────────────────
# color = header/button brand color; from_name / from_addr = the spoofed sender
# (a real sending domain on the public internet would be rejected — that's fine,
#  it's the teaching point; on a local SMTP it's accepted verbatim).
BRANDS: dict[str, dict] = {
    "microsoft": {
        "label": "Microsoft 365",
        "color": "#0067b8", "accent": "#50e6ff",
        "from_name": "Microsoft account team",
        "from_addr": "account-security-noreply@microsoft.com",
        "subject": "Unusual sign-in activity on your Microsoft account",
        "preheader": "We detected a sign-in attempt from a new device.",
        "headline": "Verify your recent sign-in",
        "body": "We detected a sign-in to your Microsoft 365 account from a device "
                "or location we don't recognize. To keep your account secure, please "
                "verify this activity. If you don't verify within 24 hours, access to "
                "Outlook, Teams and OneDrive may be temporarily limited.",
        "cta": "Verify my account",
        "home": "https://www.microsoft.com", "help": "https://support.microsoft.com",
    },
    "google": {
        "label": "Google Workspace",
        "color": "#1a73e8", "accent": "#34a853",
        "from_name": "Google",
        "from_addr": "no-reply@accounts.google.com",
        "subject": "Security alert: new sign-in to your Google Account",
        "preheader": "Was this you? Review activity now.",
        "headline": "Review a new sign-in",
        "body": "Your Google Account was just used to sign in on a new device. If this "
                "was you, you can ignore this email. If not, your account may be at "
                "risk — review the activity and secure your account now.",
        "cta": "Review activity",
        "home": "https://www.google.com", "help": "https://support.google.com",
    },
    "netflix": {
        "label": "Netflix",
        "color": "#e50914", "accent": "#b20710",
        "from_name": "Netflix",
        "from_addr": "info@account.netflix.com",
        "subject": "Your Netflix membership is on hold",
        "preheader": "We couldn't process your latest payment.",
        "headline": "We're having trouble with your payment",
        "body": "We were unable to validate your billing information for the next "
                "billing cycle, so your membership is on hold. To avoid losing access "
                "to your account, please update your payment details.",
        "cta": "Update payment",
        "home": "https://www.netflix.com", "help": "https://help.netflix.com",
    },
    "amazon": {
        "label": "Amazon",
        "color": "#ff9900", "accent": "#232f3e",
        "from_name": "Amazon",
        "from_addr": "account-update@amazon.com",
        "subject": "Your Amazon account has been locked",
        "preheader": "Confirm your identity to restore access.",
        "headline": "We've locked your account",
        "body": "We noticed unusual activity on your Amazon account and have "
                "temporarily locked it to protect you. To restore access to your "
                "orders and payment methods, please confirm your identity.",
        "cta": "Confirm identity",
        "home": "https://www.amazon.com", "help": "https://www.amazon.com/help",
    },
    "docusign": {
        "label": "DocuSign",
        "color": "#d4af37", "accent": "#2f3e4d",
        "from_name": "DocuSign via OmniCorp",
        "from_addr": "dse@docusign.net",
        "subject": "You have a document waiting for your signature",
        "preheader": "Please review and sign — action required.",
        "headline": "A document needs your signature",
        "body": "You have received a document that requires your electronic "
                "signature. Please review and sign it at your earliest convenience. "
                "This link will expire for security reasons.",
        "cta": "Review & sign",
        "home": "https://www.docusign.com", "help": "https://support.docusign.com",
    },
    "apple": {
        "label": "Apple",
        "color": "#111111", "accent": "#555555",
        "from_name": "Apple",
        "from_addr": "no_reply@email.apple.com",
        "subject": "Your Apple ID was used to sign in to a new device",
        "preheader": "Verify it was you.",
        "headline": "Your Apple ID was used to sign in",
        "body": "Your Apple ID was used to sign in to iCloud on a new device. If this "
                "was you, no action is needed. If you did not sign in, your Apple ID "
                "may be compromised — verify and secure it now.",
        "cta": "Verify Apple ID",
        "home": "https://www.apple.com", "help": "https://support.apple.com",
    },
    "github": {
        "label": "GitHub",
        "color": "#24292f", "accent": "#2da44e",
        "from_name": "GitHub",
        "from_addr": "noreply@github.com",
        "subject": "[GitHub] A third-party OAuth application was authorized",
        "preheader": "If this wasn't you, review it immediately.",
        "headline": "A new OAuth app was authorized",
        "body": "A third-party OAuth application was just granted access to your "
                "GitHub account. If you did not authorize this, your account may be "
                "compromised. Please review your authorized applications now.",
        "cta": "Review authorized apps",
        "home": "https://github.com", "help": "https://support.github.com",
    },
}

HTML_TEMPLATE = """\
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f2f2f2;font-family:Segoe UI,Helvetica,Arial,sans-serif;">
<span style="display:none;max-height:0;overflow:hidden;opacity:0;">{preheader}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f2f2f2;padding:24px 0;">
<tr><td align="center">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0"
         style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;
                box-shadow:0 1px 3px rgba(0,0,0,.12);">
    <tr><td style="background:{color};padding:20px 32px;">
      <span style="color:#ffffff;font-size:22px;font-weight:700;letter-spacing:.2px;">{label}</span>
    </td></tr>
    <tr><td style="padding:34px 32px 8px;">
      <h1 style="margin:0 0 14px;font-size:21px;color:#1b1b1b;">{headline}</h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.55;color:#444;">{body}</p>
      <table role="presentation" cellpadding="0" cellspacing="0"><tr><td
        style="border-radius:6px;background:{color};">
        <a href="{portal}" style="display:inline-block;padding:13px 30px;font-size:15px;
           font-weight:600;color:#ffffff;text-decoration:none;">{cta} &rarr;</a>
      </td></tr></table>
      <p style="margin:22px 0 0;font-size:12.5px;color:#888;">
        If the button doesn't work, copy and paste this link into your browser:<br>
        <span style="color:{color};word-break:break-all;">{portal}</span>
      </p>
    </td></tr>
    <tr><td style="padding:24px 32px 30px;border-top:1px solid #eee;">
      <p style="margin:0 0 6px;font-size:12px;color:#9a9a9a;">
        This is an automated security message from {label}. Please do not reply.
      </p>
      <p style="margin:0;font-size:12px;color:#9a9a9a;">
        <a href="{home}" style="color:#9a9a9a;">Home</a> &nbsp;&middot;&nbsp;
        <a href="{help}" style="color:#9a9a9a;">Help Center</a> &nbsp;&middot;&nbsp;
        <a href="{home}" style="color:#9a9a9a;">Privacy</a>
      </p>
    </td></tr>
  </table>
  <p style="margin:14px 0 0;font-size:11px;color:#bbb;">OmniGuard SOC — closed-network awareness demo (benign simulation)</p>
</td></tr></table>
</body></html>"""

TEXT_TEMPLATE = """\
{headline}

{body}

{cta}: {portal}

This is an automated security message from {label}. Please do not reply.
{home}  |  {help}

— OmniGuard SOC closed-network awareness demo (benign simulation)
"""


def build_message(brand_key: str, portal: str, to_addr: str) -> EmailMessage:
    b = BRANDS[brand_key]
    ctx = {**b, "portal": portal}
    msg = EmailMessage()
    msg["Subject"] = b["subject"]
    msg["From"] = formataddr((b["from_name"], b["from_addr"]))
    msg["To"] = to_addr
    msg["Message-ID"] = make_msgid(domain=b["from_addr"].split("@", 1)[-1])
    msg.set_content(TEXT_TEMPLATE.format(**ctx))
    msg.add_alternative(HTML_TEMPLATE.format(**ctx), subtype="html")
    return msg


def save(brand_key: str, portal: str, to_addr: str, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    msg = build_message(brand_key, portal, to_addr)
    with open(os.path.join(out_dir, f"{brand_key}.eml"), "wb") as f:
        f.write(bytes(msg))
    html = HTML_TEMPLATE.format(**{**BRANDS[brand_key], "portal": portal})
    with open(os.path.join(out_dir, f"{brand_key}.html"), "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  saved  {out_dir}/{brand_key}.html  +  {brand_key}.eml")


def send(brand_key: str, portal: str, to_addr: str, host: str, port: int,
         user: str | None, password: str | None, use_tls: bool) -> None:
    msg = build_message(brand_key, portal, to_addr)
    with smtplib.SMTP(host, port, timeout=15) as s:
        if use_tls:
            s.starttls(context=ssl.create_default_context())
        if user:
            s.login(user, password or "")
        s.send_message(msg)
    print(f"  sent   {brand_key} -> {to_addr}  via {host}:{port}  (From: {msg['From']})")


def main() -> None:
    p = argparse.ArgumentParser(description="OmniGuard phishing-email lab generator (closed network).")
    p.add_argument("--brand", choices=sorted(BRANDS), help="single brand")
    p.add_argument("--all", action="store_true", help="every brand")
    p.add_argument("--portal", default="http://127.0.0.1:8080/login.html",
                   help="the mock portal URL the CTA links to (closed network)")
    p.add_argument("--to", default="victim@lab.local", help="recipient address")
    p.add_argument("--save", action="store_true", help="write .html + .eml to --out")
    p.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "out"))
    p.add_argument("--send", action="store_true", help="send via SMTP")
    p.add_argument("--smtp-host", default="127.0.0.1")
    p.add_argument("--smtp-port", type=int, default=1025)
    p.add_argument("--smtp-user", default=None)
    p.add_argument("--smtp-pass", default=None)
    p.add_argument("--tls", action="store_true", help="STARTTLS (for real SMTP relays)")
    args = p.parse_args()

    brands = sorted(BRANDS) if args.all else ([args.brand] if args.brand else [])
    if not brands:
        p.error("pick --brand <name> or --all")
    if not (args.save or args.send):
        args.save = True  # default to writing files

    print(f"portal (CTA target): {args.portal}\n")
    for bk in brands:
        if args.save:
            save(bk, args.portal, args.to, args.out)
        if args.send:
            send(bk, args.portal, args.to, args.smtp_host, args.smtp_port,
                 args.smtp_user, args.smtp_pass, args.tls)


if __name__ == "__main__":
    main()
