#!/usr/bin/env python3
"""
Demo hosts setup — makes the fake login pages resolve to a real-looking domain
instead of a bare IP, so the dashboard/graph show e.g. "netflix-account-verify.com"
instead of "192.168.1.240". Everything still stays on your closed network; no DNS,
nothing public.

It just adds a few lines to the machine's hosts file (a local name->IP phone book),
inside a clearly marked block it can remove again. Needs admin, because editing the
hosts file always does.

Run on each machine that will BROWSE the fake pages (the victim):

    add the entries (point them at the analyst machine's IP):
        Windows (admin PowerShell):  python demo\\setup_demo_hosts.py 192.168.1.240
        Mac/Linux:                   sudo python3 demo/setup_demo_hosts.py 192.168.1.240

    remove them again:
        python demo\\setup_demo_hosts.py --remove

After adding, use these links in your phishing email (the port picks the brand):
    http://netflix-account-verify.com:5800     http://amazon-account-verify.com:6200
    http://google-signin-verify.com:5700       http://tiktok-login-verify.com:5900
    http://claude-anthropic-verify.com:5500
"""

import ctypes
import os
import platform
import sys

# fake domain  ->  the fake-site port it should open (from fake_sites/serve.sh)
DOMAINS = {
    "google-signin-verify.com": 5700,
    "netflix-account-verify.com": 5800,
    "tiktok-login-verify.com": 5900,
    "amazon-account-verify.com": 6200,
    "claude-anthropic-verify.com": 5500,
    "account-google-verify.com": 5600,   # the SPA / late-login test page
}

BEGIN = "# >>> omniguard-demo >>>"
END = "# <<< omniguard-demo <<<"


def hosts_path():
    if platform.system() == "Windows":
        return r"C:\Windows\System32\drivers\etc\hosts"
    return "/etc/hosts"


def is_admin():
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def strip_block(text):
    """Remove any existing omniguard-demo block, so this is idempotent."""
    if BEGIN not in text:
        return text
    before, _, rest = text.partition(BEGIN)
    _, _, after = rest.partition(END)
    return (before.rstrip() + "\n" + after.lstrip()).strip() + "\n"


def main():
    path = hosts_path()
    remove = "--remove" in sys.argv
    ip_args = [a for a in sys.argv[1:] if not a.startswith("-")]

    if not is_admin():
        print("! Needs admin to edit the hosts file.")
        print("  Windows: open PowerShell as Administrator, then run it again.")
        print("  Mac/Linux: run it with sudo.")
        sys.exit(1)

    try:
        with open(path, "r") as f:
            text = f.read()
    except Exception as e:
        print(f"! could not read {path}: {e}")
        sys.exit(1)

    cleaned = strip_block(text)

    if remove:
        with open(path, "w") as f:
            f.write(cleaned)
        print(f"Removed the omniguard-demo entries from {path}.")
        return

    if not ip_args:
        print("Usage: setup_demo_hosts.py <ANALYST_IP>    (or --remove)")
        print("  e.g. python demo/setup_demo_hosts.py 192.168.1.240")
        sys.exit(1)
    ip = ip_args[0]

    block = [BEGIN,
             f"# fake phishing domains for the OmniGuard demo -> {ip} (closed network only)"]
    block += [f"{ip}\t{d}" for d in DOMAINS]
    block.append(END)
    new_text = cleaned.rstrip() + "\n" + "\n".join(block) + "\n"

    with open(path, "w") as f:
        f.write(new_text)

    print(f"Added {len(DOMAINS)} fake domains -> {ip} in {path}\n")
    print("Use these links in your phishing email:")
    for d, port in DOMAINS.items():
        print(f"  http://{d}:{port}")
    print("\nUndo any time with:  python demo/setup_demo_hosts.py --remove")


if __name__ == "__main__":
    main()
