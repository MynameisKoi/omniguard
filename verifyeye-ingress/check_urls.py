"""Run the VerifyEye agent over many URLs at once and print a verdict table.

Meant for testing the agent (and its evidence capture) quickly:

    python check_urls.py --fake                       # every local fake site
    python check_urls.py --real                       # a set of real login pages
    python check_urls.py --fake --real                # both
    python check_urls.py https://example.com/login    # any URLs you like
    python check_urls.py --file urls.txt              # one URL per line

Needs the agent on :8100 and the core API on :8000. After the run it asks the
core API whether each page's screenshot actually arrived (EVIDENCE column).
Fake sites need ./fake_sites/serve.sh running. Repeat URLs within 10 minutes
come back from the agent's cache; --fresh clears it first.
"""
import argparse
import asyncio
import time
from datetime import datetime, timezone

import httpx

AGENT = "http://localhost:8100"
CORE = "http://localhost:8000"

# fake_sites/serve.sh ports. all of these should come back as phishing
FAKE = [
    "http://localhost:5500/",   # claude (with the google oauth popup)
    "http://localhost:5600/",   # spa-test: login form only appears after a click
    "http://localhost:5700/",   # fake google oauth popup
    "http://localhost:5800/",   # netflix
    "http://localhost:5900/",   # tiktok
    "http://localhost:6200/",   # amazon (not 6000: chrome refuses that port)
    "http://localhost:6100/",   # fake apple popup
]
# deliberately clean-looking: no password field, it only opens the fake google
# popup (5700, above). the agent should clear it
FAKE_CLEAN = ["http://localhost:5550/"]

# real login pages. all of these should come back cleared (not phishing)
REAL = [
    "https://github.com/login",
    "https://accounts.google.com/",
    "https://login.microsoftonline.com/",
    "https://www.netflix.com/login",
    "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0",
    "https://www.tiktok.com/login",
    "https://appleid.apple.com/sign-in",
    "https://www.notion.so/login",
    "https://www.figma.com/login",
    "https://claude.ai/login",
]


async def check(client, sem, url):
    async with sem:
        t0 = time.monotonic()
        try:
            r = await client.post(f"{AGENT}/verify", json={"url": url}, timeout=60.0)
            r.raise_for_status()
            return url, r.json(), time.monotonic() - t0, None
        except Exception as e:
            return url, None, time.monotonic() - t0, str(e) or type(e).__name__


async def stored_since(client, url, since):
    """Did a screenshot of this URL reach the core API after `since`?"""
    try:
        r = await client.get(f"{CORE}/evidence", params={"url": url, "limit": 1}, timeout=10.0)
        r.raise_for_status()
        latest = r.json()
    except Exception:
        return None   # core API unreachable
    return bool(latest) and latest[0]["captured_at"] >= since


def row(cols, widths):
    return "  ".join(str(c)[:w].ljust(w) for c, w in zip(cols, widths))


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("urls", nargs="*")
    ap.add_argument("--fake", action="store_true", help="all local fake sites (expect phishing)")
    ap.add_argument("--real", action="store_true", help="real login pages (expect cleared)")
    ap.add_argument("--file", help="file with one URL per line")
    ap.add_argument("--parallel", type=int, default=3, help="browsers at once (each ~300 MB)")
    ap.add_argument("--fresh", action="store_true", help="clear the agent's verdict cache first")
    args = ap.parse_args()

    urls = list(args.urls)
    expect = {}
    if args.fake:
        urls += FAKE + FAKE_CLEAN
        expect.update({u: True for u in FAKE})
        expect.update({u: False for u in FAKE_CLEAN})
    if args.real:
        urls += REAL
        expect.update({u: False for u in REAL})
    if args.file:
        with open(args.file) as f:
            urls += [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not urls:
        ap.error("give some URLs, or --fake / --real / --file")

    sem = asyncio.Semaphore(args.parallel)
    async with httpx.AsyncClient() as client:
        if args.fresh:
            await client.post(f"{AGENT}/cache/clear", timeout=10.0)
        started = datetime.now(timezone.utc).isoformat()
        results = await asyncio.gather(*(check(client, sem, u) for u in dict.fromkeys(urls)))
        # uploads happen just after each verdict; give the last ones a moment
        await asyncio.sleep(3)
        stored = {}
        for url, v, _, err in results:
            if v and not v.get("cached") and v.get("evidence"):
                stored[url] = await stored_since(client, url, started)

    widths = [44, 10, 5, 10, 8, 8, 6, 6]
    print(row(["URL", "VERDICT", "CONF", "BRAND", "OFF-DOM", "EVIDENCE", "TIME", "CHECK"], widths))
    print("-" * (sum(widths) + 2 * len(widths)))
    wrong = errors = missing = blocked = 0
    for url, v, secs, err in results:
        if err:
            errors += 1
            print(row([url, "ERROR", "", err, "", "", f"{secs:.1f}s", ""], widths))
            continue
        verdict = "PHISHING" if v["phishing"] else "BLOCKED" if v.get("blocked") else "cleared"
        ok = ""
        if v.get("blocked"):
            blocked += 1
            ok = "n/a"   # the agent couldn't see the page, so it can't be right or wrong
        elif url in expect:
            ok = "ok" if v["phishing"] == expect[url] else "WRONG"
            wrong += ok == "WRONG"
        if v.get("cached"):
            evidence = "cached"
        elif not v.get("evidence"):
            evidence = "no shot"
        else:
            evidence = {True: "stored", False: "MISSING", None: "no API"}[stored.get(url)]
            missing += evidence == "MISSING"
        print(row([url, verdict, f"{v['confidence']:.2f}", v.get("brand") or "-",
                   "yes" if v["off_domain"] else "no", evidence, f"{secs:.1f}s", ok], widths))

    checked = len(results) - errors
    print(f"\n{checked} checked, {errors} errors"
          + (f", {wrong} not as expected" if expect else "")
          + (f", {missing} screenshots MISSING from the core API" if missing else "")
          + (f", {blocked} blocked by a bot check" if blocked else ""))


if __name__ == "__main__":
    asyncio.run(main())
