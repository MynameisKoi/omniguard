from __future__ import annotations

import argparse
import sys
import urllib.parse
import httpx

from dom.crawler import analyze_page


def main():
    parser = argparse.ArgumentParser(description="VerifyEye Phishing & Credential Harvester Ingress")
    parser.add_argument("--url", help="Target URL to inspect (if omitted, prompts interactively)")
    parser.add_argument("--api", default="http://localhost:8000", help="OmniGuard backend API base URL")
    parser.add_argument("--host", default="WORKSTATION-CORP-01", help="Affected host identifier")
    parser.add_argument("--user", default=None, help="Attributable user username")
    parser.add_argument("--no-post", action="store_true", help="Inspect only, do not dispatch alert to backend")

    args = parser.parse_args()

    url = args.url
    if not url:
        try:
            url = input("Enter website URL: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    if not url:
        print("Error: No URL provided.")
        sys.exit(1)

    try:
        result = analyze_page(url)

        print("\n===== VerifyEye Result =====")
        print("URL:            ", result["url"])
        print("Title:          ", result["title"])
        print("Brand Target:   ", result.get("brand_target") or "None detected")
        print("Forms:          ", result["form_count"])
        print("Credential Form:", result["credential_form"])
        print("Username Field: ", result["username_field"])
        print("Password Field: ", result["password_field"])

        if result.get("form_actions"):
            print("\nForm Actions:")
            for action in result["form_actions"]:
                print("-", action)

        # Phishing detection heuristic
        parsed = urllib.parse.urlparse(result["url"])
        domain = parsed.hostname or ""
        credential_form = result.get("credential_form", False)
        brand_target = result.get("brand_target")

        # If credential form or brand impersonation detected, construct alert
        if credential_form or brand_target:
            primary_action = result["form_actions"][0] if result["form_actions"] else None
            sev = "critical" if credential_form else "high"
            brand_str = f" impersonating {brand_target}" if brand_target else ""
            desc = (
                f"Phishing page{brand_str} detected at {result['url']}. "
                f"Credential harvesting form submitting to {primary_action or 'external endpoint'}."
            )

            alert_payload = {
                "source": "verifyeye",
                "event_type": "phishing_page_detected",
                "severity": sev,
                "host": args.host,
                "user": args.user,
                "domain": domain,
                "target_url": result["url"],
                "action_endpoint": primary_action,
                "brand_target": brand_target,
                "mitre_technique": "T1566",
                "confidence": 0.94 if credential_form else 0.72,
                "description": desc,
            }

            if not args.no_post:
                endpoint = f"{args.api.rstrip('/')}/alerts"
                print(f"\n[+] Dispatching alert to OmniGuard SOC API ({endpoint})...")
                try:
                    resp = httpx.post(endpoint, json=alert_payload, timeout=10.0)
                    if resp.status_code == 201:
                        created = resp.json()
                        print(f"[✓] Alert ingested successfully! Alert ID: {created.get('alert_id')}")
                    else:
                        print(f"[!] Backend returned status {resp.status_code}: {resp.text}")
                except Exception as api_err:
                    print(f"[!] Failed to dispatch alert to backend: {api_err}")
            else:
                print("\n[i] Dry-run (--no-post): Alert generated but not dispatched:")
                print(alert_payload)

    except Exception as error:
        print("Error during analysis:", error)
        sys.exit(1)


if __name__ == "__main__":
    main()