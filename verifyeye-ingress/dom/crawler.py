from __future__ import annotations

import re
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from visual.detector import infer_brand_from_page


# bot checks (Cloudflare, Akamai, captchas...) stop the agent seeing the real
# page. that's "couldn't look", not "safe", so the verdict must say so (#9)
CHALLENGE_TITLE = re.compile(r"just a moment|attention required|security check|access denied|are you a robot|verify you are human|captcha", re.I)
CHALLENGE_BODY = re.compile(r"verify you are (a )?human|checking (if the site connection is secure|your browser)|enable javascript and cookies to continue|press (&|and) hold|unusual traffic from your computer", re.I)


def _bot_check(title: str, body: str, frames, has_inputs: bool) -> Optional[str]:
    # an interstitial ("Just a moment...") replaces the whole page
    if CHALLENGE_TITLE.search(title or ""):
        return "challenge page"
    # captcha widgets and challenge wording only block us when there's nothing
    # else on the page: plenty of real logins (Netflix) carry an invisible
    # reCAPTCHA next to a perfectly visible form
    if has_inputs:
        return None
    if any("challenges.cloudflare.com" in (f.url or "") or "captcha" in (f.url or "") for f in frames):
        return "captcha"
    if CHALLENGE_BODY.search((body or "")[:3000]):
        return "challenge page"
    return None


# buttons / links that usually reveal a login form on single-page apps
REVEAL = re.compile(r"^\s*(sign\s?in|log\s?in|login|continue|next|use password)\b", re.I)


def _reveal_login_form(page) -> None:
    """Some logins (React apps, our spa-test fixture) only render the form after
    a click. If there's no password field yet, click the first visible
    sign-in style button once and give the form a moment to appear."""
    if page.locator("input[type='password']").count() > 0:
        return
    candidates = page.locator("button, a, [role='button'], input[type='submit']").filter(has_text=REVEAL)
    for i in range(min(candidates.count(), 3)):
        target = candidates.nth(i)
        try:
            if not target.is_visible():
                continue
            target.click(timeout=2000)
            page.wait_for_selector("input[type='password']", timeout=3000)
            return
        except Exception:
            continue


def _analyze_with_playwright(url: str) -> Dict[str, Any]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # a fixed desktop viewport, so evidence screenshots are comparable
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        try:
            page.wait_for_selector("input[type='password']", timeout=5000)
        except Exception:
            _reveal_login_form(page)
        # let fonts / logos settle so the evidence shows what a person would see
        try:
            page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            pass

        # evidence (#3): what the agent actually saw. JPEG keeps it ~100-250 KB
        try:
            screenshot = page.screenshot(type="jpeg", quality=70)
        except Exception:
            screenshot = None
        final_url = page.url

        title = page.title()
        forms = page.locator("form")
        form_count = forms.count()

        credential_form = False
        username_field = False
        password_field = False
        form_actions: List[str] = []

        for i in range(form_count):
            form = forms.nth(i)
            password_fields = form.locator("input[type='password']")
            username_fields = form.locator(
                "input[type='text'], input[type='email'], input[name*='user'], input[name*='email'], input[name*='login']"
            )

            has_pwd = password_fields.count() > 0
            has_usr = username_fields.count() > 0

            if has_pwd:
                password_field = True
            if has_usr:
                username_field = True
            if has_pwd and has_usr:
                credential_form = True

            action = form.get_attribute("action") or url
            form_actions.append(action)

        body_text = page.inner_text("body") if page.locator("body").count() > 0 else ""
        has_inputs = page.locator("input:visible").count() > 0
        blocked_by = _bot_check(title, body_text, page.frames, has_inputs)
        browser.close()

        brand_target = infer_brand_from_page(
            title=title,
            url=url,
            form_actions=form_actions,
            page_text=body_text[:2000],
        )

        return {
            "url": url,
            "final_url": final_url,
            "screenshot": screenshot,
            "title": title,
            "form_count": form_count,
            "credential_form": credential_form,
            "username_field": username_field,
            "password_field": password_field,
            "form_actions": form_actions,
            "brand_target": brand_target,
            "blocked_by": blocked_by,
        }


def _analyze_with_httpx(url: str) -> Dict[str, Any]:
    """Fallback parser when Playwright browser is not installed or available."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    resp = httpx.get(url, headers=headers, follow_redirects=True, timeout=10.0)
    html = resp.text

    # Extract title
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else ""

    # Extract forms
    # (attributes of the <form> tag, its inner html)
    forms = re.findall(r"<form\b([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
    form_count = len(forms)

    credential_form = False
    username_field = False
    password_field = False
    form_actions: List[str] = []

    for form_attrs, form_html in forms:
        has_pwd = bool(re.search(r'type=["\']password["\']', form_html, re.IGNORECASE))
        has_usr = bool(re.search(r'type=["\'](text|email)["\']|name=["\'][^"\']*(user|email|login)[^"\']*["\']', form_html, re.IGNORECASE))

        if has_pwd:
            password_field = True
        if has_usr:
            username_field = True
        if has_pwd and has_usr:
            credential_form = True

        action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
        action = action_match.group(1) if action_match else url
        form_actions.append(action)

    brand_target = infer_brand_from_page(
        title=title,
        url=url,
        form_actions=form_actions,
        page_text=html[:3000],
    )

    return {
        "url": str(resp.url),
        "title": title,
        "form_count": form_count,
        "credential_form": credential_form,
        "username_field": username_field,
        "password_field": password_field,
        "form_actions": form_actions,
        "brand_target": brand_target,
    }


def analyze_page(url: str) -> Dict[str, Any]:
    """Analyzes a web page for credential harvesting and phishing signals."""
    try:
        return _analyze_with_playwright(url)
    except Exception:
        # Fall back to lightweight HTTP parsing
        return _analyze_with_httpx(url)
