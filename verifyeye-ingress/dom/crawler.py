from __future__ import annotations

import re
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from visual.detector import infer_brand_from_page


def _analyze_with_playwright(url: str) -> Dict[str, Any]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="domcontentloaded", timeout=15000)

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
        browser.close()

        brand_target = infer_brand_from_page(
            title=title,
            url=url,
            form_actions=form_actions,
            page_text=body_text[:2000],
        )

        return {
            "url": url,
            "title": title,
            "form_count": form_count,
            "credential_form": credential_form,
            "username_field": username_field,
            "password_field": password_field,
            "form_actions": form_actions,
            "brand_target": brand_target,
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
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
    form_count = len(forms)

    credential_form = False
    username_field = False
    password_field = False
    form_actions: List[str] = []

    for form_html in forms:
        has_pwd = bool(re.search(r'type=["\']password["\']', form_html, re.IGNORECASE))
        has_usr = bool(re.search(r'type=["\'](text|email)["\']|name=["\'][^"\']*(user|email|login)[^"\']*["\']', form_html, re.IGNORECASE))

        if has_pwd:
            password_field = True
        if has_usr:
            username_field = True
        if has_pwd and has_usr:
            credential_form = True

        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
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