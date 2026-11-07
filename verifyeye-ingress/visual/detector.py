"""Brand logo and impersonation detector for VerifyEye.

Combines YOLO visual detection with DOM/text heuristic brand extraction
for credential harvesting and phishing pages.
"""

from __future__ import annotations

import re
from typing import Optional, List, Dict, Any

# Brands phishing pages impersonate, as the words / domains that name them.
# Deliberately specific: generic phrases ("sign in to your account", "sso",
# "prime", "meta") named the wrong brand on most real login pages (#4).
BRANDS: Dict[str, Dict[str, list]] = {
    "Microsoft":        {"words": ["microsoft", "office 365", "outlook", "onedrive", "sharepoint"],
                         "domains": ["microsoft", "microsoftonline", "office", "live", "outlook"]},
    "Google":           {"words": ["google", "gmail"], "domains": ["google", "gmail"]},
    "Apple":            {"words": ["apple id", "apple account", "icloud", "itunes"], "domains": ["apple", "icloud"]},
    "PayPal":           {"words": ["paypal"], "domains": ["paypal"]},
    "Okta":             {"words": ["okta"], "domains": ["okta"]},
    "Amazon":           {"words": ["amazon"], "domains": ["amazon"]},
    "DocuSign":         {"words": ["docusign"], "domains": ["docusign"]},
    "Adobe":            {"words": ["adobe", "acrobat", "creative cloud"], "domains": ["adobe"]},
    "Dropbox":          {"words": ["dropbox"], "domains": ["dropbox"]},
    "Chase":            {"words": ["chase", "jpmorgan"], "domains": ["chase", "jpmorgan"]},
    "Bank of America":  {"words": ["bank of america"], "domains": ["bankofamerica", "bofa"]},
    "Wells Fargo":      {"words": ["wells fargo"], "domains": ["wellsfargo"]},
    "Netflix":          {"words": ["netflix"], "domains": ["netflix"]},
    "DHL":              {"words": ["dhl"], "domains": ["dhl"]},
    "Claude":           {"words": ["claude", "anthropic"], "domains": ["claude", "anthropic"]},
    "GitHub":           {"words": ["github"], "domains": ["github"]},
    "Instagram":        {"words": ["instagram"], "domains": ["instagram"]},
    "Facebook":         {"words": ["facebook"], "domains": ["facebook"]},
    "TikTok":           {"words": ["tiktok"], "domains": ["tiktok"]},
    "Notion":           {"words": ["notion"], "domains": ["notion"]},
    "Figma":            {"words": ["figma"], "domains": ["figma"]},
}

# "Continue with Google", "Sign in with Apple"... are third-party sign-in
# buttons on almost every login page; they say nothing about whose page it is
OAUTH_BUTTONS = re.compile(
    r"\b(continue|sign\s*in|log\s*in|sign\s*up)\s+(with|using|via)\s+[a-z0-9 ]{2,20}", re.IGNORECASE)

# how much each place counts. the page's own domain and title are what a
# person reads as "whose page is this"; where the form posts is a strong
# hint on phishing kits; body text only adds a little
W_HOST, W_TITLE, W_ACTION, W_TEXT, TEXT_CAP = 6, 5, 3, 1, 3
MIN_SCORE = 3


def _word(term: str) -> re.Pattern:
    return re.compile(r"\b" + re.escape(term).replace(r"\ ", r"\s+") + r"\b", re.IGNORECASE)


_PATTERNS = {b: [_word(w) for w in spec["words"]] for b, spec in BRANDS.items()}


def _host_labels(url: str) -> list[str]:
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    # "netflix-account-verify.com" -> ["netflix", "account", "verify", "com"]
    return re.split(r"[.\-]", host) if host else []


def infer_brand_from_page(
    title: str = "",
    url: str = "",
    form_actions: Optional[List[str]] = None,
    page_text: str = "",
) -> Optional[str]:
    """The brand this page presents itself as, or None if nothing clearly does.

    Scores every brand on where it appears (own domain, title, form target,
    body text) and returns the strongest one above MIN_SCORE, instead of the
    first keyword hit anywhere on the page."""
    text = OAUTH_BUTTONS.sub(" ", page_text or "")
    title_clean = OAUTH_BUTTONS.sub(" ", title or "")
    host = _host_labels(url)
    action_hosts = [_host_labels(a) for a in (form_actions or []) if a and "//" in a]

    best, best_score = None, 0
    for brand, spec in BRANDS.items():
        pats = _PATTERNS[brand]
        score = 0
        if any(d in host for d in spec["domains"]):
            score += W_HOST
        if any(p.search(title_clean) for p in pats):
            score += W_TITLE
        if any(any(d in labels for d in spec["domains"]) for labels in action_hosts):
            score += W_ACTION
        mentions = sum(len(p.findall(text)) for p in pats)
        score += min(mentions, TEXT_CAP) * W_TEXT
        if score > best_score:
            best, best_score = brand, score

    return best if best_score >= MIN_SCORE else None


def detect_logo(image_path: str) -> List[Dict[str, Any]]:
    """Runs YOLO object/logo detection if ultralytics is available, with graceful fallback."""
    try:
        from importlib import import_module
        YOLO = import_module("ultralytics").YOLO
        model = YOLO("yolov8n.pt")
        results = model(image_path)

        detected_objects = []
        for result in results:
            boxes = result.boxes
            for box in boxes:
                class_id = int(box.cls[0])
                confidence = float(box.conf[0])
                class_name = result.names[class_id]
                detected_objects.append({
                    "object": class_name,
                    "confidence": confidence,
                })
        return detected_objects
    except Exception:
        # ultralytics not installed or image load error -> fallback empty
        return []
