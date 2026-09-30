"""Brand logo and impersonation detector for VerifyEye.

Combines YOLO visual detection with DOM/text heuristic brand extraction
for credential harvesting and phishing pages.
"""

from __future__ import annotations

import re
from typing import Optional, List, Dict, Any

# Common high-value phishing target brands and signature patterns
BRAND_SIGNATURES: Dict[str, list[re.Pattern]] = {
    "Microsoft 365": [
        re.compile(r"microsoft|office\s*365|outlook|onedrive|sharepoint|live\.com|msn", re.IGNORECASE),
        re.compile(r"sign\s*in\s*to\s*your\s*account", re.IGNORECASE),
    ],
    "Google Workspace": [
        re.compile(r"google|gmail|workspace|accounts\.google", re.IGNORECASE),
        re.compile(r"sign\s*in\s*with\s*google", re.IGNORECASE),
    ],
    "Apple ID": [
        re.compile(r"apple\s*id|icloud|itunes", re.IGNORECASE),
    ],
    "PayPal": [
        re.compile(r"paypal|pay\s*pal", re.IGNORECASE),
    ],
    "Okta": [
        re.compile(r"okta|single\s*sign-on|sso", re.IGNORECASE),
    ],
    "Amazon": [
        re.compile(r"amazon|aws|prime", re.IGNORECASE),
    ],
    "DocuSign": [
        re.compile(r"docusign|electronic\s*signature", re.IGNORECASE),
    ],
    "Adobe": [
        re.compile(r"adobe|creative\s*cloud|acrobat", re.IGNORECASE),
    ],
    "Dropbox": [
        re.compile(r"dropbox", re.IGNORECASE),
    ],
    "Chase Bank": [
        re.compile(r"chase|jpmorgan", re.IGNORECASE),
    ],
    "Bank of America": [
        re.compile(r"bank\s*of\s*america|bofa", re.IGNORECASE),
    ],
    "Wells Fargo": [
        re.compile(r"wells\s*fargo", re.IGNORECASE),
    ],
    "Netflix": [
        re.compile(r"netflix", re.IGNORECASE),
    ],
    "DHL Express": [
        re.compile(r"dhl|parcel\s*tracking", re.IGNORECASE),
    ],
}


def infer_brand_from_page(
    title: str = "",
    url: str = "",
    form_actions: Optional[List[str]] = None,
    page_text: str = "",
) -> Optional[str]:
    """Infers the targeted brand using DOM title, URL path heuristics, and text signatures."""
    combined = f"{title} {url} {' '.join(form_actions or [])} {page_text}"

    for brand, patterns in BRAND_SIGNATURES.items():
        for pat in patterns:
            if pat.search(combined):
                return brand

    return None


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