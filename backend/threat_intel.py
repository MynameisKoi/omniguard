"""Security Patch & Threat News Analyzer (CISA KEV + Local LLM Brief).

Pulls the official CISA Known Exploited Vulnerabilities (KEV) JSON catalog
(free, no API key required) with an in-memory cache and graceful offline
fallback for closed-network demos, then summarizes actionable patch priorities
using the local Ollama model (traced via AITraceContext).
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from ai_transparency import AITraceContext
from config import OLLAMA_MODEL, OLLAMA_URL

try:
    from config import OLLAMA_NUM_GPU
except ImportError:
    OLLAMA_NUM_GPU = None

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_TTL_SECONDS = 3600
_kev_cache: dict[str, Any] = {"fetched_at": 0.0, "source": "fallback", "vulnerabilities": []}

OFFLINE_FALLBACK_KEV: list[dict[str, Any]] = [
    {
        "cveID": "CVE-2025-21298",
        "vendorProject": "Microsoft",
        "product": "Windows OLE",
        "vulnerabilityName": "Microsoft Windows OLE Remote Code Execution Vulnerability",
        "dateAdded": "2025-01-14",
        "shortDescription": "Zero-click RCE triggered when previewing a crafted RTF email in Outlook.",
        "requiredAction": "Apply Microsoft Patch Tuesday security updates immediately.",
        "dueDate": "2025-02-04",
        "knownRansomwareCampaignUse": "Unknown",
    },
    {
        "cveID": "CVE-2024-43451",
        "vendorProject": "Microsoft",
        "product": "Windows MSHTML",
        "vulnerabilityName": "Microsoft Windows MSHTML Platform Spoofing & NTLM Hash Disclosure",
        "dateAdded": "2024-11-12",
        "shortDescription": "Minimal user interaction with a malicious URL file exposes NTLMv2 hashes.",
        "requiredAction": "Install latest Windows cumulative update and block outbound SMB.",
        "dueDate": "2024-12-03",
        "knownRansomwareCampaignUse": "Known",
    },
    {
        "cveID": "CVE-2024-38077",
        "vendorProject": "Microsoft",
        "product": "Windows Remote Desktop Licensing Service",
        "vulnerabilityName": "Windows Remote Desktop Licensing Service RCE (MadLicense)",
        "dateAdded": "2024-07-09",
        "shortDescription": "Unauthenticated heap buffer overflow leading to SYSTEM code execution.",
        "requiredAction": "Patch Windows Server RDL service or disable unused licensing roles.",
        "dueDate": "2024-07-30",
        "knownRansomwareCampaignUse": "Known",
    },
    {
        "cveID": "CVE-2024-3094",
        "vendorProject": "Tukaani",
        "product": "XZ Utils / OpenSSH (Linux)",
        "vulnerabilityName": "Supply-Chain Backdoor in liblzma (XZ Utils 5.6.0-5.6.1)",
        "dateAdded": "2024-03-29",
        "shortDescription": "Malicious upstream build artifact intercepts SSH authentication on affected Linux builds.",
        "requiredAction": "Verify xz-utils version is <=5.4.x or >=5.6.2 clean rebuild.",
        "dueDate": "2024-04-05",
        "knownRansomwareCampaignUse": "Unknown",
    },
    {
        "cveID": "CVE-2024-4761",
        "vendorProject": "Google",
        "product": "Chromium / Chrome V8",
        "vulnerabilityName": "Chromium V8 Out-of-Bounds Write Vulnerability",
        "dateAdded": "2024-05-14",
        "shortDescription": "Actively exploited browser engine memory corruption via crafted web page.",
        "requiredAction": "Update Chrome/Edge/Chromium browsers across all corporate endpoints.",
        "dueDate": "2024-06-04",
        "knownRansomwareCampaignUse": "Unknown",
    },
]


def fetch_cisa_kev(limit: int = 15, query: str | None = None, force_refresh: bool = False) -> dict[str, Any]:
    """Fetch recent CISA KEV advisories (cached 1h, graceful offline fallback)."""
    now = time.time()
    if force_refresh or not _kev_cache["vulnerabilities"] or (now - _kev_cache["fetched_at"] > _CACHE_TTL_SECONDS):
        try:
            resp = httpx.get(CISA_KEV_URL, timeout=6.0)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities") or []
            # Sort newest dateAdded first
            vulns.sort(key=lambda v: str(v.get("dateAdded", "")), reverse=True)
            _kev_cache.update({"fetched_at": now, "source": "cisa_kev_live", "vulnerabilities": vulns})
        except Exception:
            if not _kev_cache["vulnerabilities"]:
                _kev_cache.update({
                    "fetched_at": now,
                    "source": "offline_cached_kev",
                    "vulnerabilities": list(OFFLINE_FALLBACK_KEV),
                })

    items = _kev_cache["vulnerabilities"]
    if query and query.strip():
        q = query.strip().lower()
        items = [
            v for v in items
            if q in str(v.get("cveID", "")).lower()
            or q in str(v.get("vendorProject", "")).lower()
            or q in str(v.get("product", "")).lower()
            or q in str(v.get("vulnerabilityName", "")).lower()
            or q in str(v.get("shortDescription", "")).lower()
        ]

    sliced = items[: max(1, min(limit, 50))]
    return {
        "source": _kev_cache["source"],
        "total_matched": len(items),
        "count": len(sliced),
        "vulnerabilities": sliced,
    }


def _deterministic_patch_brief(vulns: list[dict[str, Any]], host_os_hints: list[str]) -> str:
    if not vulns:
        return "No matching CISA KEV security advisories were found for the current filter."
    ransom = [v for v in vulns if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"]
    lines = [
        f"Reviewed {len(vulns)} recent CISA Known Exploited Vulnerabilities ({len(ransom)} linked to active ransomware campaigns).",
        "",
        "Top Priority Patches:",
    ]
    for v in vulns[:5]:
        tag = " [RANSOMWARE]" if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else ""
        lines.append(
            f"- **{v.get('cveID')}** ({v.get('vendorProject')} {v.get('product')}){tag}: "
            f"{v.get('vulnerabilityName')} — {v.get('requiredAction')}"
        )
    if host_os_hints:
        lines.append(f"\nMonitored fleet context: {', '.join(sorted(set(host_os_hints)))}.")
    return "\n".join(lines)


def analyze_security_patches(
    query: str | None = None,
    limit: int = 8,
    host_os_hints: list[str] | None = None,
    analyst: str = "system",
) -> dict[str, Any]:
    """Summarize recent CISA KEV patches using local Ollama with AITraceContext + fallback."""
    feed = fetch_cisa_kev(limit=limit, query=query)
    vulns = feed["vulnerabilities"]
    hints = host_os_hints or []

    if not vulns:
        return {**feed, "analysis": _deterministic_patch_brief([], hints), "used_llm": False}

    bullet_list = "\n".join(
        f"- {v.get('cveID')} | {v.get('vendorProject')} {v.get('product')} | "
        f"Ransomware: {v.get('knownRansomwareCampaignUse', 'Unknown')} | "
        f"{v.get('shortDescription', '')} | Action: {v.get('requiredAction', '')}"
        for v in vulns[:8]
    )
    prompt = (
        "You are a SOC vulnerability analyst. Summarize these CISA Known Exploited Vulnerabilities "
        "into a concise patch-priority brief (<= 180 words):\n"
        "1. Immediate P0/P1 patches (call out ransomware-linked or browser/OS RCE flaws first).\n"
        "2. Concrete verification/mitigation steps for the SOC team.\n\n"
        + (f"Monitored hosts/OS: {', '.join(hints)}\n\n" if hints else "")
        + f"Advisories:\n{bullet_list}"
    )

    opts: dict[str, Any] = {"temperature": 0.2, "num_ctx": 4096, "num_predict": 320}
    if OLLAMA_NUM_GPU is not None:
        opts["num_gpu"] = OLLAMA_NUM_GPU

    try:
        with AITraceContext(
            caller="patch_analyzer",
            model=OLLAMA_MODEL,
            analyst=analyst,
            prompt_data=prompt,
            metadata={"kev_count": len(vulns), "query": query},
        ) as trace:
            resp = httpx.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "options": opts},
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
            text = data.get("response", "").strip()
            tokens = {
                "prompt": data.get("prompt_eval_count", 0),
                "completion": data.get("eval_count", 0),
                "total": data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
            }
            trace.set_result(content=text, tokens=tokens)
            return {**feed, "analysis": text or _deterministic_patch_brief(vulns, hints), "used_llm": bool(text)}
    except Exception:
        return {**feed, "analysis": _deterministic_patch_brief(vulns, hints), "used_llm": False}
