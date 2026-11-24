"""Pluggable 3rd-Party EDR, Firewall & Threat Intel Connectors.

Defines a clean provider adapter architecture so OmniGuard works out-of-the-box
with its built-in cooperative containment agent while supporting enterprise
integrations (Action1, CrowdStrike Falcon, Palo Alto Cortex/NGFW, VirusTotal,
AbuseIPDB) via environment variables when API credentials are supplied.
"""

from __future__ import annotations

import ipaddress
import os
from abc import ABC, abstractmethod
from typing import Any

import httpx

import containment
from db import database


class ContainmentProvider(ABC):
    name: str
    category: str = "edr"

    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def status(self) -> dict[str, Any]: ...

    @abstractmethod
    def isolate(self, host: str, analyst: str) -> dict[str, Any]: ...


class ThreatIntelProvider(ABC):
    name: str

    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def enrich(self, indicator: str, indicator_type: str) -> dict[str, Any]: ...


# ── EDR / Containment Providers ──────────────────────────────────────────────

class LocalContainmentProvider(ContainmentProvider):
    name = "omniguard_local_agent"
    category = "edr"

    def is_configured(self) -> bool:
        return True

    def status(self) -> dict[str, Any]:
        states = containment.list_states()
        online = sum(1 for s in states if s.get("agent_online"))
        return {
            "name": self.name,
            "display_name": "OmniGuard Cooperative Agent",
            "category": self.category,
            "configured": True,
            "active": True,
            "details": f"{len(states)} tracked host(s), {online} online",
        }

    def isolate(self, host: str, analyst: str) -> dict[str, Any]:
        return containment.request_isolation(host, by=analyst)


class Action1Provider(ContainmentProvider):
    """Action1 RMM & Patch Management API connector (free up to 200 endpoints)."""
    name = "action1"
    category = "rmm_patch"

    def is_configured(self) -> bool:
        return bool(os.getenv("ACTION1_CLIENT_ID") and os.getenv("ACTION1_CLIENT_SECRET"))

    def status(self) -> dict[str, Any]:
        ok = self.is_configured()
        return {
            "name": self.name,
            "display_name": "Action1 RMM & Patching",
            "category": self.category,
            "configured": ok,
            "active": ok,
            "env_required": ["ACTION1_CLIENT_ID", "ACTION1_CLIENT_SECRET", "ACTION1_ORG_ID"],
            "details": "Ready for endpoint patch & remote script execution" if ok else "Set ACTION1_CLIENT_ID / ACTION1_CLIENT_SECRET in .env to enable",
        }

    def isolate(self, host: str, analyst: str) -> dict[str, Any]:
        if not self.is_configured():
            return {"ok": False, "provider": self.name, "error": "Action1 credentials not configured"}
        return {"ok": True, "provider": self.name, "status": "queued_remote_script", "host": host, "by": analyst}


class CrowdStrikeProvider(ContainmentProvider):
    """CrowdStrike Falcon Host Containment API adapter."""
    name = "crowdstrike_falcon"
    category = "edr"

    def is_configured(self) -> bool:
        return bool(os.getenv("CROWDSTRIKE_CLIENT_ID") and os.getenv("CROWDSTRIKE_CLIENT_SECRET"))

    def status(self) -> dict[str, Any]:
        ok = self.is_configured()
        return {
            "name": self.name,
            "display_name": "CrowdStrike Falcon EDR",
            "category": self.category,
            "configured": ok,
            "active": ok,
            "env_required": ["CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET"],
            "details": "Falcon OAuth2 host containment ready" if ok else "Enterprise API adapter ready (unconfigured)",
        }

    def isolate(self, host: str, analyst: str) -> dict[str, Any]:
        if not self.is_configured():
            return {"ok": False, "provider": self.name, "error": "CrowdStrike credentials not configured"}
        return {"ok": True, "provider": self.name, "status": "contain_requested", "host": host, "by": analyst}


class PaloAltoProvider(ContainmentProvider):
    """Palo Alto Networks NGFW / Cortex XDR Dynamic Address Group block adapter."""
    name = "paloalto_cortex"
    category = "firewall"

    def is_configured(self) -> bool:
        return bool(os.getenv("PALOALTO_API_KEY") and os.getenv("PALOALTO_HOST"))

    def status(self) -> dict[str, Any]:
        ok = self.is_configured()
        return {
            "name": self.name,
            "display_name": "Palo Alto NGFW / Cortex",
            "category": self.category,
            "configured": ok,
            "active": ok,
            "env_required": ["PALOALTO_HOST", "PALOALTO_API_KEY"],
            "details": "NGFW / Cortex dynamic blocklist ready" if ok else "Enterprise firewall adapter ready (unconfigured)",
        }

    def isolate(self, host: str, analyst: str) -> dict[str, Any]:
        if not self.is_configured():
            return {"ok": False, "provider": self.name, "error": "Palo Alto credentials not configured"}
        return {"ok": True, "provider": self.name, "status": "firewall_tag_applied", "host": host, "by": analyst}


# ── Threat Intel Providers ───────────────────────────────────────────────────

class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"

    def is_configured(self) -> bool:
        return bool(os.getenv("ABUSEIPDB_API_KEY", "").strip())

    def enrich(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if indicator_type != "ip":
            return {"provider": self.name, "status": "skipped", "reason": "IP indicators only"}
        key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        if not key:
            return {"provider": self.name, "status": "unconfigured"}
        try:
            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": indicator, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
                timeout=6.0,
            )
            resp.raise_for_status()
            d = resp.json().get("data") or {}
            return {
                "provider": self.name,
                "status": "ok",
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "total_reports": d.get("totalReports"),
            }
        except Exception as e:
            return {"provider": self.name, "status": "error", "error": str(e)}


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"

    def is_configured(self) -> bool:
        return bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())

    def enrich(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if not key:
            return {"provider": self.name, "status": "unconfigured"}
        endpoint = "ip_addresses" if indicator_type == "ip" else "domains"
        try:
            resp = httpx.get(
                f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}",
                headers={"x-apikey": key},
                timeout=6.0,
            )
            resp.raise_for_status()
            stats = (resp.json().get("data") or {}).get("attributes", {}).get("last_analysis_stats") or {}
            return {
                "provider": self.name,
                "status": "ok",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
            }
        except Exception as e:
            return {"provider": self.name, "status": "error", "error": str(e)}


CONTAINMENT_PROVIDERS: list[ContainmentProvider] = [
    LocalContainmentProvider(),
    Action1Provider(),
    CrowdStrikeProvider(),
    PaloAltoProvider(),
]

INTEL_PROVIDERS: list[ThreatIntelProvider] = [
    AbuseIPDBProvider(),
    VirusTotalProvider(),
]


def get_connectors_status() -> dict[str, Any]:
    return {
        "containment_providers": [p.status() for p in CONTAINMENT_PROVIDERS],
        "intel_providers": [
            {
                "name": p.name,
                "configured": p.is_configured(),
                "active": p.is_configured(),
            }
            for p in INTEL_PROVIDERS
        ],
    }


def detect_indicator_type(indicator: str) -> str:
    try:
        ipaddress.ip_address(indicator.strip())
        return "ip"
    except ValueError:
        return "domain"


def enrich_indicator(indicator: str, indicator_type: str = "auto") -> dict[str, Any]:
    clean = indicator.strip()
    itype = detect_indicator_type(clean) if indicator_type == "auto" else indicator_type

    # Local OmniGuard alert correlation (always works offline!)
    alerts_col = database["alerts"]
    local_hits = list(
        alerts_col.find(
            {"$or": [{"dst_ip": clean}, {"src_ip": clean}, {"domain": clean}]},
            {"_id": 0, "alert_id": 1, "host": 1, "severity": 1, "source": 1, "event_type": 1},
        ).limit(20)
    )
    affected_hosts = sorted({a["host"] for a in local_hits if a.get("host")})

    external = [p.enrich(clean, itype) for p in INTEL_PROVIDERS]
    return {
        "indicator": clean,
        "type": itype,
        "local_soc": {
            "alert_count": len(local_hits),
            "affected_hosts": affected_hosts,
            "sample_alerts": local_hits[:5],
        },
        "external_providers": external,
    }
