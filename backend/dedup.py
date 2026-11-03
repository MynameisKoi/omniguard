"""Simhash perceptual alert deduplication and fusion module for OmniGuard SOC.

Inspired by enterprise SIEM alert reduction patterns (e.g. AiSOC / OCSF incident grouping):
Calculates a 64-bit locality-sensitive Simhash over alert properties.
Near-duplicate alerts occurring within a sliding time window (e.g., repeated C2 beacons
or automated scanners) are fused into a single incident with an incremented occurrence_count
and refreshed last_seen timestamp rather than flooding the dashboard and attack graph.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def tokenize(text: str) -> List[str]:
    """Extract lower-cased alphanumeric tokens from text."""
    if not text:
        return []
    return re.findall(r"\w+", text.lower())


def simhash(features: List[str], hash_bits: int = 64) -> int:
    """
    Computes a 64-bit Simhash fingerprint from a list of feature tokens.
    Simhash preserves locality: small token differences result in a small Hamming distance.
    """
    if not features:
        return 0

    v = [0] * hash_bits
    for feature in features:
        digest = int(hashlib.md5(feature.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(hash_bits):
            bit = (digest >> i) & 1
            if bit == 1:
                v[i] += 1
            else:
                v[i] -= 1

    fingerprint = 0
    for i in range(hash_bits):
        if v[i] > 0:
            fingerprint |= 1 << i

    return fingerprint


def hamming_distance(hash1: int, hash2: int) -> int:
    """Computes the Hamming distance (number of differing bits) between two 64-bit integers."""
    return bin(hash1 ^ hash2).count("1")


def compute_alert_simhash(alert_data: Dict[str, Any]) -> Tuple[int, str]:
    """
    Extracts semantic features from an alert dictionary and returns:
    (simhash_int, simhash_hex_str)
    """
    features: List[str] = []

    source = alert_data.get("source") or ""
    event_type = alert_data.get("event_type") or ""
    host = alert_data.get("host") or ""
    domain = alert_data.get("domain") or ""
    mitre = alert_data.get("mitre_technique") or ""

    if source:
        features.extend([f"src:{source.lower()}"] * 3)
    if event_type:
        features.extend([f"evt:{event_type.lower()}"] * 3)
    if host:
        features.extend([f"hst:{host.lower()}"] * 4)
    if domain:
        features.extend([f"dom:{domain.lower()}"] * 4)
    if mitre:
        features.extend([f"mit:{mitre.lower()}"] * 2)

    desc = alert_data.get("description") or ""
    for tok in tokenize(desc):
        features.append(f"desc:{tok}")

    val = simhash(features)
    return val, f"{val:016x}"


def find_matching_alert(
    new_simhash: int,
    recent_alerts: List[Dict[str, Any]],
    max_hamming_distance: int = 3,
) -> Optional[Dict[str, Any]]:
    """
    Searches candidate recent alerts to find a near-duplicate within max_hamming_distance.
    Returns the matching alert document if found, else None.
    """
    for alert in recent_alerts:
        existing_hex = alert.get("simhash")
        if not existing_hex:
            continue
        try:
            existing_val = int(existing_hex, 16)
        except ValueError:
            continue

        dist = hamming_distance(new_simhash, existing_val)
        if dist <= max_hamming_distance:
            return alert

    return None
