"""Multi-agent threat triage and containment pipeline for OmniGuard SOC.

Inspired by AiSOC multi-agent orchestration patterns:
Instead of relying on a monolithic prompt, this pipeline decomposes incident triage
into specialized security agents:
1. CorrelatorAgent: Evaluates multi-entity graph pivot points and blast radius.
2. TriageAgent: Maps MITRE ATT&CK tactics, calculates weighted risk scores (0-100),
   and assesses false-positive probability.
3. ContainmentAgent: Formulates actionable EDR containment and response playbooks
   under a human-in-the-loop governance model.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class CorrelatorAgent:
    """Agent 1: Correlates alerts and graph entities to map incident blast radius."""

    def run(self, host: str, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        host_alerts = [a for a in alerts if a.get("host") == host]
        all_hosts = {a.get("host") for a in alerts if a.get("host")}

        users = list({a.get("user") for a in host_alerts if a.get("user")})
        domains = list({a.get("domain") for a in host_alerts if a.get("domain")})
        c2_ips = list({a.get("dst_ip") for a in host_alerts if a.get("dst_ip")})
        sources = list({a.get("source") for a in host_alerts if a.get("source")})
        mitre_techniques = list({a.get("mitre_technique") for a in host_alerts if a.get("mitre_technique")})

        is_multi_vector = "verifyeye" in sources and "spectrac2" in sources
        is_multi_host = len(all_hosts) > 1

        return {
            "target_host": host,
            "alert_count": len(host_alerts),
            "sources": sources,
            "users": users,
            "domains": domains,
            "c2_ips": c2_ips,
            "mitre_techniques": mitre_techniques,
            "is_multi_vector": is_multi_vector,
            "blast_radius": "MULTI_HOST_CAMPAIGN" if is_multi_host else "ISOLATED_HOST",
        }


class TriageAgent:
    """Agent 2: Evaluates threat severity, MITRE tactics, and false positive risk."""

    def run(self, correlation: Dict[str, Any]) -> Dict[str, Any]:
        count = correlation.get("alert_count", 0)
        multi_vector = correlation.get("is_multi_vector", False)
        sources = correlation.get("sources", [])
        techniques = correlation.get("mitre_techniques", [])

        # Weighted composite risk scoring (0 - 100)
        risk_score = 0
        if count > 0:
            risk_score += min(count * 10, 30)
        if "spectrac2" in sources:
            risk_score += 35
        if "verifyeye" in sources:
            risk_score += 25
        if multi_vector:
            risk_score += 20  # Convergent C2 + Phishing attack

        risk_score = min(risk_score, 100)

        # Classification & Confidence
        if risk_score >= 80:
            classification = "TRUE_POSITIVE_ACTIVE_COMPROMISE"
            confidence = 0.95
        elif risk_score >= 50:
            classification = "SUSPICIOUS_THREAT_ACTIVITY"
            confidence = 0.80
        elif risk_score > 0:
            classification = "LOW_CONFIDENCE_ANOMALY"
            confidence = 0.50
        else:
            classification = "BENIGN_OR_NO_DATA"
            confidence = 0.10

        return {
            "risk_score": risk_score,
            "classification": classification,
            "confidence": confidence,
            "mitre_summary": {
                "techniques": techniques,
                "tactics": (
                    ["Initial Access (TA0001)", "Command and Control (TA0011)"]
                    if multi_vector
                    else ["Command and Control (TA0011)"] if "spectrac2" in sources
                    else ["Initial Access (TA0001)"] if "verifyeye" in sources
                    else []
                ),
            },
            "false_positive_probability": max(0.02, round(1.0 - confidence, 2)),
        }


class ContainmentAgent:
    """Agent 3: Formulates targeted response playbooks with human-in-the-loop approval."""

    def run(self, correlation: Dict[str, Any], triage: Dict[str, Any]) -> Dict[str, Any]:
        risk = triage.get("risk_score", 0)
        host = correlation.get("target_host", "UNKNOWN")
        domains = correlation.get("domains", [])
        users = correlation.get("users", [])

        actions: List[Dict[str, Any]] = []

        if risk >= 75:
            actions.append({
                "action": "NETWORK_ISOLATION",
                "target": host,
                "urgency": "IMMEDIATE",
                "automated_executable": True,
                "description": f"Sever network egress on {host} to arrest active C2 exfiltration.",
            })
        if domains:
            actions.append({
                "action": "BLOCK_DOMAIN_EGRESS",
                "target": domains,
                "urgency": "HIGH",
                "automated_executable": False,
                "description": f"Add {', '.join(domains)} to enterprise DNS sinkhole.",
            })
        if users:
            actions.append({
                "action": "REVOKE_SESSION_CREDENTIALS",
                "target": users,
                "urgency": "MEDIUM",
                "automated_executable": False,
                "description": f"Invalidate OAuth refresh tokens for user(s): {', '.join(users)}.",
            })

        return {
            "requires_human_approval": True,
            "containment_priority": "CRITICAL" if risk >= 80 else "HIGH" if risk >= 50 else "MONITOR",
            "recommended_actions": actions,
            "justification": (
                f"Multi-agent investigation identified risk score {risk}/100 on {host}. "
                f"Convergent attack vectors require immediate containment to stop lateral spread."
            ),
        }


class MultiAgentInvestigationPipeline:
    """Orchestrates Correlator, Triage, and Containment agents."""

    def __init__(self):
        self.correlator = CorrelatorAgent()
        self.triage = TriageAgent()
        self.containment = ContainmentAgent()

    def investigate(self, host: str, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        correlation = self.correlator.run(host, alerts)
        triage = self.triage.run(correlation)
        containment = self.containment.run(correlation, triage)

        return {
            "host": host,
            "correlation": correlation,
            "triage": triage,
            "containment": containment,
        }

