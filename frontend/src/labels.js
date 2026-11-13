// human wording for the codes the backend sends (ledger stages, triage
// classifications, containment actions...). Anything not listed still reads
// fine: NETWORK_ISOLATION -> "Network isolation".

export function humanize(code) {
    if (!code) return ""
    const s = String(code).toLowerCase().replace(/_/g, " ")
    return s.charAt(0).toUpperCase() + s.slice(1)
        .replace(/\bai\b/g, "AI").replace(/\bedr\b/g, "EDR").replace(/\bc2\b/g, "C2")
}

const MAP = {
    // triage verdicts (agents.py)
    TRUE_POSITIVE_ACTIVE_COMPROMISE: "Active compromise",
    SUSPICIOUS_THREAT_ACTIVITY: "Suspicious activity",
    LOW_CONFIDENCE_ANOMALY: "Low-confidence anomaly",
    BENIGN_OR_NO_DATA: "Benign / not enough data",
    // correlation
    MULTI_HOST_CAMPAIGN: "Multi-host campaign",
    ISOLATED_HOST: "Single host",
    // containment actions
    NETWORK_ISOLATION: "Isolate the host from the network",
    BLOCK_DOMAIN_EGRESS: "Block the malicious domains",
    REVOKE_SESSION_CREDENTIALS: "Revoke the user's sessions",
    // ledger actions
    ANSWER_QUERY: "Answered an analyst's question",
}

export const label = (code) => MAP[code] ?? humanize(code)

// MITRE ATT&CK technique names for the ids our engines emit
export const MITRE_NAMES = {
    T1566: "Phishing",
    T1071: "Application layer protocol",
    T1078: "Valid accounts",
    T1021: "Remote services",
    T1056: "Input capture",
}

// triage verdicts (triage.py), short and long, and their tone
export const VERDICT_SHORT = { true_positive: "True positive", false_positive: "False positive", benign: "Benign", escalate: "Escalate" }
export const VERDICT_LABEL = { true_positive: "True positive", false_positive: "False positive", benign: "Benign / expected", escalate: "Needs escalation" }
export const VERDICT_TONE = { true_positive: "bad", false_positive: "good", benign: "good", escalate: "warn" }

// triage response actions (triage.py), short wording for the notification bell / toasts
export const ACTION_LABEL = { isolate_host: "isolate", reset_password: "reset password", block_domain: "block domain" }
