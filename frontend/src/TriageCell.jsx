// Where an alert is in triage, as a small cell for any alert list:
// Untriaged / AI proposal / Triaged or Resolved with the verdict (· AI when the
// AI proposed it and an analyst approved).
import { Bot, Check } from "lucide-react"
import { VERDICT_SHORT } from "./labels"

export default function TriageCell({ a, compact = false }) {
    if (!a) return null
    if (a.triage_proposal) return (
        <span className="triage-pill proposal" title="The AI proposed a triage: open the alert to approve or reject it">
            <Bot /> {compact ? "AI" : "AI proposal"}
        </span>
    )
    if (a.status === "new" || !a.status) return <span className="triage-pill new"><span className="dot" />{compact ? "New" : "Untriaged"}</span>
    const v = a.triage?.verdict
    if (compact) return (
        <span className={`triage-pill ${a.status} verdict-${v}`} title={`${a.status}${v ? `: ${VERDICT_SHORT[v]}` : ""}`}>
            <Check />{v ? VERDICT_SHORT[v] : a.status}
        </span>
    )
    return (
        <span className="cell-main">
            <span className={`triage-pill ${a.status}`}><Check />{a.status === "resolved" ? "Resolved" : "Triaged"}</span>
            {v && <span className={`cell-sub verdict-${v}`}>{VERDICT_SHORT[v] || v}{a.triage?.via === "ai" ? " · AI" : ""}</span>}
        </span>
    )
}
