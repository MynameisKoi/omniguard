// Triage an alert on its page: by hand ("Triage"), or let the AI do it
// ("Triage with AI"). The AI's triage is only a proposal: the analyst reviews
// it in the same form, can change anything, and approves or rejects it.
// Nothing about the alert changes until a person saves or approves.
import { useState } from "react"
import { Sparkles, ClipboardCheck, Check, X, Bot, UserCheck } from "lucide-react"
import { api } from "./api"
import { timeAgo, exactTime } from "./time"

const VERDICTS = [
    { id: "true_positive", label: "True positive", tone: "bad" },
    { id: "false_positive", label: "False positive", tone: "good" },
    { id: "benign", label: "Benign / expected", tone: "good" },
    { id: "escalate", label: "Needs escalation", tone: "warn" },
]
const SEVERITIES = ["critical", "high", "medium", "low"]
const LOCAL = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/
const verdictOf = (id) => VERDICTS.find(v => v.id === id) || { id, label: id, tone: "warn" }

// the response actions that fit this alert (the backend checks the same)
function actionsFor(a) {
    const out = []
    if (a.host) out.push({ id: "isolate_host", label: `Isolate ${a.host}` })
    if (a.user) out.push({ id: "reset_password", label: `Reset the password for ${a.user}` })
    const target = a.domain || (a.source === "spectrac2" ? a.dst_ip : null)
    if (target && !LOCAL.test(target)) out.push({ id: "block_domain", label: `Block ${target}` })
    return out
}

function TriageForm({ alert, initial, ai, busy, onSubmit, onReject, onCancel }) {
    const [verdict, setVerdict] = useState(initial.verdict || "")
    const [severity, setSeverity] = useState(initial.severity || alert.severity)
    const [status, setStatus] = useState(initial.status || "triaged")
    const [notes, setNotes] = useState(initial.notes || "")
    const [actions, setActions] = useState(initial.actions || [])
    const options = actionsFor(alert)
    const toggle = (id) => setActions(xs => xs.includes(id) ? xs.filter(x => x !== id) : [...xs, id])
    const changed = ai && (verdict !== initial.verdict || severity !== initial.severity || status !== initial.status
        || notes !== initial.notes || [...actions].sort().join() !== [...(initial.actions || [])].sort().join())

    return (
        <form className="triage-form" onSubmit={e => { e.preventDefault(); onSubmit({ verdict, severity, status, notes, actions }) }}>
            <div className="triage-field">
                <span className="triage-label">Verdict</span>
                <div className="triage-chips" role="radiogroup" aria-label="Verdict">
                    {VERDICTS.map(v => (
                        <button type="button" key={v.id} role="radio" aria-checked={verdict === v.id}
                            className={`triage-chip ${v.tone} ${verdict === v.id ? "on" : ""}`} onClick={() => setVerdict(v.id)}>
                            {v.label}
                        </button>
                    ))}
                </div>
            </div>

            <div className="triage-row">
                <label className="triage-field">
                    <span className="triage-label">Severity</span>
                    <select value={severity} onChange={e => setSeverity(e.target.value)}>
                        {SEVERITIES.map(s => <option key={s} value={s}>{s}{s === alert.severity ? " (current)" : ""}</option>)}
                    </select>
                </label>
                <label className="triage-field">
                    <span className="triage-label">Mark as</span>
                    <select value={status} onChange={e => setStatus(e.target.value)}>
                        <option value="triaged">Triaged (still being worked)</option>
                        <option value="resolved">Resolved (done)</option>
                    </select>
                </label>
            </div>

            {options.length > 0 && (
                <div className="triage-field">
                    <span className="triage-label">Response actions <em>simulated, recorded in the ledger</em></span>
                    {options.map(o => (
                        <label key={o.id} className="triage-check">
                            <input type="checkbox" checked={actions.includes(o.id)} onChange={() => toggle(o.id)} />
                            {o.label}
                        </label>
                    ))}
                </div>
            )}

            <label className="triage-field">
                <span className="triage-label">Notes</span>
                <textarea rows={ai ? 6 : 3} value={notes} onChange={e => setNotes(e.target.value)}
                    placeholder="Why this verdict? What did you check?" />
            </label>

            <div className="triage-buttons">
                <button type="submit" className="btn primary" disabled={!verdict || busy}>
                    {busy ? <span className="btn-spinner" /> : <Check />}
                    {ai ? (changed ? "Approve with my changes" : "Approve") : "Save triage"}
                </button>
                {ai
                    ? <button type="button" className="btn" disabled={busy} onClick={onReject}><X /> Reject</button>
                    : <button type="button" className="btn" disabled={busy} onClick={onCancel}>Cancel</button>}
            </div>
        </form>
    )
}

export default function TriagePanel({ alert, onUpdated }) {
    const [mode, setMode] = useState(null)        // null | "manual"
    const [busy, setBusy] = useState(null)        // "ai" | "save"
    const [error, setError] = useState(null)
    const proposal = alert.triage_proposal
    const done = alert.triage

    async function call(path, body, kind) {
        setBusy(kind); setError(null)
        try {
            const r = await api(`/alerts/${alert.alert_id}${path}`, {
                method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}),
            })
            const out = await r.json().catch(() => ({}))
            if (!r.ok) throw new Error(out.detail || `the server answered ${r.status}`)
            onUpdated?.(out)
            setMode(null)
        } catch (e) {
            setError(`Couldn't ${kind === "ai" ? "get the AI's triage" : "save"}: ${e.message}`)
        } finally {
            setBusy(null)
        }
    }

    const state = proposal ? "proposal" : mode === "manual" ? "editing" : busy === "ai" ? "working" : done ? "done" : "open"
    const tone = state === "done" ? verdictOf(done.verdict).tone : state === "open" ? "open" : "ai"
    const Icon = state === "proposal" ? Bot : state === "working" ? Sparkles : state === "done" ? Check : ClipboardCheck

    return (
        <section className={`triage-card ${tone}`} aria-label="Triage">
            <div className="triage-bar">
                <span className="triage-icon"><Icon /></span>
                <div className="triage-headline">
                    {state === "open" && <><b>Not triaged yet</b>
                        <span>Decide yourself, or let the AI propose a verdict for you to review.</span></>}
                    {state === "working" && <><b>AI is triaging…</b>
                        <span className="ai-loading"><span className="ai-dot" /><span className="ai-dot" /><span className="ai-dot" />
                            Checking the host, user, domain and related alerts</span></>}
                    {state === "proposal" && <><b>AI proposal: {verdictOf(proposal.verdict).label}</b>
                        <span>Review it below. Nothing is applied until you approve.</span></>}
                    {state === "editing" && <><b>Triage this alert</b>
                        <span>Pick a verdict and what to do about it.</span></>}
                    {state === "done" && <><b>{verdictOf(done.verdict).label} <em>· {done.status}, {done.severity}</em></b>
                        <span title={exactTime(done.at)}>
                            {done.via === "ai" ? <><Bot /> AI proposed, approved by {done.by}</> : <><UserCheck /> {done.by}</>}
                            {" · "}{timeAgo(done.at)}
                            {done.via === "ai" && done.proposed_verdict && done.proposed_verdict !== done.verdict &&
                                ` · changed from "${verdictOf(done.proposed_verdict).label}"`}
                        </span></>}
                </div>
                {(state === "open" || state === "done") && (
                    <div className="triage-start">
                        <button className="btn sm" onClick={() => setMode("manual")}>
                            <ClipboardCheck /> {done ? "Triage again" : "Triage"}
                        </button>
                        {state === "open" && (
                            <button className="btn sm primary" onClick={() => call("/triage/ai", null, "ai")}>
                                <Sparkles /> Triage with AI
                            </button>
                        )}
                    </div>
                )}
            </div>

            {error && <div className="triage-body"><div className="login-error">{error}</div></div>}

            {state === "proposal" && (
                <div className="triage-body">
                    {proposal.summary && <p className="triage-summary">{proposal.summary}</p>}
                    <ul className="triage-reasons">{proposal.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
                    <TriageForm key={proposal.proposed_at} alert={alert} initial={proposal} ai busy={busy === "save"}
                        onSubmit={edits => call("/triage/ai/approve", edits, "save")}
                        onReject={() => call("/triage/ai/reject", {}, "save")} />
                </div>
            )}

            {state === "editing" && (
                <div className="triage-body">
                    <TriageForm alert={alert} initial={done ? { ...done, actions: [] } : {}} busy={busy === "save"}
                        onSubmit={body => call("/triage", body, "save")} onCancel={() => setMode(null)} />
                </div>
            )}

            {state === "done" && (done.actions?.length > 0 || done.notes || done.ai_summary) && (
                <div className="triage-body">
                    {done.actions?.length > 0 && (
                        <ul className="triage-actions">{done.actions.map(a => <li key={a.id}><Check /> {a.label} <em>simulated</em></li>)}</ul>
                    )}
                    {done.ai_summary && <p className="triage-summary">{done.ai_summary}</p>}
                    {done.notes && <p className="triage-notes">{done.notes}</p>}
                </div>
            )}
        </section>
    )
}
