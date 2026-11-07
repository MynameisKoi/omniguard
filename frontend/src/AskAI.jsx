import { useState, useEffect, useRef, useMemo } from 'react'
import {
    Sparkles, Plus, Send, MessageSquare, Trash2, Pencil, Check, X, ArrowRight,
    ShieldAlert, ShieldCheck, ShieldOff, CircleAlert, Wrench, Maximize2, Link2, Lock, LockOpen,
} from 'lucide-react'
import { api } from './api'
import AiMarkdown from './AiMarkdown'
import GraphCanvas from './GraphCanvas'
import { EvidenceList } from './Evidence'
import { timeAgo, exactTime } from './time'
import { label, humanize, MITRE_NAMES } from './labels'
import { scopeIds } from './graphScope'

/* Ask AI (#1, #23, #19): the SOC agent. Saved conversations on the left; on
 * the right the agent answers by calling tools, and what they return is drawn
 * with the dashboard's own pieces (alert tables, the graph, screenshots...).
 * Anything that changes state waits on an approval card. */

const SUGGESTIONS = [
    "What should I look at first?",
    "Which hosts had both phishing and C2?",
    "Tell me about cdn-telemetry-sync.net",
    "What happened on LAPTOP-10?",
    "Show me the audit trail for LAPTOP-10",
    "Show me everything about phishing this week",
    "Show me the network graph around LAPTOP-10",
    "Compare BUILD-SRV-02 and DEV-BOX-11",
    "What is a C2 beacon?",
]

// a step as a sentence: "Looking up LAPTOP-10"
const STEP_WORDS = {
    search_alerts: "Searching alerts", get_alert: "Opening alert", entity_summary: "Looking up",
    get_host_graph: "Mapping the graph around", get_evidence: "Fetching the agent's screenshots",
    attention_findings: "Checking what needs attention", system_status: "Checking the systems",
    ledger_lookup: "Reading the audit ledger", investigate_host: "Running a full investigation on",
    isolate_host: "Proposing to isolate", set_alert_status: "Proposing a status change",
    show_dashboard: "Building a dashboard of", show_graph: "Lighting up the graph around",
    show_screenshots: "Laying out the agent's screenshots", show_ledger: "Walking the audit chain for",
    compare_entities: "Comparing",
}
function stepText(step) {
    const a = step.args || {}
    const subject = a.names || a.name || a.hostname || a.host || a.entity || a.query || a.domain || a.severity || ""
    return `${STEP_WORDS[step.tool] || humanize(step.tool)}${subject ? ` ${subject}` : ""}`
}

function dayGroup(ts) {
    const d = new Date(ts), start = new Date(); start.setHours(0, 0, 0, 0)
    if (d >= start) return "Today"
    if (d >= start - 864e5) return "Yesterday"
    if (d >= start - 7 * 864e5) return "Previous 7 days"
    return "Earlier"
}

// ── what tools return, drawn with dashboard pieces ───────────────────────

function AlertsBlock({ data, onOpenAlert }) {
    const rows = data.alerts || []
    if (!rows.length) return <div className="ask-block ask-empty">No alerts matched.</div>
    return (
        <div className="ask-block">
            <table className="table ask-table">
                <tbody>
                    {rows.slice(0, 6).map(a => (
                        <tr key={a.alert_id} className="row-link" onClick={() => onOpenAlert(a.alert_id)}>
                            <td><span className={`sev ${a.severity}`}>{a.severity}</span></td>
                            <td className="td-mono">{a.event_type}</td>
                            <td className="td-mono td-dim">{a.host}</td>
                            <td className="td-mono td-faint td-clip">{a.domain || a.user || "—"}</td>
                            <td className="td-faint" title={exactTime(a.timestamp)}>{timeAgo(a.timestamp)}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
            {data.total > 6 && <div className="ask-more">{data.total - 6} more match</div>}
        </div>
    )
}

function EntityBlock({ data, onFilter }) {
    const sev = data.severity || {}
    const engines = data.host_engines || {}
    return (
        <div className="ask-block ask-entity">
            <div className="ask-entity-head">
                <div>
                    <span className="ask-eyebrow">{data.kind}</span>
                    <div className="ask-entity-name">{data.name}</div>
                </div>
                <button className="ask-link" onClick={() => onFilter(data.name)}>Open page <ArrowRight /></button>
            </div>
            <dl className="ask-facts">
                <div><dt>Alerts</dt><dd>{data.alert_count}</dd></div>
                <div><dt>Critical</dt><dd className={sev.critical ? "crit" : ""}>{sev.critical || 0}</dd></div>
                <div><dt>Hosts</dt><dd>{data.hosts?.length || 0}</dd></div>
                <div><dt>Last seen</dt><dd title={exactTime(data.last_seen)}>{data.last_seen ? timeAgo(data.last_seen) : "—"}</dd></div>
            </dl>
            {data.hosts?.length > 0 && data.kind !== "host" && (
                <div className="ask-hosts">
                    {data.hosts.slice(0, 8).map(h => (
                        <button key={h.host} className="ask-host" onClick={() => onFilter(h.host)} title={`Open ${h.host}`}>
                            <span className="mono">{h.host}</span>
                            {(engines[h.host] || []).map(e => <span key={e} className={`ask-eng eng-${e}`}>{e === "verifyeye" ? "phishing" : e === "spectrac2" ? "C2" : e}</span>)}
                        </button>
                    ))}
                </div>
            )}
            {data.kind === "host" && data.timeline?.length > 0 && (
                <ol className="ask-timeline">
                    {data.timeline.slice(-5).map((t, i) => (
                        <li key={i}><span className={`sev-dot ${t.severity}`} /><span className="mono">{t.event}</span>
                            {t.detail && <span className="td-faint"> · {t.detail}</span>}
                            <time title={exactTime(t.time)}>{timeAgo(t.time)}</time></li>
                    ))}
                </ol>
            )}
        </div>
    )
}

function FindingsBlock({ data, onFilter }) {
    return (
        <ul className="ask-block ask-findings">
            {(data.findings || []).map((f, i) => (
                <li key={i} className={f.tone}>
                    <span>{f.text}</span>
                    {f.entities?.length > 0 && (
                        <span className="ask-chips">
                            {f.entities.slice(0, 4).map(e => <button key={e} className="ask-chip" onClick={() => onFilter(e)}>{e}</button>)}
                        </span>
                    )}
                </li>
            ))}
        </ul>
    )
}

function LedgerBlock({ data }) {
    const rows = data.records || []
    if (!rows.length) return <div className="ask-block ask-empty">Nothing in the ledger yet.</div>
    return (
        <ul className="ask-block ask-ledger">
            {rows.slice(0, 6).map(r => (
                <li key={r.ledger_id || r.entry_hash}>
                    <b>{(r.action_taken || "").startsWith("NETWORK_ISOLATION") ? `Isolated ${r.entity_id}` : `${label(r.action_taken)} · ${r.entity_id}`}</b>
                    <span className="td-faint">{(r.analyst_user || "").startsWith("system") ? "AI" : r.analyst_user} · {r.timestamp ? timeAgo(r.timestamp) : ""}</span>
                </li>
            ))}
        </ul>
    )
}

function InvestigationBlock({ data }) {
    const inv = data.investigation || {}, t = inv.triage || {}, c = inv.containment || {}, cor = inv.correlation || {}
    const score = t.risk_score ?? 0
    return (
        <div className={`ask-block ask-invest ${score >= 70 ? "critical" : score >= 40 ? "high" : "good"}`}>
            <div className="ask-invest-head">
                <span className="ask-score">{score}<small>/100</small></span>
                <div>
                    <span className="ask-eyebrow">Verdict on {inv.host}</span>
                    <div className="ask-entity-name">{label(t.classification) || "No verdict"}</div>
                    <span className="td-faint">{cor.alert_count} alerts · {(cor.mitre_techniques || []).map(m => MITRE_NAMES[m] ? `${m} ${MITRE_NAMES[m]}` : m).join(", ")}</span>
                </div>
            </div>
            {(c.recommended_actions || []).length > 0 && (
                <ol className="ask-plan">
                    {c.recommended_actions.map((a, i) => (
                        <li key={i}><span className={`urg ${(a.urgency || "").toLowerCase()}`}>{humanize(a.urgency)}</span> {label(a.action)}</li>
                    ))}
                </ol>
            )}
        </div>
    )
}

function StatusBlock({ data }) {
    return (
        <div className="ask-block ask-status">
            {Object.entries(data.status || {}).map(([k, up]) => (
                <span key={k} className={up ? "up" : "down"}><i />{k === "neo4j" ? "Neo4j" : k === "mongo" ? "MongoDB" : "AI model"} {up ? "online" : "offline"}</span>
            ))}
        </div>
    )
}

/* ── whole dashboard views, drawn inside a reply ──────────────────────────
 * The agent's show_* tools say WHICH view and WHAT it's scoped to; the view
 * itself is the dashboard's real component (passed in from App as `views`),
 * so it's as interactive here as on its own tab. "Full screen" lifts the same
 * view into an overlay without leaving the chat. */

function ViewFrame({ title, note, onTab, tabLabel, children, full: renderFull, tall = false }) {
    const [full, setFull] = useState(false)
    const [open, setOpen] = useState(!tall)   // tall views start as a preview
    useEffect(() => {
        if (!full) return
        const esc = (e) => e.key === "Escape" && setFull(false)
        window.addEventListener("keydown", esc)
        return () => window.removeEventListener("keydown", esc)
    }, [full])
    const head = (inFull) => (
        <header className="ask-view-head">
            <div>
                <span className="ask-eyebrow">{note}</span>
                <b>{title}</b>
            </div>
            <span className="ask-view-tools">
                {onTab && <button className="ask-link" onClick={onTab}>{tabLabel} <ArrowRight /></button>}
                {inFull
                    ? <button className="btn" onClick={() => setFull(false)}><X /> Close</button>
                    : <button className="btn" onClick={() => setFull(true)}><Maximize2 /> Full screen</button>}
            </span>
        </header>
    )
    return (
        <>
            <div className="ask-block ask-view">
                {head(false)}
                <div className={`ask-view-body${open ? "" : " clipped"}`}>{children}</div>
                {tall && (
                    <button className="ask-view-more" onClick={() => setOpen(!open)}>
                        {open ? "Show less" : "Show everything — charts, hosts, graph and every alert"}
                    </button>
                )}
            </div>
            {full && (
                <div className="ask-full" role="dialog" aria-modal="true" aria-label={title}>
                    {head(true)}
                    <div className="ask-full-body">{renderFull ? renderFull() : children}</div>
                </div>
            )}
        </>
    )
}

// the alerts a view is about, from the live list the page already holds
function useSubset(views, ids) {
    return useMemo(() => {
        const want = new Set(ids || [])
        return (views?.alerts || []).filter(a => want.has(a.alert_id))
    }, [views?.alerts, ids])
}

function DashboardView({ data, views, onFilter }) {
    const subset = useSubset(views, data.alert_ids)
    if (!data.alert_ids?.length) return <div className="ask-block ask-empty">No alerts match {data.label}.</div>
    if (!subset.length) return <div className="ask-block ask-empty">Loading {data.label}…</div>
    const gone = data.alert_ids.length - subset.length
    return (
        <ViewFrame
            title={data.label} note={`Dashboard · ${subset.length} alert${subset.length === 1 ? "" : "s"}${gone > 0 ? ` (${gone} since removed)` : ""}`}
            onTab={data.term && data.term !== data.label ? () => onFilter(data.term) : () => views.openGraph(subset, data.label)}
            tabLabel={data.term && data.term !== data.label ? "Open in Search" : "Open in graph"}
            tall
        >
            <div className="ask-dash">{views.dashboard(subset, data.term || data.label)}</div>
        </ViewFrame>
    )
}

function GraphView({ data, views }) {
    const subset = useSubset(views, data.alert_ids)
    // one stable focus per block, so the explorer lights it up once
    const focus = useMemo(() => ({ label: data.entity, ids: [...scopeIds(subset)] }), [data.entity, subset])
    const [cleared, setCleared] = useState(false)
    if (!subset.length) return <div className="ask-block ask-empty">Loading the graph around {data.entity}…</div>
    return (
        <ViewFrame title={data.entity} note="Network graph · everything linked to it lit up"
            onTab={() => views.openGraph(subset, data.entity)} tabLabel="Open the graph tab">
            <div className="ask-graphx">{views.graph(cleared ? null : focus, () => setCleared(true))}</div>
        </ViewFrame>
    )
}

function ScreenshotsView({ data }) {
    const items = data.evidence || []
    if (!items.length) return <div className="ask-block ask-empty">The agent hasn't screenshotted anything matching that yet.</div>
    const phish = items.filter(e => e.phishing).length
    return (
        <ViewFrame title={`${items.length} page${items.length === 1 ? "" : "s"} the agent visited`}
            note={`Screenshots · ${phish} phishing`} full={() => <EvidenceList items={items} limit={items.length} />}>
            <EvidenceList items={items} limit={8} />
        </ViewFrame>
    )
}

function LedgerChain({ data, views }) {
    const rows = data.records || [], chain = data.chain || {}
    const body = (n) => (
        <>
            <div className={`ask-chain-status ${chain.valid ? "ok" : "bad"}`}>
                {chain.valid ? <Lock /> : <LockOpen />}
                {chain.valid
                    ? <>All {chain.checked} blocks verify — every hash links to the one before it, nothing was altered.</>
                    : <>Chain broken at entry <span className="mono">{chain.failing}</span> — a record was changed or removed.</>}
            </div>
            {!rows.length ? <div className="ask-empty">No entries{data.entity ? ` for ${data.entity}` : ""} yet.</div> : (
                <ol className="ask-chain">
                    {rows.slice(0, n).map((r, i) => (
                        // joined to the entry above only if that one's prev_hash IS this hash;
                        // filtered to one host, other entries sit in between
                        <li key={r.ledger_id || r.entry_hash}
                            className={[chain.failing === r.ledger_id && "bad", i > 0 && rows[i - 1].prev_hash !== r.entry_hash && "gap"].filter(Boolean).join(" ")}
                            title={i > 0 && rows[i - 1].prev_hash !== r.entry_hash ? "Other ledger entries sit between these two" : undefined}>
                            <div className="ask-chain-top">
                                <b>{(r.action_taken || "").startsWith("NETWORK_ISOLATION") ? `Isolated ${r.entity_id}` : `${label(r.action_taken)} · ${r.entity_id}`}</b>
                                <time title={exactTime(r.timestamp)}>{r.timestamp ? timeAgo(r.timestamp) : ""}</time>
                            </div>
                            <span className="td-faint">{label(r.stage)} · {(r.analyst_user || "").startsWith("system") ? "AI" : r.analyst_user}</span>
                            {r.reasoning_output && <p>{r.reasoning_output}</p>}
                            <span className="ask-hash mono" title={`hash ${r.entry_hash}\nprevious ${r.prev_hash}`}>
                                <Link2 /> {String(r.entry_hash || "").slice(0, 12)} ← {String(r.prev_hash || "").slice(0, 12)}
                            </span>
                        </li>
                    ))}
                </ol>
            )}
        </>
    )
    return (
        <ViewFrame title={data.entity ? `Audit trail for ${data.entity}` : "Recent audit trail"}
            note={`Ledger · ${rows.length} entr${rows.length === 1 ? "y" : "ies"}`}
            onTab={views?.openLedger} tabLabel="Open the ledger" full={() => body(rows.length)}>
            {body(5)}
        </ViewFrame>
    )
}

function CompareView({ data, onFilter }) {
    const items = data.entities || []
    return (
        <ViewFrame title={items.map(e => e.name).join(" vs ")} note={`Comparison · ${items.length} side by side`}>
            <div className="ask-compare" style={{ "--cols": items.length }}>
                {items.map(e => <EntityBlock key={e.name} data={e} onFilter={onFilter} />)}
            </div>
        </ViewFrame>
    )
}

function Block({ block, onOpenAlert, onFilter, views }) {
    const d = block.data || {}
    switch (block.render) {
        case "alerts": return <AlertsBlock data={d} onOpenAlert={onOpenAlert} />
        case "alert": return <AlertsBlock data={{ alerts: [d.alert], total: 1 }} onOpenAlert={onOpenAlert} />
        case "entity": return <EntityBlock data={d} onFilter={onFilter} />
        case "graph": return (
            <div className="ask-block ask-graph">
                <GraphCanvas compact host={d.host} />
                <button className="ask-link" onClick={() => onFilter(d.host)}>Open {d.host} <ArrowRight /></button>
            </div>
        )
        case "evidence": return d.evidence?.length ? <div className="ask-block"><EvidenceList items={d.evidence} /></div>
            : <div className="ask-block ask-empty">The agent has no screenshot of that page yet.</div>
        case "findings": return <FindingsBlock data={d} onFilter={onFilter} />
        case "ledger": return <LedgerBlock data={d} />
        case "investigation": return <InvestigationBlock data={d} />
        case "status": return <StatusBlock data={d} />
        case "dashboard": return views ? <DashboardView data={d} views={views} onFilter={onFilter} /> : null
        case "graph_explorer": return views ? <GraphView data={d} views={views} /> : null
        case "screenshots": return <ScreenshotsView data={d} />
        case "ledger_view": return <LedgerChain data={d} views={views} />
        case "compare": return <CompareView data={d} onFilter={onFilter} />
        default: return null
    }
}

// an action the agent wants to take: nothing happens until the analyst clicks
function ApprovalCard({ approval, onDecide }) {
    const [busy, setBusy] = useState(null)
    const a = approval.args || {}
    const what = approval.tool === "isolate_host" ? `Isolate ${a.hostname} from the network`
        : approval.tool === "set_alert_status" ? `Mark alert ${String(a.alert_id).slice(0, 8)}… as ${a.status}`
        : humanize(approval.tool)
    const decide = async (approve) => {
        setBusy(approve ? "approve" : "reject")
        await onDecide(approval, approve)
        setBusy(null)
    }
    return (
        <div className={`ask-approval ${approval.status}`}>
            <div className="ask-approval-head">
                {approval.status === "approved" ? <ShieldCheck /> : approval.status === "rejected" ? <X /> : <ShieldOff />}
                <div>
                    <span className="ask-eyebrow">{approval.status === "pending" ? "Needs your approval" : humanize(approval.status)}</span>
                    <b>{what}</b>
                    {a.reason && <span className="td-faint">Reason: {a.reason}</span>}
                </div>
            </div>
            {approval.status === "pending" ? (
                <div className="ask-approval-actions">
                    <button className="btn danger" disabled={!!busy} onClick={() => decide(true)}>
                        {busy === "approve" ? <><span className="btn-spinner" /> Running…</> : "Approve"}
                    </button>
                    <button className="btn" disabled={!!busy} onClick={() => decide(false)}>Reject</button>
                </div>
            ) : approval.result ? <p className="ask-approval-result">{approval.result}</p> : null}
        </div>
    )
}

function Steps({ steps, live }) {
    const [open, setOpen] = useState(false)
    const running = steps.some(s => s.status === "running")
    const shown = live || open || running ? steps : []
    return (
        <div className="ask-steps">
            {!live && !running && (
                <button className="ask-steps-toggle" onClick={() => setOpen(!open)}>
                    <Wrench /> Used {steps.length} tool{steps.length === 1 ? "" : "s"} {open ? "▴" : "▾"}
                </button>
            )}
            {shown.map((s, i) => (
                <div key={i} className={`ask-step ${s.status === "running" ? "running" : s.ok ? "ok" : "err"}`}>
                    {s.status === "running" ? <span className="btn-spinner" /> : s.ok ? <Check /> : <CircleAlert />}
                    <span>{stepText(s)}</span>
                    {s.status !== "running" && s.summary && !s.ok && <em>{s.summary}</em>}
                </div>
            ))}
        </div>
    )
}

const WIDE = new Set(["dashboard", "graph_explorer", "screenshots", "compare"])

function Message({ m, live, onOpenAlert, onFilter, onDecide, views }) {
    if (m.role === "user") return <div className="ask-msg user"><div className="ask-bubble">{m.content}</div></div>
    const thinking = live && !m.content && !(m.steps || []).length
    return (
        <div className={`ask-msg ai${(m.blocks || []).some(b => WIDE.has(b.render)) ? " wide" : ""}`}>
            <span className="ask-avatar"><Sparkles /></span>
            <div className="ask-body">
                {(m.steps || []).length > 0 && <Steps steps={m.steps} live={live} />}
                {(m.blocks || []).map((b, i) => <Block key={i} block={b} onOpenAlert={onOpenAlert} onFilter={onFilter} views={views} />)}
                {(m.approvals || []).map(a => <ApprovalCard key={a.approval_id} approval={a} onDecide={(ap, ok) => onDecide(m, ap, ok)} />)}
                {thinking ? <div className="ai-loading"><span className="ai-dot" /><span className="ai-dot" /><span className="ai-dot" />Thinking…</div>
                    : m.content ? <AiMarkdown text={m.content} /> : null}
            </div>
        </div>
    )
}

export default function AskAI({ onOpenAlert, onFilter, views }) {
    const [convos, setConvos] = useState([])
    const [activeId, setActiveId] = useState(() => { try { return localStorage.getItem("og_ask_convo") } catch { return null } })
    const [messages, setMessages] = useState([])
    const [loadedId, setLoadedId] = useState(null)      // whose messages are in `messages`
    const justCreated = useRef(null)                     // a chat send() just made: nothing to load
    const [streaming, setStreaming] = useState(false)
    const [draft, setDraft] = useState("")
    const [renaming, setRenaming] = useState(null)   // { id, title }
    const [confirmDelete, setConfirmDelete] = useState(null)
    const [error, setError] = useState(null)
    const logRef = useRef(null)
    const inputRef = useRef(null)

    const loadList = () => api("/conversations").then(r => r.ok ? r.json() : []).then(setConvos).catch(() => {})
    useEffect(() => { loadList() }, [])

    useEffect(() => {
        try { activeId ? localStorage.setItem("og_ask_convo", activeId) : localStorage.removeItem("og_ask_convo") } catch { /* private mode */ }
        // a brand-new chat from send(): its first message is already on screen
        if (!activeId || justCreated.current === activeId) return
        let alive = true
        api(`/conversations/${activeId}`)
            .then(r => r.ok ? r.json() : null)
            .then(c => {
                if (!alive) return
                if (c) { setMessages(c.messages || []); setLoadedId(activeId) }
                else setActiveId(null)   // deleted elsewhere
            })
        return () => { alive = false }
    }, [activeId])
    const loadingChat = !!activeId && loadedId !== activeId

    const openChat = (id) => {
        setError(null)
        if (!id) { setMessages([]); setLoadedId(null) }
        setActiveId(id)
    }

    // keep the newest message in view while the agent works
    useEffect(() => {
        const el = logRef.current
        if (el) el.scrollTop = el.scrollHeight
    }, [messages])

    // grow the composer with its text
    useEffect(() => {
        const el = inputRef.current
        if (!el) return
        el.style.height = "auto"
        el.style.height = `${Math.min(el.scrollHeight, 160)}px`
    }, [draft])

    const patchLast = (fn) => setMessages(ms => ms.map((m, i) => i === ms.length - 1 ? fn(m) : m))

    async function send(text) {
        text = text.trim()
        if (!text || streaming) return
        setDraft(""); setError(null); setStreaming(true)
        let id = activeId
        try {
            if (!id) {
                const r = await api("/conversations", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })
                id = (await r.json()).conversation_id
                justCreated.current = id
                setMessages([]); setLoadedId(id); setActiveId(id)
            }
            setMessages(ms => [...ms, { role: "user", content: text },
                { role: "assistant", content: "", steps: [], blocks: [], approvals: [], live: true }])

            const res = await api(`/conversations/${id}/messages`, {
                method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: text }),
            })
            if (!res.ok || !res.body) throw new Error(`the server answered ${res.status}`)
            const reader = res.body.getReader(), decoder = new TextDecoder()
            let buffer = ""
            for (;;) {
                const { value, done } = await reader.read()
                if (done) break
                buffer += decoder.decode(value, { stream: true })
                const lines = buffer.split("\n")
                buffer = lines.pop()
                for (const line of lines) {
                    if (!line.trim()) continue
                    const e = JSON.parse(line)
                    if (e.type === "step" && e.status === "running") patchLast(m => ({ ...m, steps: [...m.steps, e] }))
                    else if (e.type === "step") patchLast(m => {
                        const steps = [...m.steps]
                        const i = steps.map(s => s.status).lastIndexOf("running")
                        steps[i >= 0 ? i : steps.length] = e
                        return { ...m, steps }
                    })
                    else if (e.type === "block") patchLast(m => ({ ...m, blocks: [...m.blocks, e] }))
                    else if (e.type === "approval") patchLast(m => ({ ...m, approvals: [...m.approvals, e] }))
                    else if (e.type === "token") patchLast(m => ({ ...m, content: m.content + e.text }))
                    else if (e.type === "done") patchLast(m => ({ ...m, content: e.content ?? m.content, message_id: e.message_id, live: false }))
                    else if (e.type === "error") throw new Error(e.message)
                }
            }
        } catch (err) {
            setError(`Something went wrong: ${err.message}`)
            patchLast(m => m.role === "assistant" ? { ...m, live: false } : m)
        } finally {
            setStreaming(false)
            loadList()
        }
    }

    async function decide(message, approval, approve) {
        const r = await api(`/conversations/${activeId}/approvals/${approval.approval_id}`, {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ approve }),
        })
        const updated = r.ok ? await r.json() : { ...approval, status: "failed", result: `Couldn't ${approve ? "approve" : "reject"} (${r.status})` }
        setMessages(ms => ms.map(m => m !== message ? m : {
            ...m, approvals: m.approvals.map(a => a.approval_id === approval.approval_id ? updated : a),
        }))
    }

    async function rename(id, title) {
        setRenaming(null)
        if (!title.trim()) return
        await api(`/conversations/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title }) })
        loadList()
    }

    async function remove(id) {
        setConfirmDelete(null)
        await api(`/conversations/${id}`, { method: "DELETE" })
        if (id === activeId) openChat(null)
        loadList()
    }

    const groups = []
    convos.forEach(c => {
        const g = dayGroup(c.updated_at)
        if (!groups.length || groups[groups.length - 1].label !== g) groups.push({ label: g, items: [] })
        groups[groups.length - 1].items.push(c)
    })

    return (
        <div className="ask">
            <aside className="ask-side">
                <button className="ask-new" onClick={() => { openChat(null); inputRef.current?.focus() }}>
                    <Plus /> New chat
                </button>
                <div className="ask-list">
                    {convos.length === 0 && <p className="ask-side-empty">Your chats will appear here.</p>}
                    {groups.map(g => (
                        <div key={g.label}>
                            <div className="ask-group">{g.label}</div>
                            {g.items.map(c => (
                                <div key={c.conversation_id} className={`ask-item ${c.conversation_id === activeId ? "on" : ""}`}>
                                    {renaming?.id === c.conversation_id ? (
                                        <input className="ask-rename" autoFocus defaultValue={c.title}
                                            onKeyDown={e => { if (e.key === "Enter") rename(c.conversation_id, e.target.value); if (e.key === "Escape") setRenaming(null) }}
                                            onBlur={e => rename(c.conversation_id, e.target.value)} />
                                    ) : confirmDelete === c.conversation_id ? (
                                        <div className="ask-confirm">
                                            <span>Delete this chat?</span>
                                            <button onClick={() => remove(c.conversation_id)} className="danger">Delete</button>
                                            <button onClick={() => setConfirmDelete(null)}>Keep</button>
                                        </div>
                                    ) : (
                                        <>
                                            <button className="ask-item-main" onClick={() => openChat(c.conversation_id)} title={c.title}>
                                                <MessageSquare /><span>{c.title}</span>
                                            </button>
                                            <span className="ask-item-tools">
                                                <button onClick={() => setRenaming({ id: c.conversation_id })} aria-label="Rename"><Pencil /></button>
                                                <button onClick={() => setConfirmDelete(c.conversation_id)} aria-label="Delete"><Trash2 /></button>
                                            </span>
                                        </>
                                    )}
                                </div>
                            ))}
                        </div>
                    ))}
                </div>
                <p className="ask-side-note"><ShieldAlert /> Runs on your machine. Actions always ask you first.</p>
            </aside>

            <section className="ask-main">
                <div className="ask-log" ref={logRef}>
                    {loadingChat ? <div className="content-spinner"><div className="spinner" /></div>
                        : messages.length === 0 ? (
                            <div className="ask-welcome">
                                <span className="ask-welcome-mark"><Sparkles /></span>
                                <h2>What can I help you investigate?</h2>
                                <p>I can search alerts, look up hosts and domains, map the attack graph, pull the agent's screenshots,
                                    read the audit ledger and run investigations. Anything that changes something waits for your approval.</p>
                                <div className="ask-suggest">
                                    {SUGGESTIONS.map(q => <button key={q} onClick={() => send(q)}>{q}</button>)}
                                </div>
                            </div>
                        ) : messages.map((m, i) => (
                            <Message key={m.message_id || i} m={m} live={!!m.live}
                                onOpenAlert={onOpenAlert} onFilter={onFilter} onDecide={decide} views={views} />
                        ))}
                    {error && <div className="login-error ask-error">{error}</div>}
                </div>

                <form className="ask-composer" onSubmit={e => { e.preventDefault(); send(draft) }}>
                    <textarea
                        ref={inputRef}
                        rows={1}
                        value={draft}
                        placeholder={streaming ? "Working on it…" : "Ask about your alerts, hosts, domains — or ask me to act"}
                        onChange={e => setDraft(e.target.value)}
                        onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(draft) } }}
                        disabled={streaming}
                    />
                    <button type="submit" className="ask-send" disabled={streaming || !draft.trim()} aria-label="Send">
                        {streaming ? <span className="btn-spinner" /> : <Send />}
                    </button>
                </form>
            </section>
        </div>
    )
}
