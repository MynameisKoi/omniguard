import { useState, useEffect } from 'react'
import { Camera, ShieldCheck, ShieldAlert, ShieldQuestion, X, ExternalLink, Fingerprint } from 'lucide-react'
import { api } from "./api"
import { timeAgo, exactTime } from './time'

/* Agent evidence (#3): the screenshots VerifyEye's sandboxed agent took of the
 * pages it checked, with its verdict. Used on the alert detail (EvidencePanel),
 * and entity drill-downs (EvidenceGallery). */

// an <img> can't send the session header, so screenshots are fetched with it
// and shown from a local blob URL (released again when the image goes away)
function useAuthedImage(path) {
    const [src, setSrc] = useState(null)
    useEffect(() => {
        let alive = true, url
        api(path)
            .then(r => r.ok ? r.blob() : null)
            .then(b => { if (alive && b) { url = URL.createObjectURL(b); setSrc(url) } })
            .catch(() => {})
        return () => { alive = false; if (url) URL.revokeObjectURL(url) }
    }, [path])
    return src
}
const host = (url) => { try { return new URL(url).hostname } catch { return url } }
// the API sends UTC without a zone marker; say so, or browsers read it as local time
const utc = (ts) => /(Z|[+-]\d\d:\d\d)$/.test(ts || "") ? ts : `${ts}Z`

function verdictOf(e) {
    if (e.phishing) return { key: "phishing", label: `Phishing · ${Math.round(e.confidence * 100)}%`, icon: ShieldAlert }
    if (e.blocked) return { key: "blocked", label: "Couldn't see — bot check", icon: ShieldQuestion }
    return { key: "cleared", label: "Cleared", icon: ShieldCheck }
}

export function VerdictBadge({ evidence }) {
    const v = verdictOf(evidence)
    return <span className={`ev-verdict ${v.key}`}><v.icon />{v.label}</span>
}

// a screenshot that fades in once loaded, instead of popping in half-drawn
function Shot({ evidence, onOpen, size = "" }) {
    const [loaded, setLoaded] = useState(false)
    const src = useAuthedImage(evidence.image_url)
    return (
        <button className={`ev-shot ${size} ${loaded ? "loaded" : ""}`} onClick={() => onOpen(evidence)} title="View full size">
            {src && <img src={src} alt={`What the agent saw at ${host(evidence.url)}`} onLoad={() => setLoaded(true)} />}
        </button>
    )
}

// full-size view, with the details and a fresh check of the image's fingerprint
export function EvidenceViewer({ evidence, onClose }) {
    const [check, setCheck] = useState(null)   // null = checking, else { integrity_ok }
    const src = useAuthedImage(evidence.image_url)
    useEffect(() => {
        const onKey = (ev) => { if (ev.key === "Escape") onClose() }
        window.addEventListener("keydown", onKey)
        api(`/evidence/${evidence.evidence_id}`)
            .then(r => r.json()).then(setCheck).catch(() => setCheck({ integrity_ok: null }))
        return () => window.removeEventListener("keydown", onKey)
    }, [evidence.evidence_id, onClose])

    const offDomain = evidence.off_domain
    return (
        <div className="modal-backdrop" onClick={onClose}>
            <div className="modal ev-viewer" role="dialog" aria-modal="true" aria-label="Agent evidence" onClick={e => e.stopPropagation()}>
                <header className="ev-viewer-head">
                    <div>
                        <span className="ev-eyebrow"><Camera /> What the agent saw</span>
                        <h3>{host(evidence.url)}</h3>
                    </div>
                    <button className="icon-btn" onClick={onClose} aria-label="Close"><X /></button>
                </header>

                {src ? <img className="ev-viewer-img" src={src} alt={`Screenshot of ${evidence.url}`} />
                     : <div className="ev-shot skeleton" />}

                <div className="ev-facts">
                    <div><span>Verdict</span><VerdictBadge evidence={evidence} /></div>
                    <div><span>Captured</span>{exactTime(utc(evidence.captured_at))} · {timeAgo(utc(evidence.captured_at))}</div>
                    {evidence.brand && <div><span>Looks like</span>{evidence.brand}</div>}
                    <div className="wide"><span>Page</span><a href={evidence.url} target="_blank" rel="noreferrer noopener" className="mono">{evidence.url} <ExternalLink /></a></div>
                    {evidence.final_url && evidence.final_url !== evidence.url && (
                        <div className="wide"><span>Redirected to</span><span className="mono">{evidence.final_url}</span></div>
                    )}
                    {evidence.form_actions?.length > 0 && (
                        <div className="wide">
                            <span>Password goes to</span>
                            <span className={`mono ${offDomain ? "ev-bad" : ""}`}>
                                {evidence.form_actions.join(", ")}{offDomain ? " — a different site" : ""}
                            </span>
                        </div>
                    )}
                    {evidence.blocked && (
                        <div className="wide"><span>Note</span>A bot check ({evidence.blocked_by}) stopped the agent before the real page loaded, so there's no verdict either way.</div>
                    )}
                    <div className="wide">
                        <span>Fingerprint</span>
                        <span className="ev-integrity">
                            <Fingerprint />
                            <span className="mono">{evidence.image_sha256.slice(0, 16)}…</span>
                            {check === null ? <em>checking…</em>
                                : check.integrity_ok ? <em className="ok">matches — unaltered since capture</em>
                                : check.integrity_ok === false ? <em className="bad">doesn't match — this image may have been altered</em>
                                : <em>couldn't check</em>}
                        </span>
                    </div>
                </div>
            </div>
        </div>
    )
}

// alert detail: the capture(s) of the page this alert is about
export function EvidencePanel({ alert }) {
    const [list, setList] = useState(null)
    const [open, setOpen] = useState(null)
    useEffect(() => {
        let alive = true, timer, tries = 0
        // the extension reports the alert at once; the agent's screenshot lands
        // a few seconds later. for a fresh alert keep asking until it arrives
        const fresh = Date.now() - new Date(alert.timestamp).getTime() < 2 * 60 * 1000
        const load = () => api(`/alerts/${alert.alert_id}/evidence`)
            .then(r => r.ok ? r.json() : [])
            .catch(() => [])
            .then(d => {
                if (!alive) return
                setList(d)
                if (!d.length && fresh && ++tries < 15) timer = setTimeout(load, 2000)
            })
        load()
        return () => { alive = false; clearTimeout(timer) }
    }, [alert.alert_id, alert.timestamp])

    if (list === null) return <section className="ev-panel loading"><div className="ev-shot big skeleton" /></section>
    if (list.length === 0) return (
        <section className="ev-panel empty">
            <Camera />
            <span>No agent screenshot for this page yet — it appears here as soon as the agent has checked the page.</span>
        </section>
    )
    const latest = list[0]
    return (
        <section className="ev-panel">
            <div className="ev-panel-head">
                <span className="ev-eyebrow"><Camera /> Agent evidence</span>
                <VerdictBadge evidence={latest} />
                <span className="ev-when" title={exactTime(utc(latest.captured_at))}>captured {timeAgo(utc(latest.captured_at))}</span>
            </div>
            <Shot evidence={latest} onOpen={setOpen} size="big" />
            {latest.off_domain && latest.form_actions?.length > 0 && (
                <p className="ev-caption">
                    The password on this page is sent to <b className="mono">{host(latest.form_actions[0])}</b>, not {host(latest.url)}.
                </p>
            )}
            {list.length > 1 && (
                <div className="ev-strip">
                    <span>{list.length} captures</span>
                    {list.slice(1, 6).map(e => <Shot key={e.evidence_id} evidence={e} onOpen={setOpen} size="tiny" />)}
                </div>
            )}
            {open && <EvidenceViewer evidence={open} onClose={() => setOpen(null)} />}
        </section>
    )
}

// entity drill-down (#30 stage 2): the screenshots behind these alerts
export function EvidenceGallery({ alerts }) {
    const urls = [...new Set(alerts.map(a => a.target_url).filter(Boolean))].slice(0, 8)
    const key = urls.join("\n")
    const [items, setItems] = useState(null)
    const [open, setOpen] = useState(null)
    useEffect(() => {
        let alive = true
        const list = key ? key.split("\n") : []
        Promise.all(list.map(u =>
            api(`/evidence?limit=1&url=${encodeURIComponent(u)}`).then(r => r.ok ? r.json() : []).catch(() => [])
        )).then(rs => { if (alive) setItems(rs.flat()) })
        return () => { alive = false }
    }, [key])

    if (!urls.length) return null
    return (
        <>
            {items === null ? <div className="ev-grid">{urls.slice(0, 3).map(u => <div key={u} className="ev-shot skeleton" />)}</div>
                : items.length === 0 ? <div className="empty">No agent screenshots for these pages yet.</div>
                : (
                    <div className="ev-grid">
                        {items.map(e => (
                            <figure key={e.evidence_id} className="ev-card">
                                <Shot evidence={e} onOpen={setOpen} />
                                <figcaption>
                                    <span className="mono">{host(e.url)}</span>
                                    <VerdictBadge evidence={e} />
                                </figcaption>
                            </figure>
                        ))}
                    </div>
                )}
            {open && <EvidenceViewer evidence={open} onClose={() => setOpen(null)} />}
        </>
    )
}

// a row of captures already fetched (the Ask AI page gets them from a tool)
export function EvidenceList({ items }) {
    const [open, setOpen] = useState(null)
    if (!items?.length) return null
    return (
        <>
            <div className="ev-grid">
                {items.slice(0, 4).map(e => (
                    <figure key={e.evidence_id} className="ev-card">
                        <Shot evidence={e} onOpen={setOpen} />
                        <figcaption>
                            <span className="mono">{host(e.url)}</span>
                            <VerdictBadge evidence={e} />
                        </figcaption>
                    </figure>
                ))}
            </div>
            {open && <EvidenceViewer evidence={open} onClose={() => setOpen(null)} />}
        </>
    )
}
