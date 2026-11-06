import { useState, useEffect, useMemo, useRef } from 'react'
import { Search, X, ArrowRight, ArrowLeft, Sparkles } from 'lucide-react'
import GraphCanvas from './GraphCanvas'
import { TOKEN } from './graphStyle'
import { timeAgo, exactTime } from './time'
import { alertEntityIds } from './graphScope'

/* The Network graph tab (#29): the attack graph as an explorer, not a picture.
 *   - find an entity by name and fly to it
 *   - filter by severity / engine / time (which alerts count) and by entity type
 *   - click a node: what it is, what it connects to, which alerts involve it
 * All filtering is client-side: the graph comes from Neo4j as-is, and the alerts
 * we already hold decide which entities are in scope. */

const SEVERITIES = ["critical", "high", "medium", "low"]
const ENGINES = ["verifyeye", "spectrac2", "manual"]
const RANGES = { "24h": 864e5, "7d": 7 * 864e5, "30d": 30 * 864e5 }
const GROUP_PREVIEW = 6   // connections listed per relationship before "+N more"

// HAS_IP -> "has IP", CONNECTED_TO_DOMAIN -> "connected to domain"
const relLabel = (t) => t.toLowerCase().split("_").map(w => w === "ip" ? "IP" : w === "url" ? "URL" : w).join(" ")

// types the alerts search understands (see matchesTerm in App)
const SEARCHABLE = new Set(["Host", "User", "Domain", "IP", "Technique"])

function TypeDot({ type }) {
    return (
        <span
            className={`graph-legend-dot shape-${type.toLowerCase()}`}
            style={{ background: `var(${TOKEN[type]})` }}
        />
    )
}

// same look as the dashboard's segmented filters
function Pick({ label, value, options, onChange }) {
    return (
        <div className="seg-group">
            <span className="seg-label">{label}</span>
            <div className="seg" role="group" aria-label={label}>
                <button className={`seg-btn ${value === null ? "on" : ""}`} onClick={() => onChange(null)} aria-pressed={value === null}>All</button>
                {options.map(o => (
                    <button key={o} className={`seg-btn ${value === o ? "on" : ""}`} onClick={() => onChange(o)} aria-pressed={value === o}>{o}</button>
                ))}
            </div>
        </div>
    )
}

export default function GraphExplorer({ alerts, refreshKey, onOpenAlert, onFilter, focus, onClearFocus }) {
    const cyRef = useRef(null)
    const [graph, setGraph] = useState({ nodes: [], edges: [] })
    const [ready, setReady] = useState(false)

    const [sev, setSev] = useState(null)
    const [engine, setEngine] = useState(null)
    // range is the preset ("7d"); since is its cut-off, fixed at the moment it's picked
    const [range, setRangeKey] = useState(null)
    const [since, setSince] = useState(-Infinity)
    const setRange = (r) => { setRangeKey(r); setSince(r ? Date.now() - RANGES[r] : -Infinity) }
    const [hiddenTypes, setHiddenTypes] = useState(() => new Set())
    const [selectedId, setSelectedId] = useState(null)
    const [find, setFind] = useState("")
    const [findOpen, setFindOpen] = useState(false)
    const [expanded, setExpanded] = useState(() => new Set())   // connection groups showing all items

    // node id -> alerts touching it, newest first
    const alertsByEntity = useMemo(() => {
        const map = new Map()
        const sorted = [...alerts].sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp))
        sorted.forEach(a => alertEntityIds(a).forEach(id => {
            if (!map.has(id)) map.set(id, [])
            map.get(id).push(a)
        }))
        return map
    }, [alerts])

    // the alert filters decide which entities are in scope; null = everything
    const filterActive = !!(sev || engine || range)
    const allowedIds = useMemo(() => {
        if (!filterActive) return null
        const ids = new Set()
        alerts.forEach(a => {
            if (sev && a.severity !== sev) return
            if (engine && a.source !== engine) return
            if (new Date(a.timestamp).getTime() < since) return
            alertEntityIds(a).forEach(id => ids.add(id))
        })
        return ids
    }, [alerts, sev, engine, since, filterActive])

    // what's on screen, worked out from data (the canvas mirrors this below)
    const isVisible = (n) => !hiddenTypes.has(n.type) && (!allowedIds || allowedIds.has(n.id))
    const shown = graph.nodes.filter(isVisible).length

    // node lookup + links per node, for the find box and the detail panel
    const index = useMemo(() => {
        const byId = new Map(graph.nodes.map(n => [n.id, n]))
        const edgesOf = new Map()
        graph.edges.forEach(e => {
            [e.source, e.target].forEach(id => {
                if (!edgesOf.has(id)) edgesOf.set(id, [])
                edgesOf.get(id).push(e)
            })
        })
        return { byId, edgesOf }
    }, [graph])

    // wire selection once the canvas exists. GraphCanvas already does the
    // highlight on tap; we only track which node is open in the panel
    const handleReady = (cy) => {
        cyRef.current = cy
        cy.on("tap", "node", e => setSelectedId(e.target.id()))
        cy.on("tap", e => { if (e.target === cy) setSelectedId(null) })
        setReady(true)
    }

    // apply type + alert filters. runs after GraphCanvas has synced new data in
    // (child effects run first), so freshly arrived nodes get filtered too
    useEffect(() => {
        const cy = cyRef.current
        if (!cy) return
        cy.batch(() => {
            cy.nodes().forEach(n => {
                const keep = !hiddenTypes.has(n.data("type")) && (!allowedIds || allowedIds.has(n.id()))
                n.toggleClass("gone", !keep)
            })
        })
        // a node that just got filtered out can't keep its highlight
        if (cy.nodes(":selected.gone").nonempty()) cy.elements().removeClass("faded hl").unselect()
    }, [graph, hiddenTypes, allowedIds, ready])

    // when the analyst changes a filter (not when a live alert lands), refit
    const filterKey = `${sev}|${engine}|${range}|${[...hiddenTypes].join(",")}`
    const firstFilter = useRef(true)
    useEffect(() => {
        if (firstFilter.current) { firstFilter.current = false; return }
        const cy = cyRef.current
        const visible = cy?.elements(":visible")
        if (visible?.length) cy.animate({ fit: { eles: visible, padding: 40 }, duration: 260 })
    }, [filterKey])

    // select a node from outside the canvas (find box, connection list):
    // same highlight as a click, then fly to its neighbourhood
    const focusNode = (id) => {
        const cy = cyRef.current
        const node = cy?.getElementById(id)
        if (!node || node.empty()) return
        if (node.hasClass("gone")) {
            // it's filtered out: make its type visible and drop the alert filters
            setHiddenTypes(prev => { const next = new Set(prev); next.delete(node.data("type")); return next })
            setSev(null); setEngine(null); setRange(null)
            node.removeClass("gone")
        }
        const near = node.closedNeighborhood()
        cy.elements().removeClass("faded hl").unselect()
        cy.elements().difference(near).addClass("faded")
        near.addClass("hl")
        node.select()
        setSelectedId(id)

        // frame the neighbourhood in the part of the canvas the detail panel
        // leaves free: the left side on desktop, the top on phones
        const narrow = cy.width() < 640
        const w = narrow ? cy.width() : cy.width() - 334
        const h = narrow ? cy.height() * 0.38 : cy.height()
        const bb = near.filter(":visible").boundingBox()
        const pad = 50
        const zoom = Math.min(cy.maxZoom(), Math.max(cy.minZoom(),
            Math.min((w - 2 * pad) / Math.max(bb.w, 1), (h - 2 * pad) / Math.max(bb.h, 1))))
        cy.animate({
            zoom,
            pan: { x: w / 2 - zoom * (bb.x1 + bb.w / 2), y: h / 2 - zoom * (bb.y1 + bb.h / 2) },
            duration: 350,
        })
    }

    const clearSelection = () => {
        const cy = cyRef.current
        cy?.elements().removeClass("faded hl").unselect()
        setSelectedId(null)
    }

    // "See in network graph" from a dashboard: light up that set of entities
    // (and the links between them), fade everything else, and frame them
    const focusIds = useMemo(() => focus ? new Set(focus.ids) : null, [focus])
    const focusFound = focusIds ? graph.nodes.filter(n => focusIds.has(n.id)).length : 0
    const lightUp = () => {
        const cy = cyRef.current
        if (!cy || !focusIds) return
        const lit = cy.nodes().filter(n => focusIds.has(n.id()))
        const litAll = lit.union(lit.edgesWith(lit))
        cy.elements().removeClass("faded hl").unselect()
        setSelectedId(null)
        if (lit.empty()) return
        cy.elements().difference(litAll).addClass("faded")
        litAll.addClass("hl")
        const visible = lit.filter(":visible")
        if (visible.nonempty()) cy.animate({ fit: { eles: visible, padding: 70 }, duration: 400 })
    }
    // once per focus, as soon as the graph has loaded. not on every live
    // update, or it would undo whatever the analyst clicked on since
    const litFor = useRef(null)
    useEffect(() => {
        if (!focus || !ready || !graph.nodes.length || litFor.current === focus) return
        litFor.current = focus
        lightUp()
    }, [focus, ready, graph]) // eslint-disable-line react-hooks/exhaustive-deps

    // focus dropped from outside (e.g. the sidebar link while already on this
    // tab): the page doesn't remount, so take the highlight down ourselves
    useEffect(() => {
        if (focus || !litFor.current) return
        litFor.current = null
        cyRef.current?.elements().removeClass("faded hl").unselect()
    }, [focus])

    const clearFocus = () => {
        clearSelection()
        litFor.current = null
        onClearFocus?.()
    }

    const toggleType = (type) => setHiddenTypes(prev => {
        const next = new Set(prev)
        next.has(type) ? next.delete(type) : next.add(type)
        return next
    })

    const resetFilters = () => { setSev(null); setEngine(null); setRange(null); setHiddenTypes(new Set()) }

    // find box: match labels, most connected first
    const q = find.trim().toLowerCase()
    const findHits = !q ? [] : graph.nodes
        .filter(n => String(n.label ?? "").toLowerCase().includes(q))
        .sort((a, b) => (index.edgesOf.get(b.id)?.length || 0) - (index.edgesOf.get(a.id)?.length || 0))
        .slice(0, 8)

    const pickHit = (id) => { focusNode(id); setFind(""); setFindOpen(false) }

    // everything the detail panel shows. A node filtered out of view closes it.
    const node = selectedId ? index.byId.get(selectedId) : null
    let detail = null
    if (node && isVisible(node)) {
        // group connections by relationship + direction: "has IP → 10.0.0.5"
        const groups = {}
        ;(index.edgesOf.get(node.id) || []).forEach(e => {
            const out = e.source === node.id
            const other = index.byId.get(out ? e.target : e.source)
            if (!other || !isVisible(other)) return
            const key = `${out ? "out" : "in"}:${e.type}`
            if (!groups[key]) groups[key] = { out, rel: e.type, items: [] }
            groups[key].items.push(other)
        })
        const related = alertsByEntity.get(node.id) || []
        const times = related.map(a => new Date(a.timestamp).getTime()).filter(t => !isNaN(t))
        const grouped = Object.values(groups).sort((a, b) => b.items.length - a.items.length)
        detail = {
            ...node,
            groups: grouped,
            connections: grouped.reduce((n, g) => n + g.items.length, 0),
            related,
            worst: SEVERITIES.find(s => related.some(a => a.severity === s)),
            first: times.length ? Math.min(...times) : null,
            last: times.length ? Math.max(...times) : null,
        }
    }

    const total = graph.nodes.length
    const note = total === 0 ? undefined
        : shown === total ? `${total} entities · ${graph.edges.length} connections`
        : `${shown} of ${total} entities shown`

    const toolbar = (
        <>
        {focus && (
            <div className="gx-focus" role="status">
                <Sparkles />
                <span>
                    {focusFound
                        ? <>Highlighting <b>{focusFound}</b> {focusFound === 1 ? "entity" : "entities"} from {focus.label}</>
                        : <>None of {focus.label}’s entities are in the graph yet</>}
                </span>
                {focusFound > 0 && <button className="gx-reset" onClick={lightUp}>Highlight again</button>}
                <button className="gx-reset" onClick={clearFocus}><X /> Clear</button>
            </div>
        )}
        <div className="gx-toolbar">
            <div className="gx-find">
                <Search />
                <input
                    placeholder="Find a host, user, domain, IP…"
                    value={find}
                    onChange={e => { setFind(e.target.value); setFindOpen(true) }}
                    onFocus={() => setFindOpen(true)}
                    onBlur={() => setTimeout(() => setFindOpen(false), 120)}
                    onKeyDown={e => {
                        if (e.key === "Enter" && findHits[0]) pickHit(findHits[0].id)
                        if (e.key === "Escape") { setFind(""); setFindOpen(false); e.currentTarget.blur() }
                    }}
                    aria-label="Find an entity in the graph"
                />
                {findOpen && find.trim() && (
                    <div className="gx-find-menu">
                        {findHits.length === 0
                            ? <div className="gx-find-empty">No entity matches “{find.trim()}”</div>
                            : findHits.map(n => (
                                <button key={n.id} className="gx-find-row" onMouseDown={e => e.preventDefault()} onClick={() => pickHit(n.id)}>
                                    <TypeDot type={n.type} />
                                    <span className="gx-find-label">{n.label}</span>
                                    <span className="gx-find-type">{n.type}</span>
                                </button>
                            ))}
                    </div>
                )}
            </div>
            <Pick label="Severity" value={sev} options={SEVERITIES} onChange={setSev} />
            <Pick label="Engine" value={engine} options={ENGINES} onChange={setEngine} />
            <Pick label="Time" value={range} options={Object.keys(RANGES)} onChange={setRange} />
            {(filterActive || hiddenTypes.size > 0) && (
                <button className="gx-reset" onClick={resetFilters}>
                    <X /> Clear filters
                </button>
            )}
        </div>
        </>
    )

    return (
        <GraphCanvas
            refreshKey={refreshKey}
            onReady={handleReady}
            onGraph={setGraph}
            toolbar={toolbar}
            hiddenTypes={hiddenTypes}
            onToggleType={toggleType}
            note={note}
        >
            {ready && total > 0 && shown === 0 && (
                <div className="graph-overlay">
                    <span>No entities match these filters.</span>
                    <button className="gx-reset" onClick={resetFilters}><X /> Clear filters</button>
                </div>
            )}

            {detail && (
                // keyed by node: jumping to another node starts the panel at the top
                <aside key={detail.id} className="gx-panel" aria-label={`${detail.type} details`}>
                    <div className="gx-head">
                        <div className="gx-type"><TypeDot type={detail.type} />{detail.type}</div>
                        <button className="gx-close" onClick={clearSelection} aria-label="Close details"><X /></button>
                    </div>
                    <div className="gx-title">{detail.label}</div>

                    <div className="gx-stats">
                        <div><b>{detail.related.length}</b><span>alerts</span></div>
                        <div><b>{detail.connections}</b><span>links</span></div>
                        <div>
                            {detail.worst
                                ? <span className={`sev ${detail.worst}`}>{detail.worst}</span>
                                : <b className="gx-none">—</b>}
                            <span>worst</span>
                        </div>
                    </div>

                    {detail.first && (
                        <div className="gx-seen">
                            <div><span>First seen</span>{exactTime(detail.first)}</div>
                            <div><span>Last seen</span>{exactTime(detail.last)}</div>
                        </div>
                    )}

                    <div className="gx-section">
                        <div className="gx-section-title">Connections</div>
                        {detail.groups.length === 0
                            ? <div className="gx-empty">Nothing else on screen links to this.</div>
                            : detail.groups.map(g => {
                                // busy hosts can have dozens of URLs; show a few, expand on demand
                                const key = `${detail.id}|${g.out}:${g.rel}`
                                const open = expanded.has(key)
                                const items = open ? g.items : g.items.slice(0, GROUP_PREVIEW)
                                return (
                                    <div className="gx-group" key={key}>
                                        <div className="gx-rel">
                                            {g.out ? <ArrowRight /> : <ArrowLeft />}
                                            {g.out ? relLabel(g.rel) : `${relLabel(g.rel)} (from)`}
                                            <span className="gx-rel-n">{g.items.length}</span>
                                        </div>
                                        {items.map(it => (
                                            <button key={it.id} className="gx-link" onClick={() => focusNode(it.id)} title={`Go to ${it.label}`}>
                                                <TypeDot type={it.type} />
                                                <span>{it.label}</span>
                                            </button>
                                        ))}
                                        {g.items.length > GROUP_PREVIEW && (
                                            <button className="gx-more" onClick={() => setExpanded(prev => {
                                                const next = new Set(prev)
                                                open ? next.delete(key) : next.add(key)
                                                return next
                                            })}>
                                                {open ? "Show fewer" : `+${g.items.length - GROUP_PREVIEW} more`}
                                            </button>
                                        )}
                                    </div>
                                )
                            })}
                    </div>

                    <div className="gx-section">
                        <div className="gx-section-title">
                            Related alerts
                            {detail.related.length > 0 && <span className="gx-count">{detail.related.length}</span>}
                        </div>
                        {detail.related.length === 0
                            ? <div className="gx-empty">No alert names this {detail.type.toLowerCase()} directly.</div>
                            : detail.related.slice(0, 6).map(a => (
                                <button key={a.alert_id} className="gx-alert" onClick={() => onOpenAlert(a.alert_id)}>
                                    <span className={`sev ${a.severity}`}>{a.severity}</span>
                                    <span className="gx-alert-type">{a.event_type}</span>
                                    <span className="gx-alert-time" title={exactTime(a.timestamp)}>{timeAgo(a.timestamp)}</span>
                                </button>
                            ))}
                        {detail.related.length > 0 && SEARCHABLE.has(detail.type) && (
                            <button className="gx-more" onClick={() => onFilter(detail.label)}>
                                View all {detail.related.length} alerts <ArrowRight />
                            </button>
                        )}
                    </div>
                </aside>
            )}
        </GraphCanvas>
    )
}
