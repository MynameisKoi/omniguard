import { useRef, useEffect, useState, useMemo }  from 'react'
import cytoscape from 'cytoscape'
import fcose from 'cytoscape-fcose'
import { API_URL } from "./config"
import { Maximize2, Minimize2, Plus, Minus, Scan, Shuffle } from 'lucide-react'
import { buildGraphStyle, attachGraphInteractions, NODE_TYPES, TOKEN } from './graphStyle'
import { scopeIds } from './graphScope'

// fcose: a much faster force layout than the built-in cose (cose is roughly
// quadratic — ~8s for 600 entities — and freezes the page while it runs)
cytoscape.use(fcose)

// fcose settings shared by first draw, live updates and "tidy". Above ~1500
// entities its default mode slows sharply (≈10s at 4000); draft stays ~1s
function forceLayout(n, extra) {
    return {
        name: "fcose",
        quality: n > 1500 ? "draft" : "default",
        animate: false,
        padding: 40,
        // roomier than fcose's defaults: our nodes carry labels underneath
        nodeRepulsion: 30000,
        idealEdgeLength: 130,
        nodeSeparation: 110,
        ...extra,
    }
}

/* The cytoscape canvas: fetching, live sync, fullscreen and zoom controls.
 * The explorer (GraphExplorer) drives it from outside through these props:
 *   onReady(cy)    the instance, once, so it can listen for taps / filter / focus
 *   onGraph(data)  the fetched {nodes, edges}, every time it changes
 *   toolbar        extra controls rendered above the legend
 *   hiddenTypes + onToggleType   make the legend chips toggle entity types
 *   note           replaces the "N entities · M connections" text
 *   children       overlays drawn on top of the canvas (detail panel, empty state)
 * and the smaller dashboard graphs use:
 *   scope          a list of alerts: only the entities they touch are fetched
 *                  (null = the whole graph). Lets a filtered view filter the graph too.
 * what gets fetched (graph at scale, #13 — the browser layout slows down fast,
 * so ask the backend for only what will be drawn):
 *   limit          the N most-connected entities (null = all)
 *   include        entity ids that must be in it anyway (what "See in graph" lights up) */
function GraphCanvas({ compact = false, refreshKey, host, onReady, onGraph, toolbar, hiddenTypes, onToggleType, note, scope = null, limit = null, include = null, children }) {
    // going to write useRef
    const containerRef = useRef(null);

    // the live cytoscape instance, so the fullscreen toggle can resize it
    const cyRef = useRef(null);
    const [fullscreen, setFullscreen] = useState(false);

    // adding the state for graph, error and loading
    const [graph, setGraph] = useState({nodes: [], edges: []})
    const [error, setError] = useState(null)
    const [loading, setLoading] = useState(true)

    // node ids in scope, and a stable key so we only refit when the scope really changes
    // (callers pass a fresh array every render, so key on the ids, not the array)
    const scopeKey = scope ? "s:" + [...scopeIds(scope)].sort().join("\n") : ""
    const scopedIds = useMemo(
        () => scopeKey ? scopeKey.slice(2).split("\n").filter(Boolean) : null,
        [scopeKey],
    )
    const includeKey = include?.length ? [...include].sort().join("\n") : ""
    const fittedKey = useRef(null)
    // how many in-scope entities came back (null = not scoped)
    const shownCount = scopedIds ? graph.nodes.length : null

    // fetch the graph. asking for something different (first load, another
    // scope, "show more") goes straight away; a plain refresh — every live
    // alert bumps refreshKey — waits a beat, so a burst of alerts costs one
    // request and one layout instead of one each
    const lastRequest = useRef(null)
    useEffect(() => {
        let cancelled = false
        const run = () => {
            const req = host
                ? fetch(`${API_URL}/graph/host/${encodeURIComponent(host)}`)
                : fetch(`${API_URL}/graph/view`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(scopedIds
                        ? { only: scopedIds }
                        : { limit, include: includeKey ? includeKey.split("\n") : [] }),
                })
            req
            .then(res => res.json())
            .then(data => { if (!cancelled) { setGraph(data); onGraph?.(data) } })
            .catch(err => { if (!cancelled) setError(err.message) })
            .finally(() => { if (!cancelled) setLoading(false) })
        }
        const requestKey = [host, scopeKey, limit, includeKey].join("|")
        const id = setTimeout(run, lastRequest.current === requestKey ? 1200 : 0)
        lastRequest.current = requestKey
        return () => { cancelled = true; clearTimeout(id) }
    }, [refreshKey, host, scopedIds, scopeKey, limit, includeKey])

    // create the cytoscape instance ONCE. If we rebuilt it on every graph
    // change, the whole layout would reshuffle each time an alert arrives —
    // the node you're looking at would jump. Instead we build it empty here and
    // sync data into it below, so positions are preserved across updates.
    useEffect(() => {
        if (!containerRef.current) return

        const cy = cytoscape({
            container: containerRef.current,
            elements: [],
            style: buildGraphStyle(),
            minZoom: 0.3,
            maxZoom: 2.5,
        })
        cyRef.current = cy
        attachGraphInteractions(cy)
        onReady?.(cy)

        // the palette lives in CSS variables, so re-apply the stylesheet when
        // the dashboard theme flips
        const observer = new MutationObserver(() => cy.style(buildGraphStyle()))
        observer.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ["data-theme"],
        })

        // cytoscape caches the container size at init. On the detail page and
        // the dashboard the container is often 0-sized for a frame, so nodes
        // get laid out against nothing and render off-screen. Watch the size
        // and re-fit once it has real dimensions.
        let lastW = 0, lastH = 0
        const sizer = new ResizeObserver(() => {
            const el = containerRef.current
            if (!el || !cyRef.current) return
            const { clientWidth: w, clientHeight: h } = el
            if (w === lastW && h === lastH) return
            lastW = w; lastH = h
            if (w > 0 && h > 0) {
                cy.resize()
                if (cy.nodes(":visible").length) cy.fit(cy.elements(":visible"), 40)
            }
        })
        sizer.observe(containerRef.current)

        return () => {
            observer.disconnect()
            sizer.disconnect()
            cy.destroy()
            cyRef.current = null
        }
    }, [])

    // sync the fetched graph into the existing instance: add new elements,
    // drop ones that are gone, then lay out ONLY the new nodes so everything
    // already on screen stays where the analyst last saw it.
    useEffect(() => {
        const cy = cyRef.current
        if (!cy) return

        // degree drives node size; recompute it each sync since edges change
        const degree = {}
        graph.edges.forEach(e => {
            degree[e.source] = (degree[e.source] || 0) + 1
            degree[e.target] = (degree[e.target] || 0) + 1
        })

        const wanted = new Set([
            ...graph.nodes.map(n => n.id),
            ...graph.edges.map(e => e.id),
        ])

        // remove anything no longer in the data
        cy.elements().forEach(el => {
            if (!wanted.has(el.id())) el.remove()
        })

        // nodes that already exist keep their position; track which are new
        const fresh = []
        cy.batch(() => {
            graph.nodes.forEach(n => {
                const existing = cy.getElementById(n.id)
                if (existing.nonempty()) {
                    existing.data("degree", degree[n.id] || 0)
                } else {
                    fresh.push(cy.add({ group: "nodes", data: { ...n, degree: degree[n.id] || 0 } }))
                }
            })
            graph.edges.forEach(e => {
                if (cy.getElementById(e.id).empty()) {
                    cy.add({ group: "edges", data: e })
                }
            })
        })

        if (fresh.length === 0) return

        const firstDraw = cy.nodes().length === fresh.length
        let layout
        if (firstDraw) {
            layout = cy.layout(forceLayout(fresh.length, { randomize: true, fit: true }))
        } else {
            // live update: start each new node beside something it links to,
            // and pin everything already placed so only the newcomers move
            const settled = cy.nodes().difference(cy.collection(fresh))
            fresh.forEach(n => {
                const anchor = n.neighborhood("node").difference(cy.collection(fresh))[0]
                const p = anchor ? anchor.position() : { x: 0, y: 0 }
                n.position({ x: p.x + (Math.random() - 0.5) * 80, y: p.y + (Math.random() - 0.5) * 80 })
            })
            layout = cy.layout(forceLayout(cy.nodes().length, {
                randomize: false,
                fit: false,
                fixedNodeConstraint: settled.map(n => ({ nodeId: n.id(), position: { ...n.position() } })),
            }))
        }
        layout.run()
        return () => layout.stop()
    }, [graph])

    // the backend already sent only the scoped entities; when the scope
    // itself changes (a different filter), frame the new set
    useEffect(() => {
        const cy = cyRef.current
        if (!cy || !graph.nodes.length || fittedKey.current === scopeKey) return
        fittedKey.current = scopeKey
        if (scopeKey) cy.fit(cy.elements(":visible"), 30)
    }, [graph, scopeKey])

    // the container changes size when fullscreen flips, and cytoscape caches
    // its dimensions — it has to be told
    useEffect(() => {
        const cy = cyRef.current
        if (!cy) return
        const id = requestAnimationFrame(() => {
            cy.resize()
            cy.fit(cy.elements(":visible"), 40)
        })
        return () => cancelAnimationFrame(id)
    }, [fullscreen])

    // escape leaves fullscreen
    useEffect(() => {
        if (!fullscreen) return
        const onKey = e => { if (e.key === "Escape") setFullscreen(false) }
        window.addEventListener("keydown", onKey)
        return () => window.removeEventListener("keydown", onKey)
    }, [fullscreen])

    // zoom around the middle of the canvas, not the corner
    const zoomBy = (factor) => {
        const cy = cyRef.current
        if (!cy) return
        const level = Math.min(cy.maxZoom(), Math.max(cy.minZoom(), cy.zoom() * factor))
        cy.animate({ zoom: { level, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }, duration: 160 })
    }
    const fitAll = () => {
        const cy = cyRef.current
        if (cy) cy.animate({ fit: { eles: cy.elements(":visible"), padding: 40 }, duration: 260 })
    }
    // re-run the layout on what's on screen, for when live updates leave it messy
    const tidy = () => {
        const cy = cyRef.current
        if (!cy) return
        const visible = cy.elements(":visible")
        visible.layout(forceLayout(visible.nodes().length, {
            randomize: true, fit: true, animate: true, animationDuration: 450,
        })).run()
    }

    return (
        <div className={`graph ${fullscreen ? "fullscreen" : ""} ${compact ? "compact" : ""}`}>
            {!compact && toolbar}
            {!compact && <div className="graph-legend">
                {NODE_TYPES.map(type => {
                    const dot = (
                        <span
                            className={`graph-legend-dot shape-${type.toLowerCase()}`}
                            style={{ background: `var(${TOKEN[type]})` }}
                        />
                    )
                    // with onToggleType the key doubles as a show/hide switch per type
                    return onToggleType ? (
                        <button
                            key={type}
                            className={`graph-legend-item toggle ${hiddenTypes?.has(type) ? "off" : ""}`}
                            onClick={() => onToggleType(type)}
                            aria-pressed={!hiddenTypes?.has(type)}
                            title={hiddenTypes?.has(type) ? `Show ${type} nodes` : `Hide ${type} nodes`}
                        >
                            {dot}{type}
                        </button>
                    ) : (
                        <span className="graph-legend-item" key={type}>{dot}{type}</span>
                    )
                })}
                <span className="graph-legend-note">
                    {loading
                        ? "loading…"
                        : note ?? `${graph.nodes.length} entities · ${graph.edges.length} connections`}
                    {fullscreen && <span className="graph-esc">esc</span>}
                </span>
                <button
                    className="graph-expand"
                    onClick={() => setFullscreen(!fullscreen)}
                    title={fullscreen ? "Exit fullscreen" : "Expand to fullscreen"}
                >
                    {fullscreen ? <Minimize2 /> : <Maximize2 />}
                    {fullscreen ? "Exit" : "Expand"}
                </button>
            </div>}

            {error && <div className="error">Could not load the graph — {error}</div>}

            <div className="graph-stage">
                <div ref={containerRef} className="graph-canvas" />

                {loading && (
                    <div className="graph-overlay">
                        <div className="spinner" />
                        <span>Loading graph…</span>
                    </div>
                )}
                {!loading && !error && graph.nodes.length === 0 && (
                    <div className="graph-overlay">
                        <span>No entities yet — they appear as alerts come in.</span>
                    </div>
                )}
                {!loading && graph.nodes.length > 0 && shownCount === 0 && (
                    <div className="graph-overlay">
                        <span>None of these alerts are in the graph yet.</span>
                    </div>
                )}

                {!compact && (
                    <div className="graph-zoom" role="group" aria-label="Graph view controls">
                        <button onClick={() => zoomBy(1.3)} title="Zoom in" aria-label="Zoom in"><Plus /></button>
                        <button onClick={() => zoomBy(1 / 1.3)} title="Zoom out" aria-label="Zoom out"><Minus /></button>
                        <button onClick={fitAll} title="Fit to screen" aria-label="Fit to screen"><Scan /></button>
                        <button onClick={tidy} title="Tidy layout" aria-label="Tidy layout"><Shuffle /></button>
                    </div>
                )}

                {children}
            </div>
        </div>
    )
}

export default GraphCanvas; 