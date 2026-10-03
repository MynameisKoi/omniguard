import { useRef, useEffect, useState }  from 'react'
import cytoscape from 'cytoscape'
import { API_URL } from "./config"
import { Maximize2, Minimize2 } from 'lucide-react'
import { buildGraphStyle, attachGraphInteractions, NODE_TYPES, TOKEN } from './graphStyle'

function GraphCanvas({ compact = false, refreshKey}) {
    // going to write useRef
    const containerRef = useRef(null);

    // the live cytoscape instance, so the fullscreen toggle can resize it
    const cyRef = useRef(null);
    const [fullscreen, setFullscreen] = useState(false);

    // adding the state for graph, error and loading
    const [graph, setGraph] = useState({nodes: [], edges: []})
    const [error, setError] = useState(null)
    const [loading, setLoading] = useState(true)

    // adding useEffect here 
    useEffect(() => {
        // fetching the backend for the graph data
        fetch(`${API_URL}/graph`)
        .then(res => res.json())
        .then(data => setGraph(data))
        .catch(err => setError(err.message))
        .finally(() => setLoading(false))
    }, [refreshKey])

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

        // the palette lives in CSS variables, so re-apply the stylesheet when
        // the dashboard theme flips
        const observer = new MutationObserver(() => cy.style(buildGraphStyle()))
        observer.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ["data-theme"],
        })

        return () => {
            observer.disconnect()
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

        // lock everything already placed so cose only positions the new nodes
        const settled = cy.nodes().difference(cy.collection(fresh))
        settled.lock()

        const layout = cy.layout({
            name: "cose",
            animate: false,
            padding: 40,
            nodeRepulsion: 14000,
            idealEdgeLength: 95,
            nodeOverlap: 24,
            fit: firstDraw,       // only auto-fit on the very first render
            randomize: firstDraw, // new nodes start near their neighbours otherwise
        })
        layout.run()
        settled.unlock()

        return () => layout.stop()
    }, [graph])

    // the container changes size when fullscreen flips, and cytoscape caches
    // its dimensions — it has to be told
    useEffect(() => {
        const cy = cyRef.current
        if (!cy) return
        const id = requestAnimationFrame(() => {
            cy.resize()
            cy.fit(undefined, 40)
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

    return (
        <div className={`graph ${fullscreen ? "fullscreen" : ""} ${compact ? "compact" : ""}`}>
            {!compact && <div className="graph-legend">
                {NODE_TYPES.map(type => (
                    <span className="graph-legend-item" key={type}>
                        <span
                            className={`graph-legend-dot shape-${type.toLowerCase()}`}
                            style={{ background: `var(${TOKEN[type]})` }}
                        />
                        {type}
                    </span>
                ))}
                <span className="graph-legend-note">
                    {loading
                        ? "loading…"
                        : `${graph.nodes.length} entities · ${graph.edges.length} connections`}
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

            <div ref={containerRef} className="graph-canvas" />
        </div>
    )
}

export default GraphCanvas; 