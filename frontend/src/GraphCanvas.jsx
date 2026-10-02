import { useRef, useEffect, useState }  from 'react'
import cytoscape from 'cytoscape'
import { Maximize2, Minimize2 } from 'lucide-react'
import { buildGraphStyle, attachGraphInteractions, NODE_TYPES, TOKEN } from './graphStyle'

function GraphCanvas() {
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
        fetch("http://localhost:8000/graph")
        .then(res => res.json())
        .then(data => setGraph(data))
        .catch(err => setError(err.message))
        .finally(() => setLoading(false))
    }, [])

    // adding another useEffect to render the graph once the data arrives
    useEffect(() => {
        if (!containerRef.current || graph.nodes.length == 0) return 

        // node size is driven by how many things it connects to. Count it here
        // rather than after cytoscape is built, because the stylesheet reads
        // `degree` the moment the elements are added.
        const degree = {}
        graph.edges.forEach(e => {
            degree[e.source] = (degree[e.source] || 0) + 1
            degree[e.target] = (degree[e.target] || 0) + 1
        })

        const cy = cytoscape({
            container: containerRef.current,
            elements: [
                ...graph.nodes.map(n => ({data: {...n, degree: degree[n.id] || 0}})),
                ...graph.edges.map(e => ({data: e})),
            ],
            style: buildGraphStyle(),
            minZoom: 0.3,
            maxZoom: 2.5,
        })

        // held in a variable so the cleanup can stop it — cose keeps a
        // requestAnimationFrame loop alive that would otherwise fire against a
        // destroyed instance when StrictMode remounts
        const layout = cy.layout({
            name: "cose",
            animate: false,
            padding: 40,
            nodeRepulsion: 14000,
            idealEdgeLength: 95,
            nodeOverlap: 24,
        })
        layout.run()

        attachGraphInteractions(cy)
        cyRef.current = cy

        // the palette lives in CSS variables, so re-apply the stylesheet when
        // the dashboard theme flips
        const observer = new MutationObserver(() => cy.style(buildGraphStyle()))
        observer.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ["data-theme"],
        })

        return () => {
            observer.disconnect()
            layout.stop()
            cy.destroy()
            cyRef.current = null
        }
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
        <div className={`graph ${fullscreen ? "fullscreen" : ""}`}>
            <div className="graph-legend">
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
            </div>

            {error && <div className="error">Could not load the graph — {error}</div>}

            <div ref={containerRef} className="graph-canvas" />
        </div>
    )
}

export default GraphCanvas; 