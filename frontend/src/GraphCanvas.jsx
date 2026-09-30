import { useRef, useEffect, useState } from 'react'
import cytoscape from 'cytoscape'

// Node colour palette — one colour per entity label.
// These are HSL values that work on both dark and light backgrounds.
const LABEL_COLOUR = {
    Host:      "#4f9cf9",  // blue
    IP:        "#a78bfa",  // violet
    Domain:    "#fb923c",  // orange
    URL:       "#4ade80",  // green
    Process:   "#f87171",  // red
    User:      "#2dd4bf",  // teal
    Technique: "#facc15",  // yellow
};

const DEFAULT_COLOUR = "#94a3b8";

// Cytoscape stylesheet
const STYLE = [
    {
        selector: "node",
        style: {
            "background-color": (ele) => LABEL_COLOUR[ele.data("label")] ?? DEFAULT_COLOUR,
            "label": "data(display)",
            "color": "#f1f5f9",
            "font-size": "10px",
            "text-valign": "bottom",
            "text-margin-y": "4px",
            "text-outline-color": "#0f172a",
            "text-outline-width": "2px",
            "width": 28,
            "height": 28,
            "border-width": 2,
            "border-color": "#1e293b",
        },
    },
    {
        selector: "node[label='Host']",
        style: { width: 36, height: 36, "font-size": "11px", "font-weight": "bold" },
    },
    {
        selector: "edge",
        style: {
            "width": 1.5,
            "line-color": "#334155",
            "target-arrow-color": "#475569",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "label": "data(type)",
            "font-size": "8px",
            "color": "#64748b",
            "text-rotation": "autorotate",
            "text-outline-color": "#0f172a",
            "text-outline-width": "1px",
        },
    },
    {
        selector: ":selected",
        style: {
            "border-color": "#f8fafc",
            "border-width": 3,
            "line-color": "#94a3b8",
        },
    },
];

/**
 * GraphCanvas — renders the OmniGuard entity graph using Cytoscape.js.
 *
 * Props:
 *   hostname  (string|null)  — if set, fetches GET /graph/host/{hostname}
 *                              instead of the full GET /graph.
 *   height    (string)       — CSS height string, default "460px".
 */
function GraphCanvas({ hostname = null, height = "460px" }) {
    const containerRef = useRef(null);
    const cyRef        = useRef(null);
    const [status, setStatus]   = useState("loading"); // loading | ok | empty | error
    const [tooltip, setTooltip] = useState(null);      // { label, x, y }
    const [nodeCount, setNodeCount] = useState(0);
    const [edgeCount, setEdgeCount] = useState(0);

    useEffect(() => {
        let cancelled = false;
        setStatus("loading");

        const url = hostname
            ? `http://localhost:8000/graph/host/${encodeURIComponent(hostname)}`
            : "http://localhost:8000/graph";

        fetch(url)
            .then(r => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return r.json();
            })
            .then(({ nodes, edges }) => {
                if (cancelled) return;

                if (!nodes.length) {
                    setStatus("empty");
                    return;
                }

                setNodeCount(nodes.length);
                setEdgeCount(edges.length);

                // Destroy previous instance if the component re-renders
                if (cyRef.current) {
                    cyRef.current.destroy();
                    cyRef.current = null;
                }

                const cy = cytoscape({
                    container: containerRef.current,
                    elements: [...nodes, ...edges],
                    style: STYLE,
                    layout: {
                        name: "cose",
                        animate: true,
                        animationDuration: 600,
                        nodeRepulsion: 6000,
                        gravity: 0.4,
                        idealEdgeLength: 80,
                        randomize: false,
                        fit: true,
                        padding: 24,
                    },
                    minZoom: 0.3,
                    maxZoom: 4,
                    wheelSensitivity: 0.3,
                });

                // Tooltip on hover
                cy.on("mouseover", "node", (evt) => {
                    const d = evt.target.data();
                    const pos = evt.renderedPosition;
                    const key = d.hostname || d.username || d.address || d.domain_name || d.url || d.process_id || d.id;
                    setTooltip({ label: `${d.label}: ${key}`, x: pos.x, y: pos.y });
                });
                cy.on("mouseout", "node", () => setTooltip(null));

                cyRef.current = cy;
                setStatus("ok");
            })
            .catch(err => {
                if (!cancelled) {
                    console.error("GraphCanvas fetch error:", err);
                    setStatus("error");
                }
            });

        return () => {
            cancelled = true;
            // Don't destroy on cleanup — only destroy when re-fetching (above).
        };
    }, [hostname]);

    // Clean up on unmount
    useEffect(() => {
        return () => {
            if (cyRef.current) {
                cyRef.current.destroy();
                cyRef.current = null;
            }
        };
    }, []);

    return (
        <div style={{ position: "relative", height, width: "100%" }}>
            {/* The Cytoscape mount target — always rendered so the ref is stable */}
            <div
                ref={containerRef}
                style={{
                    height: "100%",
                    width: "100%",
                    borderRadius: "6px",
                    background: "var(--surface)",
                    display: status === "ok" ? "block" : "none",
                }}
            />

            {/* Legend — overlaid top-right */}
            {status === "ok" && (
                <div style={{
                    position: "absolute", top: 10, right: 10,
                    background: "var(--surface-raised, #1e293b)",
                    border: "1px solid var(--border, #334155)",
                    borderRadius: 6, padding: "8px 12px",
                    fontSize: 10, lineHeight: 1.7, userSelect: "none",
                }}>
                    {Object.entries(LABEL_COLOUR).map(([lbl, col]) => (
                        <div key={lbl} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <span style={{ width: 9, height: 9, borderRadius: "50%", background: col, display: "inline-block" }} />
                            <span style={{ color: "var(--text-dim, #94a3b8)" }}>{lbl}</span>
                        </div>
                    ))}
                    <div style={{ marginTop: 6, color: "var(--text-dim, #94a3b8)", borderTop: "1px solid var(--border, #334155)", paddingTop: 4 }}>
                        {nodeCount} nodes · {edgeCount} edges
                    </div>
                </div>
            )}

            {/* Hover tooltip */}
            {tooltip && (
                <div style={{
                    position: "absolute",
                    left: tooltip.x + 12, top: tooltip.y - 8,
                    background: "#0f172a", border: "1px solid #334155",
                    borderRadius: 4, padding: "3px 8px",
                    fontSize: 11, color: "#f1f5f9",
                    pointerEvents: "none", whiteSpace: "nowrap",
                }}>
                    {tooltip.label}
                </div>
            )}

            {/* Loading / empty / error overlays */}
            {status === "loading" && (
                <div style={overlayStyle}>
                    <span style={{ color: "var(--text-dim, #94a3b8)", fontSize: 13 }}>Loading graph…</span>
                </div>
            )}
            {status === "empty" && (
                <div style={overlayStyle}>
                    <span style={{ fontSize: 28, marginBottom: 8 }}>⬡</span>
                    <span style={{ color: "var(--text-dim, #94a3b8)", fontSize: 13 }}>
                        Graph is empty — post alerts at <code>localhost:8000/docs</code>
                    </span>
                </div>
            )}
            {status === "error" && (
                <div style={overlayStyle}>
                    <span style={{ color: "#f87171", fontSize: 13 }}>Could not load graph — is the backend running?</span>
                </div>
            )}
        </div>
    );
}

const overlayStyle = {
    height: "100%",
    width: "100%",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: 6,
    background: "var(--surface)",
    border: "1px solid var(--border, #334155)",
    gap: 8,
};

export default GraphCanvas;