/* Cytoscape styling for the attack graph.
 *
 * Kept out of GraphCanvas so the component stays about data and lifecycle.
 *
 * Encoding:
 *   shape  -> entity type   (primary — works without colour)
 *   colour -> entity type   (backs up the shape; cool = internal, warm = external)
 *   size   -> degree        (how many things this entity connects to)
 *
 * Colours come from CSS custom properties so the graph follows the light/dark
 * theme rather than carrying its own palette.
 */

const SHAPE = {
    Host:      "round-rectangle",
    User:      "ellipse",
    Process:   "round-triangle",
    IP:        "hexagon",
    Domain:    "round-diamond",
    URL:       "round-tag",
    Technique: "star",
};

const TOKEN = {
    Host:      "--g-host",
    User:      "--g-user",
    Process:   "--g-process",
    IP:        "--g-ip",
    Domain:    "--g-domain",
    URL:       "--g-url",
    Technique: "--g-technique",
};

export const NODE_TYPES = Object.keys(SHAPE);

export function readToken(name, fallback = "#888") {
    const value = getComputedStyle(document.documentElement)
        .getPropertyValue(name)
        .trim();
    return value || fallback;
}

export function buildGraphStyle() {
    const css = getComputedStyle(document.documentElement);
    const v = (name, fallback) => css.getPropertyValue(name).trim() || fallback;

    const text = v("--text", "#e6e9ed");
    const faint = v("--faint", "#6a727c");
    const surface = v("--surface", "#0e1013");
    const edge = v("--g-edge", "#39414b");
    const edgeHl = v("--g-edge-hl", "#8b7cf6");
    const mono = v("--mono", "monospace");

    const perType = NODE_TYPES.map(type => ({
        selector: `node[type = "${type}"]`,
        style: {
            "shape": SHAPE[type],
            "background-color": v(TOKEN[type], "#888"),
        },
    }));

    return [
        {
            selector: "node",
            style: {
                "width": 30,
                "height": 30,
                "border-width": 2,
                "border-color": surface,
                "label": "data(label)",
                "color": text,
                "font-family": mono,
                "font-size": 10,
                "text-valign": "bottom",
                "text-halign": "center",
                "text-margin-y": 6,
                "text-max-width": 130,
                "text-wrap": "ellipsis",
                "min-zoomed-font-size": 7,
                "transition-property": "opacity, border-color, border-width",
                "transition-duration": "140ms",
            },
        },
        // size by how many things this entity connects to. Separate rule so a
        // node without a degree still gets the base style above.
        {
            selector: "node[degree]",
            style: {
                "width": "mapData(degree, 1, 8, 26, 56)",
                "height": "mapData(degree, 1, 8, 26, 56)",
            },
        },
        ...perType,
        {
            selector: "edge",
            style: {
                "width": 1.4,
                "line-color": edge,
                "target-arrow-color": edge,
                "target-arrow-shape": "triangle",
                "arrow-scale": 0.75,
                "curve-style": "bezier",
                "color": faint,
                "font-family": mono,
                "font-size": 9,
                "text-rotation": "autorotate",
                "text-background-color": surface,
                "text-background-opacity": 1,
                "text-background-padding": 2,
                "transition-property": "opacity, line-color, width",
                "transition-duration": "140ms",
            },
        },

        /* ---- interaction states ---- */

        // everything outside the selected neighbourhood. Dimmed enough to push
        // it back, not so far that you lose the shape of the wider graph.
        {
            selector: ".faded",
            style: { "opacity": 0.32, "text-opacity": 0.22 },
        },
        // the hovered node and its direct neighbours
        {
            selector: "node.hl",
            style: { "border-color": edgeHl, "border-width": 3 },
        },
        {
            selector: "edge.hl",
            style: {
                "line-color": edgeHl,
                "target-arrow-color": edgeHl,
                "width": 2,
                "label": "data(type)",   // edge labels only while hovering
                "z-index": 10,
            },
        },
        {
            selector: "node:selected",
            style: { "border-color": edgeHl, "border-width": 3 },
        },
    ];
}

/* Clicking a node highlights it and its direct neighbours and fades the rest.
 * Deliberately on click, not hover — the graph shouldn't flicker as the
 * pointer crosses it, and a held selection is what you want while reading.
 * Listeners die with the cy instance on destroy. */
export function attachGraphInteractions(cy) {
    const clear = () => cy.elements().removeClass("faded").removeClass("hl");

    cy.on("tap", "node", evt => {
        const near = evt.target.closedNeighborhood();
        clear();
        cy.elements().difference(near).addClass("faded");
        near.addClass("hl");
    });

    // tapping empty canvas drops the selection
    cy.on("tap", evt => {
        if (evt.target === cy) {
            clear();
            cy.elements().unselect();
        }
    });

    // the canvas itself pans, so it gets a grab hand; nodes are clickable, so
    // they get a pointer. Clearing the inline style hands it back to the CSS.
    const container = cy.container();
    if (container) {
        cy.on("mouseover", "node", () => { container.style.cursor = "pointer"; });
        cy.on("mouseout", "node", () => { container.style.cursor = ""; });
        cy.on("grabon", () => { container.style.cursor = "grabbing"; });
        cy.on("freeon", () => { container.style.cursor = ""; });
    }
}

export { SHAPE, TOKEN };
