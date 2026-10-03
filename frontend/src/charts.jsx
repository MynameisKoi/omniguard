/* Small hand-rolled SVG charts.
 *
 * No charting library on purpose — these are three simple shapes and a
 * dependency would be heavier than the code it replaces. Colours come from
 * CSS custom properties so everything follows the light/dark theme.
 */

const SEVERITIES = ["critical", "high", "medium", "low"];

/* ---- sparkline: one line, no axes, meant to be read as a trend ---- */

export function Sparkline({ values, stroke = "var(--accent)", width = 110, height = 30 }) {
    if (!values || values.length < 2) return null;

    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min || 1;

    const x = i => (i / (values.length - 1)) * width;
    const y = v => height - ((v - min) / span) * (height - 4) - 2;

    const line = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    const area = `${line} ${width},${height} 0,${height}`;
    const id = `spark-${stroke.replace(/[^a-z0-9]/gi, "")}`;

    return (
        <svg className="spark" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
            <defs>
                <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={stroke} stopOpacity="0.28" />
                    <stop offset="100%" stopColor={stroke} stopOpacity="0" />
                </linearGradient>
            </defs>
            <polygon points={area} fill={`url(#${id})`} />
            <polyline points={line} fill="none" stroke={stroke} strokeWidth="1.5"
                      strokeLinejoin="round" strokeLinecap="round" />
        </svg>
    );
}

/* ---- stacked area over time, one band per severity ---- */

export function StackedArea({ data, height = 190 }) {
    if (!data || data.length === 0) return null;

    const width = 640;
    const padLeft = 26;
    const padBottom = 18;
    const plotW = width - padLeft;
    const plotH = height - padBottom;

    // running totals per bucket give each band its upper edge
    const tops = data.map(d => {
        let running = 0;
        const out = {};
        for (const sev of SEVERITIES) {
            running += d[sev] || 0;
            out[sev] = running;
        }
        out._total = running;
        return out;
    });

    const max = Math.max(...tops.map(t => t._total), 1);
    const niceMax = Math.ceil(max / 20) * 20 || 20;

    const x = i => padLeft + (i / (data.length - 1)) * plotW;
    const y = v => plotH - (v / niceMax) * plotH;

    // bands are drawn largest-first so smaller ones sit on top
    const bands = [...SEVERITIES].reverse().map(sev => {
        const upper = tops.map((t, i) => `${x(i).toFixed(1)},${y(t[sev]).toFixed(1)}`);
        const points = [...upper, `${x(data.length - 1).toFixed(1)},${plotH}`, `${padLeft},${plotH}`];
        return { sev, points: points.join(" ") };
    });

    const gridLines = [0, 0.25, 0.5, 0.75, 1].map(f => ({
        y: plotH - f * plotH,
        value: Math.round(niceMax * f),
    }));

    return (
        <svg className="area-chart" viewBox={`0 0 ${width} ${height}`} role="img"
             aria-label="Alert volume over the last 24 hours by severity">
            {gridLines.map(g => (
                <g key={g.value}>
                    <line x1={padLeft} x2={width} y1={g.y} y2={g.y} className="chart-grid" />
                    <text x={padLeft - 6} y={g.y + 3} className="chart-tick" textAnchor="end">
                        {g.value}
                    </text>
                </g>
            ))}

            {bands.map(b => (
                <polygon key={b.sev} points={b.points} className={`area-band sev-${b.sev}`} />
            ))}

            {data.map((d, i) =>
                i % 4 === 0 ? (
                    <text key={d.label} x={x(i)} y={height - 4} className="chart-tick" textAnchor="middle">
                        {d.label}
                    </text>
                ) : null
            )}
        </svg>
    );
}

/* ---- labelled horizontal bar, used for techniques and assets ---- */

export function BarRow({ label, sub, value, max, tone }) {
    const pct = max ? Math.max(2, (value / max) * 100) : 0;
    return (
        <div className="barrow">
            <span className="barrow-label">
                {label}
                {sub && <em>{sub}</em>}
            </span>
            <span className="barrow-track">
                <span className={`barrow-fill ${tone ? `sev-${tone}` : ""}`} style={{ width: `${pct}%` }} />
            </span>
            <span className="barrow-value">{value}</span>
        </div>
    );
}

/* ---- "this isn't real data yet" marker ---- */

export function SampleBadge({ note = "sample data" }) {
    return <span className="sample-badge" title="Placeholder — needs a backend endpoint">{note}</span>;
}
