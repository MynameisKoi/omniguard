/* Small hand-rolled SVG charts.
 *
 * No charting library on purpose — these are three simple shapes and a
 * dependency would be heavier than the code it replaces. Colours come from
 * CSS custom properties so everything follows the light/dark theme.
 */

import { useState } from 'react';

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
    const [hover, setHover] = useState(null);
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

    const onMove = (e) => {
        const rect = e.currentTarget.getBoundingClientRect();
        const relX = ((e.clientX - rect.left) / rect.width) * width; // into viewBox space
        let idx = Math.round(((relX - padLeft) / plotW) * (data.length - 1));
        setHover(Math.max(0, Math.min(data.length - 1, idx)));
    };

    const hd = hover != null ? data[hover] : null;
    const hTotal = hd ? (hd.critical || 0) + (hd.high || 0) + (hd.medium || 0) + (hd.low || 0) : 0;

    return (
        <div className="area-wrap">
            <svg className="area-chart" viewBox={`0 0 ${width} ${height}`} role="img"
                 preserveAspectRatio="none"
                 onMouseMove={onMove} onMouseLeave={() => setHover(null)}
                 aria-label="Alert volume over time by severity">
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

                {hover != null && (
                    <>
                        <line x1={x(hover)} x2={x(hover)} y1={0} y2={plotH} className="area-cursor" />
                        {SEVERITIES.map(sev => (data[hover][sev] > 0
                            ? <circle key={sev} cx={x(hover)} cy={y(tops[hover][sev])} r="3" className={`area-dot sev-${sev}`} />
                            : null))}
                    </>
                )}

                {data.map((d, i) =>
                    i % 4 === 0 ? (
                        <text key={d.label} x={x(i)} y={height - 4} className="chart-tick" textAnchor="middle">
                            {d.label}
                        </text>
                    ) : null
                )}
            </svg>

            {hd && (
                <div className="area-tooltip" style={{ left: `${Math.max(13, Math.min(87, (x(hover) / width) * 100))}%` }}>
                    <div className="att-label">{hd.label}</div>
                    {SEVERITIES.map(sev => (
                        <div className="att-row" key={sev}>
                            <span className={`att-dot sev-${sev}`} />
                            <span className="att-key">{sev}</span>
                            <span className="att-n">{hd[sev] || 0}</span>
                        </div>
                    ))}
                    <div className="att-total">total <b>{hTotal}</b></div>
                </div>
            )}
        </div>
    );
}

/* ---- labelled horizontal bar, used for techniques and assets ---- */

export function BarRow({ label, sub, value, max, tone, onClick }) {
    const pct = max ? Math.max(2, (value / max) * 100) : 0;
    const clickable = typeof onClick === "function";
    return (
        <div
            className={`barrow ${clickable ? "clickable" : ""}`}
            onClick={onClick}
            role={clickable ? "button" : undefined}
            tabIndex={clickable ? 0 : undefined}
            onKeyDown={clickable ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(); } } : undefined}
            title={clickable ? `Filter by ${label}` : undefined}
        >
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

/* ---- pie chart: filled wedges + legend, for a few categories ---- */

export function PieChart({ slices, size = 128, onSlice, activeKey }) {
    const sum = slices.reduce((a, s) => a + s.n, 0);
    const clickable = typeof onSlice === "function";
    if (sum === 0) return <div className="empty">No data yet.</div>;

    const cx = size / 2, cy = size / 2, r = size / 2 - 2;
    let angle = -Math.PI / 2;
    const wedges = slices.filter(s => s.n > 0).map(s => {
        const frac = s.n / sum;
        const a0 = angle, a1 = angle + frac * 2 * Math.PI;
        angle = a1;
        const large = frac > 0.5 ? 1 : 0;
        const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
        const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
        // a single full-circle slice can't be drawn as an arc; draw a circle instead
        const d = frac >= 0.999
            ? `M ${cx} ${cy - r} A ${r} ${r} 0 1 1 ${cx - 0.01} ${cy - r} Z`
            : `M ${cx} ${cy} L ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)} Z`;
        return { ...s, d };
    });

    return (
        <div className="pie-wrap">
            <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} className="pie" role="img">
                {wedges.map(w => (
                    <path
                        key={w.key}
                        d={w.d}
                        className={`pie-slice ${clickable ? "clickable" : ""} ${activeKey && activeKey !== w.key ? "dim" : ""}`}
                        style={{ fill: w.fill }}
                        onClick={clickable ? () => onSlice(w.key) : undefined}
                    >
                        <title>{`${w.key}: ${w.n}`}</title>
                    </path>
                ))}
            </svg>
            <div className="pie-legend">
                {slices.map(s => (
                    <div
                        className={`pie-row ${clickable ? "clickable" : ""} ${activeKey === s.key ? "active" : ""}`}
                        key={s.key}
                        onClick={clickable ? () => onSlice(s.key) : undefined}
                        role={clickable ? "button" : undefined}
                    >
                        <span className="pie-swatch" style={{ background: s.fill }} />
                        <span className="pie-key">{s.key}</span>
                        <span className="pie-n">{s.n}</span>
                        <span className="pie-pct">{Math.round((s.n / sum) * 100)}%</span>
                    </div>
                ))}
            </div>
        </div>
    );
}

/* ---- vertical bar / column chart ---- */

export function BarChart({ data, height = 160, onBar }) {
    const max = Math.max(1, ...data.map(d => d.value));
    const clickable = typeof onBar === "function";
    return (
        <div className="vbar-chart" style={{ height }}>
            {data.map((d, i) => (
                <div
                    className={`vbar-col ${clickable ? "clickable" : ""}`}
                    key={i}
                    onClick={clickable ? () => onBar(d) : undefined}
                    title={`${d.label}: ${d.value}`}
                >
                    <span className="vbar-val">{d.value}</span>
                    <div className="vbar-track">
                        <div className={`vbar ${d.tone ? `sev-${d.tone}` : ""}`} style={{ height: `${(d.value / max) * 100}%`, background: d.fill }} />
                    </div>
                    <span className="vbar-label">{d.label}</span>
                </div>
            ))}
        </div>
    );
}

/* ---- "this isn't real data yet" marker ---- */

export function SampleBadge({ note = "sample data" }) {
    return <span className="sample-badge" title="Placeholder — needs a backend endpoint">{note}</span>;
}
