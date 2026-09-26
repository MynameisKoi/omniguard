import "./App.css"
import { useState, useEffect } from 'react';

const SEVERITIES = ["critical", "high", "medium", "low"];
const SOURCES = ["verifyeye", "spectrac2", "manual"];

const MITRE = {
    T1566: "Phishing",
    T1071: "Application layer protocol",
    T1078: "Valid accounts",
    T1021: "Remote services",
    T1056: "Input capture",
};

const ENGINE_ROLE = {
    verifyeye: "Phishing pages, credential forms",
    spectrac2: "Encrypted C2 beaconing",
    manual: "Analyst-submitted",
};

const pct = (n, total) => `${total ? (n / total) * 100 : 0}%`;

function App() {
    // adding the state for alerts
    const [alerts, setAlerts] = useState([])

    // adding the state for error
    const [error, setError] = useState(null)

    // ui state
    const [navOpen, setNavOpen] = useState(true)
    const [page, setPage] = useState("alerts")      // which nav section
    const [selectedId, setSelectedId] = useState(null)
    const [filter, setFilter] = useState(null)

    // we will fetch the alerts from backend
    useEffect(() => {
        fetch("http://localhost:8000/alerts")
        .then((res) => res.json())
        .then((data) => setAlerts(data))
        .catch(err => setError(err.message))
    }, []);

    const countOf = (sev) => alerts.filter(a => a.severity === sev).length;

    // { value: count } for any alert field, ignoring nulls
    const countBy = (field) => alerts.reduce((acc, a) => {
        const v = a[field];
        if (v) acc[v] = (acc[v] || 0) + 1;
        return acc;
    }, {});

    // [[value, count], ...] sorted high to low
    const topN = (field, n) =>
        Object.entries(countBy(field)).sort((x, y) => y[1] - x[1]).slice(0, n);

    const countDistinct = (field) => Object.keys(countBy(field)).length;
    const visible = filter ? alerts.filter(a => a.severity === filter) : alerts;
    const selected = alerts.find(a => a.alert_id === selectedId);
    const maxCount = Math.max(1, ...SEVERITIES.map(countOf));

    const NAV = [
        { group: "Monitor", items: [
            { id: "overview", icon: "▤", label: "Overview" },
            { id: "alerts",   icon: "⚑", label: "Alerts", count: alerts.length },
            { id: "graph",    icon: "⬡", label: "Attack graph" },
        ]},
        { group: "Inventory", items: [
            { id: "hosts",  icon: "▣", label: "Hosts" },
            { id: "users",  icon: "◍", label: "Users" },
        ]},
        { group: "System", items: [
            { id: "engines",  icon: "◈", label: "Engines" },
            { id: "settings", icon: "⚙", label: "Settings" },
        ]},
    ];

    const openAlert = (id) => { setSelectedId(id); setPage("alert-detail"); };

    return (
        <div className="shell">

            {/* ─── left nav ─────────────────────────── */}
            <nav className={`nav ${navOpen ? "" : "collapsed"}`}>
                <div className="nav-head">
                    <button className="burger" onClick={() => setNavOpen(!navOpen)} aria-label="Toggle navigation">
                        <span />
                    </button>
                    {navOpen && <div className="nav-name">OmniGuard <em>SOC</em></div>}
                </div>

                {NAV.map(section => (
                    <div className="nav-group" key={section.group}>
                        <div className="nav-group-label">{section.group}</div>
                        {section.items.map(item => (
                            <button
                                key={item.id}
                                className={`nav-item ${page === item.id || (page === "alert-detail" && item.id === "alerts") ? "active" : ""}`}
                                onClick={() => { setPage(item.id); setSelectedId(null); }}
                                title={item.label}
                            >
                                <span className="nav-icon">{item.icon}</span>
                                {navOpen && <span>{item.label}</span>}
                                {navOpen && item.count != null && <span className="nav-count">{item.count}</span>}
                            </button>
                        ))}
                    </div>
                ))}

                <div className="nav-foot">
                    <div className="avatar">AM</div>
                    {navOpen && (
                        <div className="who">
                            <b>A. Maharjan</b>
                            <span>Tier 2 analyst</span>
                        </div>
                    )}
                </div>
            </nav>

            {/* ─── main column ──────────────────────── */}
            <div className="main">

                <header className="topbar">
                    <div className="crumb">
                        {page === "alert-detail" ? (
                            <>
                                <button className="back" onClick={() => setPage("alerts")}>Alerts</button>
                                <span className="slash">/</span>
                                {selected ? selected.event_type : "detail"}
                            </>
                        ) : (
                            NAV.flatMap(s => s.items).find(i => i.id === page)?.label ?? "Alerts"
                        )}
                    </div>
                    <div className="grow" />
                    <input className="search" placeholder="Search host, user, domain…" />
                    <span className="clock">{new Date().toLocaleDateString()}</span>
                </header>

                <div className="content">

                    {error && <div className="error">Could not reach the backend — {error}</div>}

                    {/* ── alerts list ── */}
                    {page === "alerts" && (
                        <>
                            <div className="stats">
                                <div className="stat">
                                    <div className="stat-label">Total</div>
                                    <div className="stat-value">{alerts.length}</div>
                                </div>
                                <div className="stat">
                                    <div className="stat-label">Critical</div>
                                    <div className="stat-value critical">{countOf("critical")}</div>
                                </div>
                                <div className="stat">
                                    <div className="stat-label">High</div>
                                    <div className="stat-value high">{countOf("high")}</div>
                                </div>
                                <div className="stat">
                                    <div className="stat-label">Untriaged</div>
                                    <div className="stat-value">{alerts.filter(a => a.status === "new").length}</div>
                                </div>
                                <div className="stat">
                                    <div className="stat-label">Engines</div>
                                    <div className="stat-value good">2</div>
                                </div>
                            </div>

                            <div className="panel">
                                <div className="filterbar">
                                    <span className="label">Severity</span>
                                    <button className={`chip ${filter === null ? "on" : ""}`} onClick={() => setFilter(null)}>all</button>
                                    {SEVERITIES.map(sev => (
                                        <button key={sev} className={`chip ${filter === sev ? "on" : ""}`} onClick={() => setFilter(sev)}>
                                            {sev}
                                        </button>
                                    ))}
                                </div>

                                {visible.length === 0 ? (
                                    <div className="empty">
                                        No alerts. Post one at <code>localhost:8000/docs</code>.
                                    </div>
                                ) : (
                                    <table className="table">
                                        <thead>
                                            <tr>
                                                <th>Severity</th>
                                                <th>Event</th>
                                                <th>Host</th>
                                                <th>User</th>
                                                <th className="td-wide">Domain</th>
                                                <th>Source</th>
                                                <th>Status</th>
                                                <th>Time</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {visible.map(a => (
                                                <tr key={a.alert_id} onClick={() => openAlert(a.alert_id)}>
                                                    <td><span className={`sev ${a.severity}`}>{a.severity}</span></td>
                                                    <td className="td-mono">{a.event_type}</td>
                                                    <td className="td-mono">{a.host}</td>
                                                    <td className={`td-mono ${a.user ? "td-dim" : "td-faint"}`}>{a.user || "—"}</td>
                                                    <td className={`td-mono td-wide ${a.domain ? "td-dim" : "td-faint"}`}>{a.domain || "—"}</td>
                                                    <td><span className="tag">{a.source}</span></td>
                                                    <td className="td-dim">{a.status}</td>
                                                    <td className="td-mono td-faint">
                                                        {new Date(a.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                )}
                            </div>
                        </>
                    )}

                    {/* ── single alert ── */}
                    {page === "alert-detail" && selected && (
                        <>
                            <div className="detail-title">
                                <span className={`sev ${selected.severity}`}>{selected.severity}</span>
                                <h2>{selected.event_type}</h2>
                                <span className="tag">{selected.source}</span>
                                <span className="tag">{selected.status}</span>
                                <span className="when">{new Date(selected.timestamp).toLocaleString()}</span>
                            </div>

                            <div className="split">
                                <div>
                                    {selected.description && <p className="note">{selected.description}</p>}

                                    <div className="panel">
                                        <div className="panel-head">
                                            <span className="panel-title">Attack graph</span>
                                            <span className="panel-note">placeholder — React Flow</span>
                                        </div>
                                        <div className="panel-body">
                                            <div className="canvas">
                                                <span className="hint">neighbourhood of {selected.host}</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div className="panel">
                                    <div className="panel-head">
                                        <span className="panel-title">Details</span>
                                    </div>
                                    <div className="panel-body">
                                        <div className="kv">
                                            <KV k="Host"       v={selected.host} />
                                            <KV k="User"       v={selected.user} />
                                            <KV k="Domain"     v={selected.domain} />
                                            <KV k="Source IP"  v={selected.src_ip} />
                                            <KV k="Dest IP"    v={selected.dst_ip} />
                                            <KV k="MITRE"      v={selected.mitre_technique} />
                                            <KV k="Confidence" v={selected.confidence != null ? `${Math.round(selected.confidence * 100)}%` : null} />
                                            <KV k="Alert ID"   v={selected.alert_id} />
                                        </div>
                                        <div className="actions">
                                            <button className="btn">Mark triaged</button>
                                            <button className="btn danger">Isolate host</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </>
                    )}

                    {/* ── overview ── */}
                    {page === "overview" && (
                        <>
                            <div className="stats">
                                <div className="stat">
                                    <div className="stat-label">Total alerts</div>
                                    <div className="stat-value">{alerts.length}</div>
                                </div>
                                <div className="stat">
                                    <div className="stat-label">Critical</div>
                                    <div className="stat-value critical">{countOf("critical")}</div>
                                </div>
                                <div className="stat">
                                    <div className="stat-label">Hosts affected</div>
                                    <div className="stat-value">{countDistinct("host")}</div>
                                </div>
                                <div className="stat">
                                    <div className="stat-label">Domains seen</div>
                                    <div className="stat-value">{countDistinct("domain")}</div>
                                </div>
                                <div className="stat">
                                    <div className="stat-label">Untriaged</div>
                                    <div className="stat-value high">{alerts.filter(a => a.status === "new").length}</div>
                                </div>
                            </div>

                            <div className="cols">
                                {/* severity — status palette, each bar directly labelled */}
                                <section className="panel">
                                    <div className="panel-head">
                                        <span className="panel-title">Severity distribution</span>
                                        <span className="panel-note">{alerts.length} alerts</span>
                                    </div>
                                    <div className="panel-body">
                                        <div className="rank">
                                            {SEVERITIES.map(sev => (
                                                <div className="rank-row" key={sev} title={`${sev}: ${countOf(sev)}`}>
                                                    <span className="rank-key">{sev}</span>
                                                    <span className="rank-n">{countOf(sev)}</span>
                                                    <span className="rank-track">
                                                        <span
                                                            className={`rank-fill sev-${sev}`}
                                                            style={{ width: pct(countOf(sev), maxCount) }}
                                                        />
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </section>

                                {/* engines — part-to-whole, legend + direct labels */}
                                <section className="panel">
                                    <div className="panel-head">
                                        <span className="panel-title">Detections by engine</span>
                                    </div>
                                    <div className="panel-body">
                                        <div className="stack">
                                            {SOURCES.map(src => (
                                                countBy("source")[src] ? (
                                                    <span
                                                        key={src}
                                                        className={`stack-seg eng-${src}`}
                                                        style={{ width: pct(countBy("source")[src], alerts.length) }}
                                                        title={`${src}: ${countBy("source")[src]}`}
                                                    />
                                                ) : null
                                            ))}
                                        </div>
                                        <div className="legend">
                                            {SOURCES.map(src => {
                                                const n = countBy("source")[src] || 0;
                                                return (
                                                    <div className="legend-row" key={src}>
                                                        <span className={`swatch eng-${src}`} />
                                                        <span className="legend-key">{src}</span>
                                                        <span className="legend-n">{n}</span>
                                                        <span className="legend-pct">
                                                            {alerts.length ? Math.round((n / alerts.length) * 100) : 0}%
                                                        </span>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                </section>
                            </div>

                            <div className="cols">
                                {/* magnitude on nominal categories -> one hue for every bar */}
                                <section className="panel">
                                    <div className="panel-head">
                                        <span className="panel-title">Most affected hosts</span>
                                    </div>
                                    <div className="panel-body">
                                        <RankList data={topN("host", 6)} />
                                    </div>
                                </section>

                                <section className="panel">
                                    <div className="panel-head">
                                        <span className="panel-title">Most contacted domains</span>
                                    </div>
                                    <div className="panel-body">
                                        <RankList data={topN("domain", 6)} />
                                    </div>
                                </section>
                            </div>

                            <div className="cols">
                                <section className="panel">
                                    <div className="panel-head">
                                        <span className="panel-title">MITRE techniques</span>
                                    </div>
                                    <div className="panel-body">
                                        {topN("mitre_technique", 6).length === 0 ? (
                                            <div className="empty">No techniques mapped yet.</div>
                                        ) : (
                                            <table className="mini">
                                                <thead>
                                                    <tr><th>ID</th><th>Technique</th><th className="num">Alerts</th></tr>
                                                </thead>
                                                <tbody>
                                                    {topN("mitre_technique", 6).map(([id, n]) => (
                                                        <tr key={id}>
                                                            <td className="mono">{id}</td>
                                                            <td>{MITRE[id] || "—"}</td>
                                                            <td className="num">{n}</td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        )}
                                    </div>
                                </section>

                                <section className="panel">
                                    <div className="panel-head">
                                        <span className="panel-title">Recent activity</span>
                                        <span className="panel-note">last {Math.min(6, alerts.length)}</span>
                                    </div>
                                    <div className="panel-body">
                                        {alerts.length === 0 ? (
                                            <div className="empty">Nothing yet.</div>
                                        ) : (
                                            <div className="feed">
                                                {[...alerts]
                                                    .sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp))
                                                    .slice(0, 6)
                                                    .map(a => (
                                                        <div className="feed-row" key={a.alert_id} onClick={() => openAlert(a.alert_id)}>
                                                            <span className={`feed-bar ${a.severity}`} />
                                                            <span className="feed-main">
                                                                <span className="feed-title">{a.event_type}</span>
                                                                <span className="feed-sub">{a.host} · {a.source}</span>
                                                            </span>
                                                            <span className="feed-time">
                                                                {new Date(a.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                                            </span>
                                                        </div>
                                                    ))}
                                            </div>
                                        )}
                                    </div>
                                </section>
                            </div>
                        </>
                    )}

                    {/* ── attack graph ── */}
                    {page === "graph" && (
                        <div className="panel">
                            <div className="panel-head">
                                <span className="panel-title">Attack graph</span>
                                <span className="panel-note">placeholder — needs GET /graph</span>
                            </div>
                            <div className="panel-body">
                                <div className="canvas" style={{ height: "420px" }}>
                                    <span className="hint">
                                        {countDistinct("host")} hosts · {countDistinct("domain")} domains · {alerts.length} alerts in Neo4j
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* ── hosts ── */}
                    {page === "hosts" && (
                        <div className="panel">
                            <div className="panel-head">
                                <span className="panel-title">Hosts</span>
                                <span className="panel-note">{countDistinct("host")} seen</span>
                            </div>
                            {topN("host", 50).length === 0 ? (
                                <div className="empty">No hosts yet.</div>
                            ) : (
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>Hostname</th>
                                            <th>Worst severity</th>
                                            <th>Alerts</th>
                                            <th>Users</th>
                                            <th className="td-wide">Domains contacted</th>
                                            <th>Last seen</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {topN("host", 50).map(([host, n]) => {
                                            const mine = alerts.filter(a => a.host === host);
                                            const worst = SEVERITIES.find(s => mine.some(a => a.severity === s));
                                            const users = [...new Set(mine.map(a => a.user).filter(Boolean))];
                                            const domains = [...new Set(mine.map(a => a.domain).filter(Boolean))];
                                            const last = mine.map(a => new Date(a.timestamp)).sort((x, y) => y - x)[0];
                                            return (
                                                <tr key={host} onClick={() => { setFilter(null); setPage("alerts"); }}>
                                                    <td className="td-mono">{host}</td>
                                                    <td><span className={`sev ${worst}`}>{worst}</span></td>
                                                    <td className="td-mono td-dim">{n}</td>
                                                    <td className={`td-mono ${users.length ? "td-dim" : "td-faint"}`}>
                                                        {users.join(", ") || "—"}
                                                    </td>
                                                    <td className={`td-mono td-wide ${domains.length ? "td-dim" : "td-faint"}`}>
                                                        {domains.join(", ") || "—"}
                                                    </td>
                                                    <td className="td-mono td-faint">
                                                        {last.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    )}

                    {/* ── users ── */}
                    {page === "users" && (
                        <div className="panel">
                            <div className="panel-head">
                                <span className="panel-title">Users</span>
                                <span className="panel-note">{countDistinct("user")} seen</span>
                            </div>
                            {topN("user", 50).length === 0 ? (
                                <div className="empty">
                                    No users attributed yet. Network-only alerts carry no username.
                                </div>
                            ) : (
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>Account</th>
                                            <th>Worst severity</th>
                                            <th>Alerts</th>
                                            <th className="td-wide">Hosts used</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {topN("user", 50).map(([user, n]) => {
                                            const mine = alerts.filter(a => a.user === user);
                                            const worst = SEVERITIES.find(s => mine.some(a => a.severity === s));
                                            const hosts = [...new Set(mine.map(a => a.host))];
                                            return (
                                                <tr key={user}>
                                                    <td className="td-mono">{user}</td>
                                                    <td><span className={`sev ${worst}`}>{worst}</span></td>
                                                    <td className="td-mono td-dim">{n}</td>
                                                    <td className="td-mono td-dim td-wide">{hosts.join(", ")}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    )}

                    {/* ── engines ── */}
                    {page === "engines" && (
                        <div className="panel">
                            <div className="panel-head">
                                <span className="panel-title">Detection engines</span>
                            </div>
                            <table className="table">
                                <thead>
                                    <tr>
                                        <th>Engine</th>
                                        <th>Detects</th>
                                        <th>Alerts</th>
                                        <th>Last alert</th>
                                        <th className="td-wide">Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {SOURCES.map(src => {
                                        const mine = alerts.filter(a => a.source === src);
                                        const last = mine.map(a => new Date(a.timestamp)).sort((x, y) => y - x)[0];
                                        return (
                                            <tr key={src}>
                                                <td>
                                                    <span className="legend-row" style={{ display: "inline-grid", gridTemplateColumns: "9px auto", gap: "8px" }}>
                                                        <span className={`swatch eng-${src}`} />
                                                        <span className="td-mono">{src}</span>
                                                    </span>
                                                </td>
                                                <td className="td-dim">{ENGINE_ROLE[src]}</td>
                                                <td className="td-mono td-dim">{mine.length}</td>
                                                <td className="td-mono td-faint">
                                                    {last ? last.toLocaleString() : "—"}
                                                </td>
                                                <td className={`td-wide ${mine.length ? "td-dim" : "td-faint"}`}>
                                                    {mine.length ? "reporting" : "no alerts received"}
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {/* ── settings ── */}
                    {page === "settings" && (
                        <div className="cols">
                            <section className="panel">
                                <div className="panel-head"><span className="panel-title">Connections</span></div>
                                <div className="panel-body">
                                    <div className="kv">
                                        <KV k="API" v="http://localhost:8000" />
                                        <KV k="MongoDB" v="mongodb://localhost:27017 / omniguard" />
                                        <KV k="Neo4j" v="neo4j://localhost:7687" />
                                        <KV k="Dashboard" v="http://localhost:5173" />
                                    </div>
                                </div>
                            </section>
                            <section className="panel">
                                <div className="panel-head"><span className="panel-title">About</span></div>
                                <div className="panel-body">
                                    <div className="kv">
                                        <KV k="Project" v="OmniGuard SOC" />
                                        <KV k="Alerts stored" v={String(alerts.length)} />
                                        <KV k="Contract" v="AlertCreate v0.2" />
                                        <KV k="Signed in as" v="A. Maharjan" />
                                    </div>
                                </div>
                            </section>
                        </div>
                    )}

                </div>
            </div>
        </div>
    )
}

// magnitude across nominal categories: one hue for every bar, value direct-labelled
function RankList({ data }) {
    if (data.length === 0) return <div className="empty">Nothing recorded yet.</div>;
    const max = data[0][1];
    return (
        <div className="rank">
            {data.map(([key, n]) => (
                <div className="rank-row" key={key} title={`${key}: ${n}`}>
                    <span className="rank-key">{key}</span>
                    <span className="rank-n">{n}</span>
                    <span className="rank-track">
                        <span className="rank-fill" style={{ width: pct(n, max) }} />
                    </span>
                </div>
            ))}
        </div>
    );
}

function KV({ k, v }) {
    return (
        <div className="kv-row">
            <span className="kv-key">{k}</span>
            <span className={`kv-val ${v ? "" : "empty"}`}>{v || "not reported"}</span>
        </div>
    )
}

export default App;
