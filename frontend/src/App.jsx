import "./App.css"
import { useState, useEffect } from 'react';
import GraphCanvas from './GraphCanvas';
import {
    LayoutDashboard, Flag, Share2, Server, Cpu, Settings, Menu,
    Sun, Moon, ChevronDown, ArrowRight, ExternalLink, AlertTriangle,
    ShieldAlert, Globe, Check, TriangleAlert, Inbox, X,
} from 'lucide-react';

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

function timeAgo(ts) {
    const secs = Math.floor((Date.now() - new Date(ts)) / 1000);
    if (secs < 60) return "just now";
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return days < 30 ? `${days}d ago` : new Date(ts).toLocaleDateString();
}

const NAV = [
    { group: "Monitor", items: [
        { id: "overview", icon: LayoutDashboard, label: "Overview" },
        { id: "alerts",   icon: Flag,            label: "Alerts", counted: true },
        { id: "graph",    icon: Share2,          label: "Attack graph" },
    ]},
    { group: "Investigate", items: [
        { id: "assets", icon: Server, label: "Assets" },
    ]},
    { group: "System", items: [
        { id: "engines",  icon: Cpu,      label: "Engines" },
        { id: "settings", icon: Settings, label: "Settings" },
    ]},
];

function App() {
    // adding the state for alerts
    const [alerts, setAlerts] = useState([])

    // adding the state for error
    const [error, setError] = useState(null)

    // ui state
    const [navOpen, setNavOpen] = useState(true)
    const [page, setPage] = useState("alerts")
    const [selectedId, setSelectedId] = useState(null)
    const [filter, setFilter] = useState(null)
    const [srcFilter, setSrcFilter] = useState(null)
    const [assetTab, setAssetTab] = useState("hosts")
    const [theme, setTheme] = useState(() => {
        try { return localStorage.getItem("og-theme") || "dark" } catch { return "dark" }
    })

    // we will fetch the alerts from backend
    useEffect(() => {
        fetch("http://localhost:8000/alerts")
        .then((res) => res.json())
        .then((data) => setAlerts(data))
        .catch(err => setError(err.message))
    }, []);

    // set it on <html> so body and everything else inherit the palette
    useEffect(() => {
        document.documentElement.setAttribute("data-theme", theme);
        try { localStorage.setItem("og-theme", theme) } catch { /* private mode */ }
    }, [theme]);

    // one filter set, scoping everything below it
    const scoped = alerts.filter(a =>
        (!filter || a.severity === filter) && (!srcFilter || a.source === srcFilter)
    );

    const countOf = (sev) => scoped.filter(a => a.severity === sev).length;

    // { value: count } for any alert field, ignoring nulls
    const countBy = (field) => scoped.reduce((acc, a) => {
        const v = a[field];
        if (v) acc[v] = (acc[v] || 0) + 1;
        return acc;
    }, {});

    // [[value, count], ...] sorted high to low
    const topN = (field, n) =>
        Object.entries(countBy(field)).sort((x, y) => y[1] - x[1]).slice(0, n);

    const countDistinct = (field) => Object.keys(countBy(field)).length;

    const visible = scoped;
    const selected = alerts.find(a => a.alert_id === selectedId);
    const maxCount = Math.max(1, ...SEVERITIES.map(countOf));
    const engineCounts = countBy("source");

    const byNewest = [...scoped].sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp));
    const recent = byNewest.slice(0, 3);
    const criticals = byNewest.filter(a => a.severity === "critical").slice(0, 3);

    const openAlert = (id) => { setSelectedId(id); setPage("alert-detail"); };

    // TODO: derive these from `scoped`.
    // Shape: { tone: "bad" | "warn" | "good" | "", body: <JSX> }
    // Ideas worth surfacing:
    //   - a host with alerts from more than one engine  (two tools agreeing)
    //   - a domain contacted by more than one host      (shared C2 infrastructure)
    //   - how many criticals, and on which hosts
    //   - how much of the queue is still untriaged
    const findings = [];

    const pageLabel = page === "alert-detail"
        ? "Alerts"
        : NAV.flatMap(s => s.items).find(i => i.id === page)?.label ?? "Alerts";

    return (
        <div className="shell">

            {/* ─── left nav ─────────────────────────── */}
            <nav className={`nav ${navOpen ? "" : "collapsed"}`}>
                <div className="nav-head">
                    <button className="burger" onClick={() => setNavOpen(!navOpen)} aria-label="Toggle navigation">
                        <Menu size={17} />
                    </button>
                    {navOpen && <div className="nav-name">OmniGuard <em>SOC</em></div>}
                </div>

                {NAV.map(section => (
                    <div className="nav-group" key={section.group}>
                        <div className="nav-group-label">{section.group}</div>
                        {section.items.map(item => {
                            const Icon = item.icon;
                            return (
                                <button
                                    key={item.id}
                                    className={`nav-item ${page === item.id || (page === "alert-detail" && item.id === "alerts") ? "active" : ""}`}
                                    onClick={() => { setPage(item.id); setSelectedId(null); }}
                                    title={item.label}
                                >
                                    <span className="nav-icon"><Icon /></span>
                                    {navOpen && <span>{item.label}</span>}
                                    {navOpen && item.counted && <span className="nav-count">{alerts.length}</span>}
                                </button>
                            );
                        })}
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
                        ) : pageLabel}
                    </div>
                    <div className="grow" />
                    <button
                        className="icon-btn"
                        onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                        title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
                        aria-label="Toggle theme"
                    >
                        {theme === "dark" ? <Sun /> : <Moon />}
                    </button>
                    <span className="clock">{new Date().toLocaleDateString()}</span>
                </header>

                <div className="content">

                    {error && (
                        <div className="error">
                            <TriangleAlert size={15} />
                            Could not reach the backend — {error}
                        </div>
                    )}

                    {/* ── alerts list ── */}
                    {page === "alerts" && (
                        <>
                            <div className="stats">
                                <Stat label="Total" value={alerts.length} />
                                <Stat label="Critical" value={countOf("critical")} tone="critical" />
                                <Stat label="High" value={countOf("high")} tone="high" />
                                <Stat label="Untriaged" value={alerts.filter(a => a.status === "new").length} />
                                <Stat label="Engines" value="2" tone="good" />
                            </div>

                            <Panel title="Alerts" note={`${visible.length} shown`} flush>
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
                                                <th>Alert</th>
                                                <th>Severity</th>
                                                <th>Host</th>
                                                <th className="td-wide">Domain</th>
                                                <th>Source</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {visible.map(a => (
                                                <tr key={a.alert_id} onClick={() => openAlert(a.alert_id)}>
                                                    <td>
                                                        <span className="cell">
                                                            <span className={`cell-mark ${a.severity}`} />
                                                            <span className="cell-main">
                                                                <span className="cell-top">{a.event_type}</span>
                                                                <span className="cell-sub">{timeAgo(a.timestamp)}</span>
                                                            </span>
                                                        </span>
                                                    </td>
                                                    <td><span className={`sev ${a.severity}`}>{a.severity}</span></td>
                                                    <td>
                                                        <span className="cell-main">
                                                            <span className="cell-top">{a.host}</span>
                                                            <span className="cell-sub">{a.user || "no user"}</span>
                                                        </span>
                                                    </td>
                                                    <td className={`td-mono td-wide ${a.domain ? "td-dim" : "td-faint"}`}>{a.domain || "—"}</td>
                                                    <td><span className="tag">{a.source}</span></td>
                                                    <td className="td-dim">{a.status}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                )}
                            </Panel>
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

                                    <Panel title="Attack graph" note="placeholder — React Flow">
                                        <div className="canvas">
                                            <span className="hint">neighbourhood of {selected.host}</span>
                                        </div>
                                    </Panel>
                                </div>

                                <Panel title="Details">
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
                                </Panel>
                            </div>
                        </>
                    )}

                    {/* ── overview ── */}
                    {page === "overview" && (
                        <>
                            <div className="hero">
                                <div className="hero-main">
                                    <h1 className="hero-title">Shift handover</h1>
                                    <p className="hero-sub">
                                        {alerts.length === 0
                                            ? "Nothing has come in yet. The queue is clear."
                                            : <>Everything open right now across <b>{countDistinct("host")}</b> host{countDistinct("host") === 1 ? "" : "s"} and <b>{Object.keys(engineCounts).length}</b> reporting engine{Object.keys(engineCounts).length === 1 ? "" : "s"}.</>}
                                    </p>
                                </div>
                                <span className="live"><span className="live-dot" />Live</span>
                            </div>

                            <div className="toolbar">
                                <Seg label="Severity" value={filter} onChange={setFilter} options={SEVERITIES} />
                                <Seg label="Engine" value={srcFilter} onChange={setSrcFilter} options={SOURCES} />
                                <span className="toolbar-grow" />
                                <span className="toolbar-count">
                                    {scoped.length === alerts.length
                                        ? `${alerts.length} alerts`
                                        : `${scoped.length} of ${alerts.length}`}
                                </span>
                                {(filter || srcFilter) && (
                                    <button className="reset" onClick={() => { setFilter(null); setSrcFilter(null); }}>
                                        <X /> Clear
                                    </button>
                                )}
                            </div>

                            <div className="stats">
                                <Stat icon={Flag}         label="Total alerts"   value={alerts.length} foot="in the queue" />
                                <Stat icon={ShieldAlert}  label="Critical"       value={countOf("critical")} tone="critical" foot="need triage first" />
                                <Stat icon={Server}       label="Hosts affected" value={countDistinct("host")} foot="seen in alerts" />
                                <Stat icon={Globe}        label="Domains seen"   value={countDistinct("domain")} foot="contacted externally" />
                                <Stat icon={Inbox}        label="Untriaged"      value={alerts.filter(a => a.status === "new").length} tone="high" foot="still untouched" />
                            </div>

                            <Attention findings={findings} />

                            <div className="section-head">
                                <span className="section-title">Alert flow &amp; triage</span>
                            </div>

                            <div className="cards">

                                <Card
                                    icon={Flag}
                                    title="Recent alerts"
                                    action={alerts.length ? "View all" : null}
                                    onAction={() => { setFilter(null); setPage("alerts"); }}
                                >
                                    {recent.length === 0 ? (
                                        <CardEmpty
                                            glyph={Flag}
                                            text="No alerts yet"
                                            cta="Post one in Swagger"
                                            onCta={() => window.open("http://localhost:8000/docs", "_blank")}
                                        />
                                    ) : recent.map(a => (
                                        <button className="item" key={a.alert_id} onClick={() => openAlert(a.alert_id)}>
                                            <span className={`item-mark ${a.severity}`} />
                                            <span className="item-main">
                                                <span className="item-title">{a.event_type}</span>
                                                <span className="item-meta">
                                                    <span className="strong">{a.host}</span>
                                                    <span className="dot">·</span>
                                                    <span>{a.source}</span>
                                                    <span className="dot">·</span>
                                                    <span>{timeAgo(a.timestamp)}</span>
                                                </span>
                                            </span>
                                        </button>
                                    ))}
                                </Card>

                                <Card
                                    icon={ShieldAlert}
                                    title="Critical alerts"
                                    action={countOf("critical") ? "View all" : null}
                                    onAction={() => { setFilter("critical"); setPage("alerts"); }}
                                >
                                    {criticals.length === 0 ? (
                                        <CardEmpty glyph={Check} text="No critical alerts open" />
                                    ) : criticals.map(a => (
                                        <button className="item" key={a.alert_id} onClick={() => openAlert(a.alert_id)}>
                                            <span className="item-mark critical" />
                                            <span className="item-main">
                                                <span className="item-title">{a.host}</span>
                                                <span className="item-meta">
                                                    <span>{a.event_type}</span>
                                                    <span className="dot">·</span>
                                                    <span>{timeAgo(a.timestamp)}</span>
                                                </span>
                                            </span>
                                        </button>
                                    ))}
                                </Card>

                                <Card
                                    icon={Server}
                                    title="Affected hosts"
                                    action={countDistinct("host") ? "View all" : null}
                                    onAction={() => { setAssetTab("hosts"); setPage("assets"); }}
                                >
                                    {topN("host", 3).length === 0 ? (
                                        <CardEmpty glyph={Server} text="No hosts seen yet" />
                                    ) : topN("host", 3).map(([host, n]) => {
                                        const mine = alerts.filter(a => a.host === host);
                                        const worst = SEVERITIES.find(s => mine.some(a => a.severity === s));
                                        return (
                                            <button className="item" key={host} onClick={() => { setAssetTab("hosts"); setPage("assets"); }}>
                                                <span className={`item-mark ${worst}`} />
                                                <span className="item-main">
                                                    <span className="item-title">{host}</span>
                                                    <span className="item-meta">
                                                        <span className="strong">{n} alert{n === 1 ? "" : "s"}</span>
                                                        <span className="dot">·</span>
                                                        <span>worst {worst}</span>
                                                    </span>
                                                </span>
                                            </button>
                                        );
                                    })}
                                </Card>

                                <Card
                                    icon={Share2}
                                    title="Attack graph"
                                    action={alerts.length ? "Open" : null}
                                    onAction={() => setPage("graph")}
                                >
                                    <CardEmpty
                                        glyph={Share2}
                                        text={alerts.length
                                            ? `${countDistinct("host")} hosts and ${countDistinct("domain")} domains in the graph`
                                            : "Graph is empty"}
                                        cta={alerts.length ? "Open attack graph" : null}
                                        onCta={() => setPage("graph")}
                                    />
                                </Card>

                                <Card
                                    icon={Cpu}
                                    title="Detection engines"
                                    action="View all"
                                    onAction={() => setPage("engines")}
                                >
                                    {SOURCES.map(src => {
                                        const n = engineCounts[src] || 0;
                                        return (
                                            <button className="item" key={src} onClick={() => setPage("engines")}>
                                                <span className={`swatch eng-${src}`} style={{ marginTop: "5px" }} />
                                                <span className="item-main">
                                                    <span className="item-title">{src}</span>
                                                    <span className="item-meta">
                                                        <span className="strong">{n} alert{n === 1 ? "" : "s"}</span>
                                                        <span className="dot">·</span>
                                                        <span>{n ? "reporting" : "no data"}</span>
                                                    </span>
                                                </span>
                                            </button>
                                        );
                                    })}
                                </Card>

                                <Card
                                    icon={Globe}
                                    title="Contacted domains"
                                    action={countDistinct("domain") ? "View all" : null}
                                    onAction={() => { setAssetTab("domains"); setPage("assets"); }}
                                >
                                    {topN("domain", 3).length === 0 ? (
                                        <CardEmpty glyph={Globe} text="No domains recorded" />
                                    ) : topN("domain", 3).map(([domain, n]) => {
                                        const mine = alerts.filter(a => a.domain === domain);
                                        const worst = SEVERITIES.find(s => mine.some(a => a.severity === s));
                                        return (
                                            <button
                                                className="item"
                                                key={domain}
                                                onClick={() => { setAssetTab("domains"); setPage("assets"); }}
                                            >
                                                <span className={`item-mark ${worst}`} />
                                                <span className="item-main">
                                                    <span className="item-title">{domain}</span>
                                                    <span className="item-meta">
                                                        <span className="strong">{n} alert{n === 1 ? "" : "s"}</span>
                                                        <span className="dot">·</span>
                                                        <span>{new Set(mine.map(a => a.host)).size} host(s)</span>
                                                    </span>
                                                </span>
                                            </button>
                                        );
                                    })}
                                </Card>

                            </div>

                            <div className="section-head">
                                <span className="section-title">Coverage</span>
                            </div>

                            <div className="cols">
                                <Panel title="Severity distribution" note={`${scoped.length} alerts`}>
                                    <Donut
                                        total={scoped.length}
                                        slices={SEVERITIES.map(sev => ({ key: sev, n: countOf(sev) }))}
                                    />
                                </Panel>

                                <Panel title="MITRE techniques">
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
                                </Panel>
                            </div>
                        </>
                    )}

                    {/* ── attack graph ── */}
                    {page === "graph" && (
                        <Panel
                            title="Attack graph"
                            note={`${countDistinct("host")} hosts · ${countDistinct("domain")} domains`}
                        >
                            <GraphCanvas />
                        </Panel>
                    )}

                    {/* ── assets: hosts + users ── */}
                    {page === "assets" && (
                        <Panel
                            title="Assets"
                            note={`${countDistinct("host")} hosts · ${countDistinct("user")} users · ${countDistinct("domain")} domains`}
                            flush
                        >
                            <div className="tabs">
                                <button className={`tab ${assetTab === "hosts" ? "on" : ""}`} onClick={() => setAssetTab("hosts")}>
                                    Hosts <span className="n">{countDistinct("host")}</span>
                                </button>
                                <button className={`tab ${assetTab === "users" ? "on" : ""}`} onClick={() => setAssetTab("users")}>
                                    Users <span className="n">{countDistinct("user")}</span>
                                </button>
                                <button className={`tab ${assetTab === "domains" ? "on" : ""}`} onClick={() => setAssetTab("domains")}>
                                    Domains <span className="n">{countDistinct("domain")}</span>
                                </button>
                            </div>

                            {assetTab === "hosts" && (
                                topN("host", 50).length === 0
                                    ? <div className="empty">No hosts yet.</div>
                                    : <table className="table">
                                        <thead>
                                            <tr>
                                                <th>Hostname</th><th>Worst severity</th><th>Alerts</th>
                                                <th>Users</th><th className="td-wide">Domains contacted</th><th>Last seen</th>
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
                                                    <tr key={host}>
                                                        <td className="td-mono">{host}</td>
                                                        <td><span className={`sev ${worst}`}>{worst}</span></td>
                                                        <td className="td-mono td-dim">{n}</td>
                                                        <td className={`td-mono ${users.length ? "td-dim" : "td-faint"}`}>{users.join(", ") || "—"}</td>
                                                        <td className={`td-mono td-wide ${domains.length ? "td-dim" : "td-faint"}`}>{domains.join(", ") || "—"}</td>
                                                        <td className="td-mono td-faint">
                                                            {last.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                                        </td>
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                            )}

                            {assetTab === "users" && (
                                topN("user", 50).length === 0
                                    ? <div className="empty">No users attributed yet. Network-only alerts carry no username.</div>
                                    : <table className="table">
                                        <thead>
                                            <tr><th>Account</th><th>Worst severity</th><th>Alerts</th><th className="td-wide">Hosts used</th></tr>
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

                            {assetTab === "domains" && (
                                topN("domain", 50).length === 0
                                    ? <div className="empty">No domains recorded yet.</div>
                                    : <table className="table">
                                        <thead>
                                            <tr>
                                                <th>Domain</th><th>Worst severity</th><th>Alerts</th>
                                                <th className="td-wide">Hosts that contacted it</th><th>Last seen</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {topN("domain", 50).map(([domain, n]) => {
                                                const mine = alerts.filter(a => a.domain === domain);
                                                const worst = SEVERITIES.find(s => mine.some(a => a.severity === s));
                                                const hosts = [...new Set(mine.map(a => a.host))];
                                                const last = mine.map(a => new Date(a.timestamp)).sort((x, y) => y - x)[0];
                                                return (
                                                    <tr key={domain}>
                                                        <td className="td-mono">{domain}</td>
                                                        <td><span className={`sev ${worst}`}>{worst}</span></td>
                                                        <td className="td-mono td-dim">{n}</td>
                                                        <td className="td-mono td-dim td-wide">{hosts.join(", ")}</td>
                                                        <td className="td-mono td-faint">{timeAgo(last)}</td>
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                            )}
                        </Panel>
                    )}

                    {/* ── engines ── */}
                    {page === "engines" && (
                        <Panel title="Detection engines" flush>
                            <table className="table">
                                <thead>
                                    <tr>
                                        <th>Engine</th><th>Detects</th><th>Alerts</th>
                                        <th>Last alert</th><th className="td-wide">Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {SOURCES.map(src => {
                                        const mine = alerts.filter(a => a.source === src);
                                        const last = mine.map(a => new Date(a.timestamp)).sort((x, y) => y - x)[0];
                                        return (
                                            <tr key={src}>
                                                <td>
                                                    <span style={{ display: "inline-grid", gridTemplateColumns: "9px auto", gap: "8px", alignItems: "center" }}>
                                                        <span className={`swatch eng-${src}`} />
                                                        <span className="td-mono">{src}</span>
                                                    </span>
                                                </td>
                                                <td className="td-dim">{ENGINE_ROLE[src]}</td>
                                                <td className="td-mono td-dim">{mine.length}</td>
                                                <td className="td-mono td-faint">{last ? last.toLocaleString() : "—"}</td>
                                                <td className={`td-wide ${mine.length ? "td-dim" : "td-faint"}`}>
                                                    {mine.length ? "reporting" : "no alerts received"}
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </Panel>
                    )}

                    {/* ── settings ── */}
                    {page === "settings" && (
                        <div className="cols">
                            <Panel title="Connections">
                                <div className="kv">
                                    <KV k="API" v="http://localhost:8000" />
                                    <KV k="MongoDB" v="mongodb://localhost:27017 / omniguard" />
                                    <KV k="Neo4j" v="neo4j://localhost:7687" />
                                    <KV k="Dashboard" v="http://localhost:5173" />
                                </div>
                            </Panel>
                            <Panel title="About">
                                <div className="kv">
                                    <KV k="Project" v="OmniGuard SOC" />
                                    <KV k="Alerts stored" v={String(alerts.length)} />
                                    <KV k="Contract" v="AlertCreate v0.2" />
                                    <KV k="Theme" v={theme} />
                                    <KV k="Signed in as" v="A. Maharjan" />
                                </div>
                            </Panel>
                        </div>
                    )}

                </div>
            </div>
        </div>
    )
}

/* Presentational only — it renders whatever findings it is handed.
   Each finding: { tone: "bad" | "warn" | "good" | "", body: <JSX> }
   The logic that produces them lives in App. */
function Attention({ findings = [] }) {
    return (
        <div className="attention">
            <div className="attention-head">
                <span className="pin"><AlertTriangle /></span>
                What needs attention
            </div>
            <ul>
                {findings.length === 0 ? (
                    <li><span>Nothing to report.</span></li>
                ) : findings.map((f, i) => (
                    <li key={i} className={f.tone}><span>{f.body}</span></li>
                ))}
            </ul>
        </div>
    );
}

/* summary card: a few rows plus a "view all" into the full page */
function Card({ icon: Icon, title, action, onAction, children }) {
    return (
        <section className="card">
            <div className="card-head">
                <span className="card-icon"><Icon /></span>
                <span className="card-title">{title}</span>
                {action && (
                    <button className="card-action" onClick={onAction}>
                        {action} <ArrowRight />
                    </button>
                )}
            </div>
            <div className="card-body">{children}</div>
        </section>
    );
}

function CardEmpty({ glyph: Glyph, text, cta, onCta }) {
    return (
        <div className="card-empty">
            <span className="glyph"><Glyph /></span>
            <p>{text}</p>
            {cta && <button className="cta" onClick={onCta}>{cta} <ExternalLink /></button>}
        </div>
    );
}

/* collapsible panel — the whole header is the hit target */
function Panel({ title, note, children, flush = false, defaultOpen = true }) {
    const [open, setOpen] = useState(defaultOpen);
    return (
        <section className={`panel ${open ? "" : "closed"}`}>
            <div className="panel-head">
                <button className="panel-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
                    <span className="chev"><ChevronDown /></span>
                    <span className="panel-title">{title}</span>
                    {note && <span className="panel-note">{note}</span>}
                </button>
            </div>
            {open && (flush ? children : <div className="panel-body">{children}</div>)}
        </section>
    );
}

function Stat({ icon: Icon, label, value, tone, foot }) {
    return (
        <div className="stat">
            <div className="stat-head">
                <span className="stat-label">{label}</span>
                {Icon && <span className={`stat-icon ${tone || ""}`}><Icon /></span>}
            </div>
            <div className={`stat-value ${tone || ""}`}>{value}</div>
            {foot && <div className="stat-foot">{foot}</div>}
        </div>
    );
}

/* one segmented control: "All" plus every option, joined into a single pill */
function Seg({ label, value, onChange, options }) {
    return (
        <div className="seg-group">
            <span className="seg-label">{label}</span>
            <div className="seg" role="group" aria-label={label}>
                <button
                    className={`seg-btn ${value === null ? "on" : ""}`}
                    onClick={() => onChange(null)}
                    aria-pressed={value === null}
                >
                    All
                </button>
                {options.map(o => (
                    <button
                        key={o}
                        className={`seg-btn ${value === o ? "on" : ""}`}
                        onClick={() => onChange(o)}
                        aria-pressed={value === o}
                    >
                        {o}
                    </button>
                ))}
            </div>
        </div>
    );
}

/* part-to-whole ring. Presentational — it draws whatever slices it is handed.
   Each slice: { key, n }; the key doubles as the CSS class for its colour. */
function Donut({ slices, total, size = 132, thickness = 14 }) {
    const r = (size - thickness) / 2;
    const circumference = 2 * Math.PI * r;
    const sum = slices.reduce((acc, s) => acc + s.n, 0);

    let offset = 0;
    const arcs = slices
        .filter(s => s.n > 0)
        .map(s => {
            const len = (s.n / sum) * circumference;
            const arc = { ...s, len, offset };
            offset += len;
            return arc;
        });

    return (
        <div className="donut-wrap">
            <div className="donut" style={{ width: size, height: size }}>
                <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size}>
                    {/* track, so an empty or partial ring still reads as a ring */}
                    <circle
                        className="donut-track"
                        cx={size / 2} cy={size / 2} r={r}
                        fill="none" strokeWidth={thickness}
                    />
                    {arcs.map(a => (
                        <circle
                            key={a.key}
                            className={`donut-arc sev-${a.key}`}
                            cx={size / 2} cy={size / 2} r={r}
                            fill="none"
                            strokeWidth={thickness}
                            strokeDasharray={`${a.len} ${circumference - a.len}`}
                            strokeDashoffset={-a.offset}
                            /* start at 12 o'clock instead of 3 */
                            transform={`rotate(-90 ${size / 2} ${size / 2})`}
                        >
                            <title>{`${a.key}: ${a.n}`}</title>
                        </circle>
                    ))}
                </svg>
                <div className="donut-center">
                    <span className="donut-total">{total}</span>
                    <span className="donut-caption">alerts</span>
                </div>
            </div>

            <div className="donut-legend">
                {slices.map(s => (
                    <div className="donut-row" key={s.key}>
                        <span className={`donut-swatch sev-${s.key}`} />
                        <span className="donut-key">{s.key}</span>
                        <span className="donut-n">{s.n}</span>
                        <span className="donut-pct">{sum ? Math.round((s.n / sum) * 100) : 0}%</span>
                    </div>
                ))}
            </div>
        </div>
    );
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
