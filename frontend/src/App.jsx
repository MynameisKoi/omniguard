import "./App.css"
import { API_URL, WS_URL } from "./config"
import { useState, useEffect, useRef } from 'react';
import GraphCanvas from './GraphCanvas';
import {
    LayoutDashboard, Flag, Share2, Server, Cpu, Settings, Menu,
    Sun, Moon, ChevronDown, ArrowRight, ExternalLink, AlertTriangle,
    ShieldAlert, Globe, Check, TriangleAlert, Inbox, X,
    Siren, Users, Activity, Target, TrendingUp, TrendingDown, Search, Bell,
    UserRound, LogOut, Sparkles, RefreshCw, Send, Bot,
} from 'lucide-react';
import { Sparkline, StackedArea, BarRow, SampleBadge } from './charts';
import { sampleThreatActivity, sampleSparkline, SAMPLE_DELTAS } from './sampleData';

const SEVERITIES = ["critical", "high", "medium", "low"];
const SOURCES = ["verifyeye", "spectrac2", "manual"];

const MITRE = {
    T1566: "Phishing",
    T1071: "Application layer protocol",
    T1078: "Valid accounts",
    T1021: "Remote services",
    T1056: "Input capture",
};

/* the status panel's initial rows — shown until the first /status poll comes back */
const SERVICES = [
    { name: "Backend API", ok: true },
    { name: "MongoDB", ok: true },
    { name: "Neo4j", ok: true },
    { name: "Data ingestion", ok: true },
    { name: "AI analysis", ok: false },
];

/* maps the keys the backend's /status returns to the labels we show, in order */
const STATUS_ROWS = [
    ["backend", "Backend API"],
    ["mongo", "MongoDB"],
    ["neo4j", "Neo4j"],
    ["ingestion", "Data ingestion"],
    ["ollama", "AI analysis"],
];

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
        { id: "overview",  icon: LayoutDashboard, label: "Dashboard" },
        { id: "alerts",    icon: Flag,            label: "Alerts", counted: true },
        { id: "incidents", icon: Siren,           label: "Incidents" },
        { id: "graph",     icon: Share2,          label: "Network graph" },
    ]},
    { group: "Investigate", items: [
        { id: "assets", icon: Server, label: "Hosts & assets" },
        { id: "users",  icon: Users,  label: "Users" },
        { id: "ledger", icon: Activity, label: "Audit ledger" },
    ]},
    { group: "System", items: [
        { id: "engines",  icon: Cpu,      label: "Engines" },
        { id: "settings", icon: Settings, label: "Settings" },
    ]},
];

function App({ user, onLogout, onUserChange }) {
    // shown in the account menu: name if set, otherwise the email
    const displayName = user.name || user.email
    const initials = displayName.split(/[\s.@]+/).filter(Boolean).slice(0, 2).map(w => w[0].toUpperCase()).join("")

    // adding the state for alerts
    const [alerts, setAlerts] = useState([])

    // adding the state for ai
    const [aiText, setAiText] = useState("")
    const [aiLoading, setAiLoading] = useState(false)
    const [aiError, setAiError] = useState(null)

    const [chatMessages, setChatMessages] = useState([])
    const [chatLoading, setChatLoading] = useState(false)

    // live service health for the status panel (starts from the initial rows)
    const [services, setServices] = useState(SERVICES)

    // adding the state for error
    const [error, setError] = useState(null)

    // ui state
    // open by default on desktop, collapsed into a drawer on phones
    const [navOpen, setNavOpen] = useState(() => window.innerWidth > 820)
    const [page, setPage] = useState("overview")   // always land on the dashboard
    const [selectedId, setSelectedId] = useState(null)
    const [filter, setFilter] = useState(null)
    const [srcFilter, setSrcFilter] = useState(null)
    const [assetTab, setAssetTab] = useState("hosts")
    const [query, setQuery] = useState("")
    // which top-bar dropdown is open: null | "search" | "bell" | "profile"
    const [menu, setMenu] = useState(null)
    const [theme, setTheme] = useState(() => {
        try { return localStorage.getItem("og-theme") || "dark" } catch { return "dark" }
    })

    // we will fetch the alerts from backend
    useEffect(() => {
        fetch(`${API_URL}/alerts`)
        .then((res) => res.json())
        .then((data) => setAlerts(data))
        .catch(err => setError(err.message))
    }, []);

    // poll /status so the system panel shows real health. runs now and every 10s.
    useEffect(() => {
        let alive = true
        const pull = () => {
            fetch(`${API_URL}/status`)
            .then(res => res.json())
            .then(data => {
                if (alive) setServices(STATUS_ROWS.map(([key, name]) => ({ name, ok: !!data[key] })))
            })
            // backend unreachable means nothing is confirmed up — show it all down
            .catch(() => { if (alive) setServices(STATUS_ROWS.map(([, name]) => ({ name, ok: false }))) })
        }
        pull()
        const id = setInterval(pull, 10000)
        return () => { alive = false; clearInterval(id) }
    }, []);

    // live alerts. if the connection drops (backend restart, wifi blip) we retry
    // every 3s, and on reconnect re-fetch the list so alerts sent meanwhile aren't lost
    useEffect(() => {
        let socket
        let closing = false
        let retry
        let dropped = false

        const connect = () => {
            socket = new WebSocket(`${WS_URL}/ws/alerts`)

            socket.onopen = () => {
                setError(null)
                if (dropped) {
                    fetch(`${API_URL}/alerts`).then(res => res.json()).then(setAlerts).catch(() => {})
                }
            }

            socket.onmessage = (event) => {
                const msg = JSON.parse(event.data)
                if (msg.type === "alert_fused") {
                    const fused = msg.alert
                    setAlerts(prev => [fused, ...prev.filter(a => a.alert_id !== fused.alert_id)])
                } else {
                    setAlerts(prev => [msg, ...prev])
                }
            }

            socket.onclose = () => {
                if (closing) return
                dropped = true
                setError("Lost the live connection to the backend — reconnecting…")
                retry = setTimeout(connect, 3000)
            }
        }
        connect()

        return () => {
            closing = true
            clearTimeout(retry)
            socket.close()
        }

    }, [])

    // set it on <html> so body and everything else inherit the palette
    useEffect(() => {
        document.documentElement.setAttribute("data-theme", theme);
        try { localStorage.setItem("og-theme", theme) } catch { /* private mode */ }
    }, [theme]);

    // a click anywhere outside an open dropdown closes it, and so does escape
    useEffect(() => {
        if (!menu) return
        const onDown = e => { if (!e.target.closest(".hasmenu")) setMenu(null) }
        const onKey = e => { if (e.key === "Escape") setMenu(null) }
        document.addEventListener("mousedown", onDown)
        window.addEventListener("keydown", onKey)
        return () => {
            document.removeEventListener("mousedown", onDown)
            window.removeEventListener("keydown", onKey)
        }
    }, [menu]);

    // free-text search across the fields an analyst would actually type
    const q = query.trim().toLowerCase();
    const matchesQuery = (a) => !q || [
        a.host, a.user, a.event_type, a.domain, a.src_ip, a.dst_ip,
        a.source, a.mitre_technique, a.description,
    ].some(v => v && String(v).toLowerCase().includes(q));

    // one filter set, scoping everything below it
    const scoped = alerts.filter(a =>
        (!filter || a.severity === filter) &&
        (!srcFilter || a.source === srcFilter) &&
        matchesQuery(a)
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

    // newest alerts first on the Alerts page
    const visible = [...scoped].sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp));
    const selected = alerts.find(a => a.alert_id === selectedId);
    const maxCount = Math.max(1, ...SEVERITIES.map(countOf));
    const engineCounts = countBy("source");

    const byNewest = [...scoped].sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp));
    const recent = byNewest.slice(0, 7);
    const criticals = byNewest.filter(a => a.severity === "critical").slice(0, 3);
    const untriaged = scoped.filter(a => a.status === "new").length;

    // placeholder until GET /stats/timeseries exists — see sampleData.js
    const activity = sampleThreatActivity();

    const techniques = topN("mitre_technique", 5);
    const techniqueMax = Math.max(1, ...techniques.map(([, n]) => n));

    // Risk score, 0-100. Weighted by severity so one critical outranks a pile
    // of lows, then scaled against the worst host so the bars stay readable.
    // Deliberately simple and explainable — not a black box.
    const RISK_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1 };
    const hostRisk = Object.keys(countBy("host")).map(host => {
        const mine = scoped.filter(a => a.host === host);
        const raw = mine.reduce((sum, a) => sum + (RISK_WEIGHT[a.severity] || 0), 0);
        return {
            host,
            raw,
            count: mine.length,
            worst: SEVERITIES.find(s => mine.some(a => a.severity === s)),
        };
    });
    const worstRaw = Math.max(1, ...hostRisk.map(h => h.raw));
    const riskyHosts = hostRisk
        .map(h => ({ ...h, score: Math.round((h.raw / worstRaw) * 100) }))
        .sort((a, b) => b.score - a.score)
        .slice(0, 6);

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
        : page === "profile"
        ? "Profile"
        : NAV.flatMap(s => s.items).find(i => i.id === page)?.label ?? "Alerts";


    async function runAiTriage() {
        setAiLoading(true)
        setAiError(null)

        try {
            const res = await fetch(`${API_URL}/ai/summary`)
            if (!res.ok) throw new Error(res.status)
            const data = await res.json()
            setAiText(data.triage)
        } catch (e) {
            setAiError(String(e))
        } finally {
            setAiLoading(false)
        }
    }

    async function sendChat(question) {
        // earlier turns go along so follow-ups ("what about that host?") have context
        const history = chatMessages.slice(-6)
        setChatMessages(prev => [...prev, { role: "user", text: question }])
        setChatLoading(true)
        try {
            const res = await fetch(`${API_URL}/ai/chat`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ question, history }),
            })
            if (!res.ok) throw new Error(res.status)
            const data = await res.json()
            setChatMessages(prev => [...prev, { role: "ai", text: data.answer }])
        } catch {
            setChatMessages(prev => [...prev, { role: "ai", text: "Couldn't reach the model — is Ollama running?" }])
        } finally {
            setChatLoading(false)
        }
    }

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
                                    onClick={() => { setPage(item.id); setSelectedId(null); if (window.innerWidth <= 820) setNavOpen(false); }}
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

                {navOpen && (
                    <div className="sysstatus">
                        <div className="sysstatus-head">System status</div>
                        {services.map(s => (
                            <div className="sysstatus-row" key={s.name}>
                                <span className={`sysstatus-dot ${s.ok ? "ok" : "down"}`} />
                                <span className="sysstatus-name">{s.name}</span>
                                <span className={`sysstatus-state ${s.ok ? "ok" : "down"}`}>
                                    {s.ok ? "Online" : "Offline"}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </nav>

            {/* dims the page behind the mobile drawer; tap to close (hidden on desktop) */}
            {navOpen && <div className="nav-backdrop" onClick={() => setNavOpen(false)} />}

            {/* ─── main column ──────────────────────── */}
            <div className="main">

                <header className="topbar">
                    <button className="topbar-burger" onClick={() => setNavOpen(!navOpen)} aria-label="Open navigation">
                        <Menu size={18} />
                    </button>
                    <div className="crumb">
                        {page === "alert-detail" ? (
                            <>
                                <button className="back" onClick={() => setPage("alerts")}>Alerts</button>
                                <span className="slash">/</span>
                                {selected ? selected.event_type : "detail"}
                            </>
                        ) : pageLabel}
                    </div>
                    <div className="searchbox hasmenu">
                        <Search />
                        <input
                            className="search"
                            placeholder="Search hosts, alerts, users, IPs…"
                            value={query}
                            onChange={e => setQuery(e.target.value)}
                            onFocus={() => setMenu("search")}
                        />
                        {query && (
                            <button className="search-clear" onClick={() => setQuery("")} aria-label="Clear search">
                                <X />
                            </button>
                        )}
                        {menu === "search" && (
                            <div className="dropdown wide">
                                <div className="dropdown-head">Search</div>
                                {query ? (
                                    <div className="dropdown-row">
                                        <span className="dropdown-title">
                                            {scoped.length} alert{scoped.length === 1 ? "" : "s"} match “{query}”
                                        </span>
                                        <span className="dropdown-sub">
                                            Filtering every panel below. Press Escape to close this.
                                        </span>
                                    </div>
                                ) : (
                                    <div className="dropdown-row">
                                        <span className="dropdown-title">Type to filter the dashboard</span>
                                        <span className="dropdown-sub">
                                            Matches host, user, event type, domain, IP, engine, technique and description.
                                        </span>
                                    </div>
                                )}
                                <div className="dropdown-note">
                                    <SampleBadge note="work needed" />
                                    Full search — jump straight to a host or run a saved query — comes
                                    with the search endpoint.
                                </div>
                            </div>
                        )}
                    </div>

                    <div className="grow" />

                    <span className="clock">
                        {new Date().toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
                    </span>
                    <span className="live"><span className="live-dot" />Live</span>

                    <span className="hasmenu">
                        <button
                            className={`icon-btn bell ${menu === "bell" ? "on" : ""}`}
                            onClick={() => setMenu(menu === "bell" ? null : "bell")}
                            title={`${untriaged} untriaged`}
                            aria-label="Notifications"
                        >
                            <Bell />
                            {untriaged > 0 && <span className="bell-badge">{untriaged > 99 ? "99+" : untriaged}</span>}
                        </button>
                        {menu === "bell" && (
                            <div className="dropdown">
                                <div className="dropdown-head">Notifications</div>
                                <div className="dropdown-empty">
                                    <Bell />
                                    <p>Notifications will arrive here when implemented.</p>
                                    <span>
                                        {untriaged} alert{untriaged === 1 ? "" : "s"} currently untriaged.
                                    </span>
                                </div>
                                <div className="dropdown-note">
                                    <SampleBadge note="work needed" />
                                    Needs a read/unread store so a notification can be dismissed.
                                </div>
                            </div>
                        )}
                    </span>

                    <button
                        className="icon-btn"
                        onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                        title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
                        aria-label="Toggle theme"
                    >
                        {theme === "dark" ? <Sun /> : <Moon />}
                    </button>

                    <span className="hasmenu">
                        <button
                            className={`whoami ${menu === "profile" ? "on" : ""}`}
                            onClick={() => setMenu(menu === "profile" ? null : "profile")}
                            aria-label="Account menu"
                        >
                            <span className="avatar sm">{initials}</span>
                            <span className="whoami-name">SOC Analyst</span>
                            <ChevronDown className="whoami-chev" />
                        </button>
                        {menu === "profile" && (
                            <div className="dropdown">
                                <div className="dropdown-id">
                                    <span className="avatar">{initials}</span>
                                    <span>
                                        <b>{displayName}</b>
                                        <em>{user.email}</em>
                                    </span>
                                </div>
                                <button className="dropdown-item" onClick={() => { setMenu(null); setPage("profile"); setSelectedId(null); }}>
                                    <UserRound /> Profile
                                </button>
                                <button className="dropdown-item" onClick={() => { setMenu(null); setPage("settings"); setSelectedId(null); }}>
                                    <Settings /> Preferences
                                </button>
                                <button className="dropdown-item danger" onClick={onLogout}>
                                    <LogOut /> Log out
                                </button>
                            </div>
                        )}
                    </span>
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

                                    <Panel title="Attack graph" note={`neighbourhood of ${selected.host}`}>
                                        <GraphCanvas host={selected.host} refreshKey={alerts.length} compact />
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
                                        <KV k="Occurrences" v={selected.occurrence_count != null ? `${selected.occurrence_count}×` : null} />
                                        <KV k="Alert ID"   v={selected.alert_id} />
                                    </div>
                                    <AlertActions alert={selected} />
                                </Panel>
                            </div>
                        </>
                    )}

                    {/* ── overview ── */}
                    {page === "overview" && (
                        <>
                            <div className="toolbar">
                                <Seg label="Severity" value={filter} onChange={setFilter} options={SEVERITIES} />
                                <span className="toolbar-sep" />
                                <Seg label="Engine" value={srcFilter} onChange={setSrcFilter} options={SOURCES} />
                                <span className="toolbar-grow" />
                                <span className="toolbar-count">
                                    {scoped.length === alerts.length
                                        ? `${alerts.length} alerts`
                                        : `${scoped.length} of ${alerts.length}`}
                                </span>
                                {(filter || srcFilter || query) && (
                                    <button
                                        className="reset"
                                        onClick={() => { setFilter(null); setSrcFilter(null); setQuery(""); }}
                                    >
                                        <X /> Clear
                                    </button>
                                )}
                            </div>

                            <div className="stats">
                                <Stat icon={Flag}        label="Total alerts" value={scoped.length}         series="total"    />
                                <Stat icon={ShieldAlert} label="Critical"     value={countOf("critical")}   series="critical" tone="critical" />
                                <Stat icon={TriangleAlert} label="High"       value={countOf("high")}       series="high"     tone="high" />
                                <Stat icon={Activity}    label="Medium"       value={countOf("medium")}     series="medium"   tone="medium" />
                                <Stat icon={Inbox}       label="Low"          value={countOf("low")}        series="low"      tone="low" />
                                <Stat icon={Target}      label="Untriaged"    value={untriaged}             series="incidents" tone="accent" />
                            </div>

                            <AiTriage
                                text={aiText}
                                loading={aiLoading}
                                error={aiError}
                                onRun={runAiTriage}
                            />

                            <Attention findings={findings} />

                            <div className="grid-3">
                                <Panel
                                    title="Threat activity"
                                    note={<><SampleBadge />last 24 hours</>}
                                    wide
                                >
                                    <div className="chart-legend">
                                        {SEVERITIES.map(sev => (
                                            <span className="chart-legend-item" key={sev}>
                                                <span className={`chart-legend-dot sev-${sev}`} />
                                                {sev}
                                            </span>
                                        ))}
                                    </div>
                                    <StackedArea data={activity} />
                                </Panel>

                                <Panel title="Severity distribution" note={`${scoped.length} alerts`}>
                                    <Donut
                                        total={scoped.length}
                                        slices={SEVERITIES.map(sev => ({ key: sev, n: countOf(sev) }))}
                                    />
                                </Panel>

                                <Panel title="Top techniques" note="MITRE ATT&amp;CK">
                                    {techniques.length === 0 ? (
                                        <div className="empty">No techniques mapped yet.</div>
                                    ) : (
                                        <div className="barrows">
                                            {techniques.map(([id, n]) => (
                                                <BarRow
                                                    key={id}
                                                    label={MITRE[id] || id}
                                                    sub={id}
                                                    value={n}
                                                    max={techniqueMax}
                                                />
                                            ))}
                                        </div>
                                    )}
                                </Panel>
                            </div>

                            <div className="grid-2">
                                <Panel
                                    title="Network graph"
                                    note={`${countDistinct("host")} hosts · ${countDistinct("domain")} domains`}
                                    action="Open"
                                    onAction={() => setPage("graph")}
                                >
                                    {alerts.length === 0 ? (
                                        <CardEmpty glyph={Share2} text="Graph is empty" />
                                    ) : (
                                        <GraphCanvas compact refreshKey={alerts.length}/>
                                    )}
                                </Panel>

                                <Panel
                                    title="Top affected assets"
                                    note="by risk score"
                                    action={countDistinct("host") ? "View all" : null}
                                    onAction={() => { setAssetTab("hosts"); setPage("assets"); }}
                                >
                                    {riskyHosts.length === 0 ? (
                                        <CardEmpty glyph={Server} text="No hosts seen yet" />
                                    ) : (
                                        <div className="barrows">
                                            {riskyHosts.map(h => (
                                                <BarRow
                                                    key={h.host}
                                                    label={h.host}
                                                    sub={`${h.count} alert${h.count === 1 ? "" : "s"}`}
                                                    value={h.score}
                                                    max={100}
                                                    tone={h.worst}
                                                />
                                            ))}
                                        </div>
                                    )}
                                </Panel>
                            </div>

                            <div className="grid-1">
                                <Panel
                                    title="Recent alerts"
                                    note={`${recent.length} shown`}
                                    action={alerts.length ? "View all" : null}
                                    onAction={() => { setFilter(null); setPage("alerts"); }}
                                    flush
                                >
                                    {recent.length === 0 ? (
                                        <CardEmpty
                                            glyph={Flag}
                                            text="No alerts yet"
                                            cta="Post one in Swagger"
                                            onCta={() => window.open("http://localhost:8000/docs", "_blank")}
                                        />
                                    ) : (
                                        <table className="table">
                                            <thead>
                                                <tr>
                                                    <th>Time</th><th>Severity</th><th>Type</th>
                                                    <th>Host</th><th className="td-wide">Description</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {recent.map(a => (
                                                    <tr key={a.alert_id} onClick={() => openAlert(a.alert_id)}>
                                                        <td className="td-mono td-faint">{timeAgo(a.timestamp)}</td>
                                                        <td><span className={`sev ${a.severity}`}>{a.severity}</span></td>
                                                        <td className="td-mono">{a.event_type}</td>
                                                        <td className="td-mono td-dim">{a.host}</td>
                                                        <td className="td-wide td-dim td-clip">{a.description || "—"}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    )}
                                </Panel>
                            </div>

                        </>
                    )}

                    {/* ── incidents ── */}
                    {page === "incidents" && (
                        <Panel
                            title="Incidents"
                            note="grouped by host"
                            flush
                        >
                            <div className="pagenote">
                                <SampleBadge note="work needed" />
                                An incident should be a real object — several alerts correlated
                                into one case with an owner and a status. For now this groups
                                alerts by host so the shape is visible.
                            </div>

                            {riskyHosts.length === 0 ? (
                                <div className="empty">No incidents. The queue is clear.</div>
                            ) : (
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>Incident</th><th>Severity</th><th>Alerts</th>
                                            <th>Engines</th><th>Risk</th><th className="td-wide">Last activity</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {riskyHosts.map(h => {
                                            const mine = scoped.filter(a => a.host === h.host);
                                            const engines = [...new Set(mine.map(a => a.source))];
                                            const last = mine.map(a => new Date(a.timestamp)).sort((x, y) => y - x)[0];
                                            return (
                                                <tr key={h.host} onClick={() => { setAssetTab("hosts"); setPage("assets"); }}>
                                                    <td>
                                                        <span className="cell">
                                                            <span className={`cell-mark ${h.worst}`} />
                                                            <span className="cell-main">
                                                                <span className="cell-top">{h.host}</span>
                                                                <span className="cell-sub">{mine.length} correlated alerts</span>
                                                            </span>
                                                        </span>
                                                    </td>
                                                    <td><span className={`sev ${h.worst}`}>{h.worst}</span></td>
                                                    <td className="td-mono td-dim">{h.count}</td>
                                                    <td>
                                                        {engines.map(e => <span className="tag" key={e}>{e}</span>)}
                                                    </td>
                                                    <td className="td-mono td-dim">{h.score}</td>
                                                    <td className="td-wide td-faint td-mono">{timeAgo(last)}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            )}
                        </Panel>
                    )}

                    {/* ── users ── */}
                    {page === "users" && (
                        <Panel title="Users" note={`${countDistinct("user")} accounts seen`} flush>
                            {topN("user", 50).length === 0 ? (
                                <div className="empty">
                                    No users attributed yet. Network-only alerts carry no username.
                                </div>
                            ) : (
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>Account</th><th>Worst severity</th><th>Alerts</th>
                                            <th>Hosts used</th><th className="td-wide">Last seen</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {topN("user", 50).map(([user, n]) => {
                                            const mine = scoped.filter(a => a.user === user);
                                            const worst = SEVERITIES.find(s => mine.some(a => a.severity === s));
                                            const hosts = [...new Set(mine.map(a => a.host))];
                                            const last = mine.map(a => new Date(a.timestamp)).sort((x, y) => y - x)[0];
                                            return (
                                                <tr key={user}>
                                                    <td>
                                                        <span className="cell">
                                                            <span className={`cell-mark ${worst}`} />
                                                            <span className="cell-main">
                                                                <span className="cell-top">{user}</span>
                                                                <span className="cell-sub">
                                                                    {hosts.length > 1 ? `on ${hosts.length} hosts` : "single host"}
                                                                </span>
                                                            </span>
                                                        </span>
                                                    </td>
                                                    <td><span className={`sev ${worst}`}>{worst}</span></td>
                                                    <td className="td-mono td-dim">{n}</td>
                                                    <td className="td-mono td-dim">{hosts.join(", ")}</td>
                                                    <td className="td-wide td-faint td-mono">{timeAgo(last)}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            )}
                        </Panel>
                    )}

                    {/* ── attack graph ── */}
                    {page === "graph" && (
                        <Panel
                            title="Attack graph"
                            note={`${countDistinct("host")} hosts · ${countDistinct("domain")} domains`}
                        >
                            <GraphCanvas refreshKey={alerts.length}/>
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
                                    <KV k="Signed in as" v={displayName} />
                                </div>
                            </Panel>
                        </div>
                    )}

                    {/* ── profile ── */}
                    {page === "profile" && <ProfilePage user={user} onSaved={onUserChange} />}

                    {/* ── audit ledger ── */}
                    {page === "ledger" && <LedgerPage />}

                </div>
            </div>

            {/* rendered once, outside the pages: one chat, on every page,
                and the conversation survives switching pages */}
            <AiChat
                messages={chatMessages}
                loading={chatLoading}
                onSend={sendChat}
                onClear={() => setChatMessages([])}
            />
        </div>
    )
}

/* Account page: shows who is signed in and lets them change their name and
   password. Every save needs the current password (v1 has no tokens yet). */
function ProfilePage({ user, onSaved }) {
    const [name, setName] = useState(user.name || "")
    const [current, setCurrent] = useState("")
    const [next, setNext] = useState("")
    const [confirm, setConfirm] = useState("")
    const [msg, setMsg] = useState(null)        // { tone: "ok" | "bad", text }
    const [saving, setSaving] = useState(false)

    const save = (e) => {
        e.preventDefault()
        if (next && next.length < 8) return setMsg({ tone: "bad", text: "New password must be at least 8 characters." })
        if (next !== confirm) return setMsg({ tone: "bad", text: "New passwords don't match." })
        setSaving(true)
        setMsg(null)
        fetch(`${API_URL}/auth/profile`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: user.email, current_password: current, name, new_password: next || null }),
        })
        .then(res => {
            if (res.status === 401) throw new Error("Current password is incorrect.")
            if (!res.ok) throw new Error("Couldn't save — try again.")
            return res.json()
        })
        .then(updated => {
            onSaved(updated)
            setCurrent(""); setNext(""); setConfirm("")
            setMsg({ tone: "ok", text: next ? "Saved. Your password has been changed." : "Saved." })
        })
        .catch(err => setMsg({ tone: "bad", text: err.message === "Failed to fetch" ? "Can't reach the backend." : err.message }))
        .finally(() => setSaving(false))
    }

    return (
        <div className="cols">
            <Panel title="Account">
                <div className="kv">
                    <KV k="Name" v={user.name} />
                    <KV k="Email" v={user.email} />
                    <KV k="Role" v="SOC analyst" />
                </div>
            </Panel>
            <Panel title="Edit profile">
                <form className="profile-form" onSubmit={save}>
                    <label className="login-field">
                        <span>Display name</span>
                        <input value={name} onChange={e => setName(e.target.value)} maxLength={80} />
                    </label>
                    <label className="login-field">
                        <span>New password <em>(leave blank to keep)</em></span>
                        <input type="password" autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} />
                    </label>
                    {next && (
                        <label className="login-field">
                            <span>Confirm new password</span>
                            <input type="password" autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} />
                        </label>
                    )}
                    <label className="login-field">
                        <span>Current password <em>(required to save)</em></span>
                        <input type="password" autoComplete="current-password" required value={current} onChange={e => setCurrent(e.target.value)} />
                    </label>
                    {msg && <div className={msg.tone === "ok" ? "profile-ok" : "login-error"}>{msg.text}</div>}
                    <button className="login-btn" type="submit" disabled={saving}>
                        {saving ? "Saving…" : "Save changes"}
                    </button>
                </form>
            </Panel>
        </div>
    )
}

// alert-detail response actions: AI investigation, OCSF export, and the
// (simulated) host isolation. each keeps its own result inline.
function AlertActions({ alert }) {
    const [busy, setBusy] = useState(null)
    const [investigation, setInvestigation] = useState(null)
    const [isolation, setIsolation] = useState(null)
    const [ocsf, setOcsf] = useState(null)
    const [err, setErr] = useState(null)

    const run = (kind, fn) => {
        setBusy(kind); setErr(null)
        fn().catch(() => setErr("Request failed — is the backend up?")).finally(() => setBusy(null))
    }

    const investigate = () => run("investigate", async () => {
        const res = await fetch(`${API_URL}/ai/investigate/pipeline`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hostname: alert.host }),
        })
        if (!res.ok) throw new Error()
        setInvestigation(await res.json())
    })
    const isolate = () => run("isolate", async () => {
        const res = await fetch(`${API_URL}/hosts/${encodeURIComponent(alert.host)}/isolate`, { method: "POST" })
        if (!res.ok) throw new Error()
        setIsolation(await res.json())
    })
    const exportOcsf = () => run("ocsf", async () => {
        const res = await fetch(`${API_URL}/alerts/${alert.alert_id}/ocsf`)
        if (!res.ok) throw new Error()
        setOcsf(await res.json())
    })

    return (
        <>
            <div className="actions">
                <button className="btn" onClick={investigate} disabled={busy}>
                    {busy === "investigate" ? "Investigating…" : "Investigate (AI)"}
                </button>
                <button className="btn" onClick={exportOcsf} disabled={busy}>
                    {busy === "ocsf" ? "Exporting…" : "Export OCSF"}
                </button>
                <button className="btn danger" onClick={isolate} disabled={busy}>
                    {busy === "isolate" ? "Isolating…" : "Isolate host"}
                </button>
            </div>
            {err && <div className="login-error" style={{ marginTop: 8 }}>{err}</div>}
            {isolation && (
                <div className="action-result">
                    <strong>Containment</strong> — {isolation.message}
                    {isolation.simulated && <span className="tag">simulated</span>}
                </div>
            )}
            {investigation && <InvestigationResult data={investigation} />}
            {ocsf && (
                <div className="action-result">
                    <div className="action-result-head">
                        <strong>OCSF Class {ocsf.class_uid} — {ocsf.class_name}</strong>
                        <button className="btn" onClick={() => setOcsf(null)}>Close</button>
                    </div>
                    <pre className="code-block">{JSON.stringify(ocsf, null, 2)}</pre>
                </div>
            )}
        </>
    )
}

// renders the multi-agent pipeline result (correlation -> triage -> containment)
function InvestigationResult({ data }) {
    const cor = data.correlation || {}, t = data.triage || {}, c = data.containment || {}
    const tone = t.risk_score >= 70 ? "bad" : t.risk_score >= 40 ? "warn" : "good"
    return (
        <div className="action-result">
            <div className="action-result-head">
                <strong>AI investigation — {data.host}</strong>
                <span className={`risk-badge ${tone}`}>risk {t.risk_score}/100</span>
            </div>
            <div className="kv">
                <KV k="Classification" v={t.classification} />
                <KV k="Confidence" v={t.confidence != null ? `${Math.round(t.confidence * 100)}%` : null} />
                <KV k="Blast radius" v={cor.blast_radius} />
                <KV k="Multi-vector" v={cor.is_multi_vector ? "yes" : "no"} />
                <KV k="MITRE" v={(cor.mitre_techniques || []).join(", ")} />
            </div>
            <div className="rec-title">
                Recommended actions
                {c.requires_human_approval && <span className="tag">needs human approval</span>}
            </div>
            <ul className="rec-list">
                {(c.recommended_actions || []).map((a, i) => (
                    <li key={i}>
                        <span className={`urg ${(a.urgency || "").toLowerCase()}`}>{a.urgency}</span>
                        <strong>{a.action}</strong> — {a.description}
                    </li>
                ))}
            </ul>
        </div>
    )
}

// the decision ledger: lists hash-chained entries and verifies the chain
const shortHash = (h) => h ? `${h.slice(0, 10)}…${h.slice(-6)}` : "—"

function LedgerPage() {
    const [records, setRecords] = useState([])
    const [loading, setLoading] = useState(true)
    const [verify, setVerify] = useState(null)
    const [verifying, setVerifying] = useState(false)
    const [err, setErr] = useState(null)
    const [selected, setSelected] = useState(null)   // a ledger entry → detail view

    const load = () => {
        setLoading(true); setErr(null)
        fetch(`${API_URL}/investigations/ledger?limit=50`)
            .then(r => r.json())
            .then(d => setRecords(d.records || []))
            .catch(() => setErr("Can't reach the backend."))
            .finally(() => setLoading(false))
    }
    useEffect(load, [])

    const runVerify = () => {
        setVerifying(true); setVerify(null)
        fetch(`${API_URL}/investigations/ledger/verify`)
            .then(r => r.json())
            .then(setVerify)
            .catch(() => setErr("Verify failed."))
            .finally(() => setVerifying(false))
    }

    if (selected) {
        return (
            <LedgerEntryDetail
                entry={selected}
                all={records}
                verify={verify}
                blockNo={records.length - records.findIndex(r => r.ledger_id === selected.ledger_id)}
                onBack={() => setSelected(null)}
                onOpen={setSelected}
            />
        )
    }

    return (
        <Panel title="Decision ledger" note="immutable SHA-256 hash-chained audit trail" action="Refresh" actionIcon={RefreshCw} onAction={load}>
                {err && <div className="login-error">{err}</div>}
                <div className="actions" style={{ marginBottom: 14 }}>
                    <button className="btn" onClick={runVerify} disabled={verifying}>
                        {verifying ? "Verifying…" : "Verify chain integrity"}
                    </button>
                    {verify && (
                        <span className={`verify-badge ${verify.valid ? "good" : "bad"}`}>
                            {verify.valid
                                ? `✓ Verified — ${verify.records_checked} blocks, no tampering`
                                : `✗ Tamper detected (id ${verify.failing_ledger_id})`}
                        </span>
                    )}
                </div>
                {loading ? <p className="note">Loading…</p> : records.length === 0 ? (
                    <p className="note">No ledger entries yet. Isolate a host or ask the AI analyst to create one.</p>
                ) : (
                    <div className="chain-list">
                        {records.map((e, i) => (
                            <button className="chain-row" key={e.ledger_id || i} onClick={() => setSelected(e)}>
                                <span className="chain-ico"><Activity /></span>
                                <div className="chain-col chain-id">
                                    <span className="chain-hash">{shortHash(e.entry_hash)}</span>
                                    <span className="chain-sub">{e.timestamp ? timeAgo(e.timestamp) : "—"}</span>
                                </div>
                                <div className="chain-col">
                                    <span className="chain-line"><span className="chain-k">Stage</span> {e.stage}</span>
                                    <span className="chain-line chain-sub">{e.action_taken}</span>
                                </div>
                                <div className="chain-col">
                                    <span className="chain-line"><span className="chain-k">Entity</span> {e.entity_type}: {e.entity_id}</span>
                                    <span className="chain-line chain-sub">by {e.analyst_user}</span>
                                </div>
                                <span className="chain-block">#{records.length - i}</span>
                            </button>
                        ))}
                    </div>
                )}
        </Panel>
    )
}

// Etherscan-style detail for one ledger entry ("transaction")
function LedgerEntryDetail({ entry, all, verify, blockNo, onBack, onOpen }) {
    const prev = all.find(e => e.entry_hash === entry.prev_hash)
    const isGenesis = /^0+$/.test(entry.prev_hash || "")
    const copy = (t) => { try { navigator.clipboard.writeText(t) } catch (e) {} }
    const hasContext = entry.input_context && Object.keys(entry.input_context).length > 0

    return (
        <>
            <button className="detail-back" onClick={onBack}><ArrowRight style={{ transform: "rotate(180deg)" }} /> Decision ledger</button>
            <Panel title={`Ledger entry · block #${blockNo}`} note="replayable, hash-chained decision record">
                <div className="tx-head">
                    <span className="chain-ico big"><Activity /></span>
                    <div className="tx-head-main">
                        <div className="tx-hash mono" onClick={() => copy(entry.entry_hash)} title="click to copy">{entry.entry_hash}</div>
                        <div className="chain-sub">{entry.timestamp ? `${new Date(entry.timestamp).toLocaleString()} · ${timeAgo(entry.timestamp)}` : "—"}</div>
                    </div>
                    {verify && (
                        <span className={`verify-badge ${verify.valid ? "good" : "bad"}`}>
                            {verify.valid ? "✓ chain verified" : "✗ tamper detected"}
                        </span>
                    )}
                </div>

                <div className="tx-grid">
                    <div className="tx-row"><span className="tx-k">Stage</span><span>{entry.stage}</span></div>
                    <div className="tx-row"><span className="tx-k">Action</span><span>{entry.action_taken}</span></div>
                    <div className="tx-row"><span className="tx-k">Entity</span><span>{entry.entity_type}: {entry.entity_id}</span></div>
                    <div className="tx-row"><span className="tx-k">Actor</span><span>{entry.analyst_user}</span></div>
                    <div className="tx-row"><span className="tx-k">Incident</span><span>{entry.incident_id || "—"}</span></div>
                    <div className="tx-row"><span className="tx-k">Reasoning</span><span>{entry.reasoning_output}</span></div>
                    <div className="tx-row"><span className="tx-k">Entry hash</span><span className="mono wrap">{entry.entry_hash}</span></div>
                    <div className="tx-row">
                        <span className="tx-k">Previous hash</span>
                        {isGenesis ? (
                            <span className="mono wrap">{entry.prev_hash} <span className="tag">genesis</span></span>
                        ) : prev ? (
                            <button className="link mono wrap" onClick={() => onOpen(prev)}>{entry.prev_hash} ↗</button>
                        ) : (
                            <span className="mono wrap">{entry.prev_hash}</span>
                        )}
                    </div>
                </div>

                {hasContext && (
                    <>
                        <div className="rec-title">Input context</div>
                        <pre className="code-block">{JSON.stringify(entry.input_context, null, 2)}</pre>
                    </>
                )}
            </Panel>
        </>
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

/* AI analyst panel — presentational only. The parent owns the fetch and passes
   text / loading / error / onRun. Renders the local model's briefing. */
function AiTriage({ text, loading, error, onRun }) {
    return (
        <section className="ai-triage">
            <div className="ai-head">
                <span className="ai-icon"><Cpu /></span>
                <div className="ai-titles">
                    <span className="ai-title">AI analyst</span>
                    <span className="ai-sub">llama3.2:3b · runs locally</span>
                </div>
                <button className="ai-run" onClick={onRun} disabled={loading}>
                    {loading
                        ? <><RefreshCw className="ai-spin" /> Analyzing…</>
                        : <><Sparkles /> {text ? "Regenerate" : "Generate briefing"}</>}
                </button>
            </div>
            <div className="ai-body">
                {error ? (
                    <div className="ai-note ai-err">Couldn&rsquo;t reach the model — is Ollama running?</div>
                ) : loading ? (
                    <div className="ai-note ai-loading">
                        <span className="ai-dot" /><span className="ai-dot" /><span className="ai-dot" />
                        Reading every alert&hellip;
                    </div>
                ) : text ? (
                    <AiMarkdown text={text} />
                ) : (
                    <div className="ai-note ai-empty">
                        Ask the local model to read every alert and write a summary with next steps.
                    </div>
                )}
            </div>
        </section>
    );
}

/* floating chat widget, bottom-right. Closed = round launcher button,
   open = pop-up window. Messages live in App so closing doesn't lose them. */
function AiChat({ messages, loading, onSend, onClear }) {
    const [open, setOpen] = useState(false);
    const [q, setQ] = useState("");
    const logRef = useRef(null);
    const inputRef = useRef(null);
    // grow the text box with what's typed (capped by max-height in CSS)
    useEffect(() => {
        const el = inputRef.current;
        if (!el) return;
        el.style.height = "auto";
        el.style.height = `${el.scrollHeight}px`;
    }, [q, open]);
    useEffect(() => {
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, [messages, loading, open]);
    useEffect(() => {
        if (!open) return;
        const onKey = (e) => { if (e.key === "Escape") setOpen(false); };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [open]);
    const submit = (e) => {
        e.preventDefault();
        const text = q.trim();
        if (!text || loading) return;
        onSend(text);
        setQ("");
    };

    if (!open) {
        return (
            <button className="ai-chat-fab" onClick={() => setOpen(true)} aria-label="Open analyst chat">
                <Bot />
                {loading && <span className="ai-chat-fab-dot" />}
            </button>
        );
    }

    return (
        <section className="ai-chat-pop" role="dialog" aria-label="Ask the analyst">
            <div className="ai-head">
                <span className="ai-icon"><Bot /></span>
                <div className="ai-titles">
                    <span className="ai-title">Ask the analyst</span>
                    <span className="ai-sub">llama3.2:3b · answers from your alerts</span>
                </div>
                {messages.length > 0 && (
                    <button className="ai-chat-clear" onClick={onClear} disabled={loading}>
                        Clear
                    </button>
                )}
                <button
                    className={`ai-chat-close ${messages.length ? "" : "solo"}`}
                    onClick={() => setOpen(false)}
                    aria-label="Minimise chat"
                >
                    <ChevronDown />
                </button>
            </div>
            <div className="ai-body">
                <div className="ai-chat-log" ref={logRef}>
                    {messages.length === 0 && !loading && (
                        <div className="ai-note ai-empty">
                            Ask about your alerts — e.g. &ldquo;which hosts are beaconing?&rdquo;
                        </div>
                    )}
                    {messages.map((m, i) => (
                        <div key={i} className={`ai-msg ai-msg-${m.role}`}>
                            {m.role === "ai" ? <AiMarkdown text={m.text} /> : m.text}
                        </div>
                    ))}
                    {loading && (
                        <div className="ai-msg ai-msg-ai">
                            <div className="ai-note ai-loading">
                                <span className="ai-dot" /><span className="ai-dot" /><span className="ai-dot" /> Thinking&hellip;
                            </div>
                        </div>
                    )}
                </div>
                <form className="ai-chat-input" onSubmit={submit}>
                    <textarea
                        ref={inputRef}
                        autoFocus
                        rows={1}
                        value={q}
                        onChange={e => setQ(e.target.value)}
                        onKeyDown={e => {
                            // Enter sends, Shift+Enter is a new line
                            if (e.key === "Enter" && !e.shiftKey) submit(e);
                        }}
                        placeholder="Ask about your alerts…"
                    />
                    <button className="ai-run" type="submit" disabled={loading} aria-label="Send">
                        <Send />
                    </button>
                </form>
            </div>
        </section>
    );
}

/* tiny markdown renderer for the model output: **bold** headings, lists, paragraphs */
function AiMarkdown({ text }) {
    const inline = (s) =>
        s.split(/(\*\*[^*]+\*\*)/g).map((p, i) =>
            p.startsWith("**") && p.endsWith("**")
                ? <strong key={i}>{p.slice(2, -2)}</strong>
                : <span key={i}>{p}</span>
        );

    const blocks = [];
    let list = null;
    const flush = () => {
        if (list) { blocks.push(<ul key={`u${blocks.length}`} className="ai-list">{list}</ul>); list = null; }
    };

    text.split("\n").forEach((raw, i) => {
        const line = raw.trim();
        if (!line) { flush(); return; }
        const headingBold = /^\*\*(.+?)\*\*:?$/.exec(line);
        if (line.startsWith("#")) { flush(); blocks.push(<h4 key={i} className="ai-h">{inline(line.replace(/^#+\s*/, ""))}</h4>); return; }
        if (headingBold) { flush(); blocks.push(<h4 key={i} className="ai-h">{headingBold[1]}</h4>); return; }
        const li = /^(\d+\.|[-*])\s+(.*)$/.exec(line);
        if (li) { if (!list) list = []; list.push(<li key={i}>{inline(li[2])}</li>); return; }
        flush();
        blocks.push(<p key={i} className="ai-p">{inline(line)}</p>);
    });
    flush();
    return <div className="ai-md">{blocks}</div>;
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
function Panel({ title, note, children, flush = false, defaultOpen = true, action, onAction, actionIcon: ActionIcon = ArrowRight, wide = false }) {
    const [open, setOpen] = useState(defaultOpen);
    return (
        <section className={`panel ${open ? "" : "closed"} ${wide ? "panel-wide" : ""}`}>
            <div className="panel-head">
                <button className="panel-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
                    <span className="chev"><ChevronDown /></span>
                    <span className="panel-title">{title}</span>
                    {note && <span className="panel-note">{note}</span>}
                </button>
                {action && (
                    <button className="panel-action" onClick={onAction}>
                        {action} <ActionIcon />
                    </button>
                )}
            </div>
            {open && (flush ? children : <div className="panel-body">{children}</div>)}
        </section>
    );
}

/* `series` and the delta come from sampleData — both are placeholders until
   GET /stats/timeseries exists. The value itself is real. */
function Stat({ icon: Icon, label, value, tone, foot, series }) {
    const delta = series ? SAMPLE_DELTAS[series] : null;
    const up = delta != null && delta >= 0;
    const colour = tone && tone !== "accent" ? `var(--fill-${tone})` : "var(--accent)";

    return (
        <div className="stat">
            <div className="stat-head">
                <span className="stat-label">{label}</span>
                {Icon && <span className={`stat-icon ${tone || ""}`}><Icon /></span>}
            </div>

            <div className="stat-row">
                <span className={`stat-value ${tone || ""}`}>{value}</span>
                {series && <Sparkline values={sampleSparkline(series)} stroke={colour} />}
            </div>

            {delta != null ? (
                <div className={`stat-delta ${up ? "up" : "down"}`} title="Placeholder — needs GET /stats/timeseries">
                    {up ? <TrendingUp /> : <TrendingDown />}
                    {Math.abs(delta)}%
                    <em>vs yesterday</em>
                </div>
            ) : foot ? (
                <div className="stat-foot">{foot}</div>
            ) : null}
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
