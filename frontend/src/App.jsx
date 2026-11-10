import "./App.css"
import { api, wsUrl } from "./api"
import { useState, useEffect, useRef, Fragment } from 'react';
import GraphCanvas from './GraphCanvas';
import GraphExplorer from './GraphExplorer';
import { timeAgo, exactTime } from './time';
import { scopeIds } from './graphScope';
import { label, humanize, MITRE_NAMES } from './labels';
import { EvidencePanel, EvidenceGallery } from './Evidence';
import AiMarkdown from './AiMarkdown';
import AskAI from './AskAI';
import { useAskActivity } from './askActivity'
import {
    LayoutDashboard, Flag, Share2, Server, Cpu, Settings, Menu,
    Sun, Moon, ChevronDown, ArrowRight, ExternalLink, AlertTriangle,
    ShieldAlert, Globe, Check, TriangleAlert, Inbox, X,
    Siren, Users, Activity, Target, TrendingUp, TrendingDown, Search, Bell,
    UserRound, LogOut, Sparkles, RefreshCw, Send, Bot, Calendar,
    GitMerge, Gauge, ShieldCheck, ShieldOff, UserCheck, Link2, Copy,
} from 'lucide-react';
import { Sparkline, StackedArea, BarRow, PieChart, BarChart, SampleBadge } from './charts';

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


// real time-series from the alerts: n buckets from the earliest alert to now,
// counted by severity (replaces the sampleData threat-activity placeholder)
function buildActivity(alerts, n = 14) {
    const times = (alerts || []).map(a => new Date(a.timestamp).getTime()).filter(t => !isNaN(t));
    if (!times.length) return [];
    const min = Math.min(...times);
    const max = Math.max(Date.now(), ...times);
    const span = Math.max(max - min, 1);
    const byDay = span > 2 * 864e5; // span over 2 days → label by date, else by hour
    const buckets = Array.from({ length: n }, () => ({ critical: 0, high: 0, medium: 0, low: 0 }));
    for (const a of alerts) {
        const t = new Date(a.timestamp).getTime();
        if (isNaN(t)) continue;
        let idx = Math.floor(((t - min) / span) * n);
        idx = Math.max(0, Math.min(n - 1, idx));
        const sev = (a.severity || "low").toLowerCase();
        if (buckets[idx][sev] != null) buckets[idx][sev]++;
    }
    return buckets.map((b, i) => {
        const at = new Date(min + (span * (i + 0.5)) / n);
        const label = byDay
            ? at.toLocaleDateString(undefined, { month: "short", day: "numeric" })
            : at.toLocaleTimeString(undefined, { hour: "2-digit" });
        return { label, ...b };
    });
}

// % change between the first half and second half of a series (real delta)
function trendDelta(series) {
    const n = (series || []).length;
    if (n < 2) return null;
    const half = Math.floor(n / 2);
    const a = series.slice(0, half).reduce((s, x) => s + x, 0);
    const b = series.slice(half).reduce((s, x) => s + x, 0);
    if (a === 0) return b > 0 ? 100 : 0;
    return Math.round(((b - a) / a) * 100);
}

const NAV = [
    { group: "Monitor", items: [
        { id: "overview",  icon: LayoutDashboard, label: "Dashboard" },
        { id: "alerts",    icon: Flag,            label: "Alerts", counted: true },
        { id: "incidents", icon: Siren,           label: "Incidents" },
        { id: "graph",     icon: Share2,          label: "Network graph" },
    ]},
    { group: "Investigate", items: [
        { id: "ask",    icon: Sparkles, label: "Ask AI" },
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

    // Ask AI replies running in the background / finished while you were elsewhere
    const askActivity = useAskActivity({ poll: true })

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
    // restore the last tab + open alert on reload instead of snapping back to the dashboard
    // the remembered page, unless it no longer exists (then the dashboard)
    const [page, setPage] = useState(() => {
        const known = new Set([...NAV.flatMap(s => s.items.map(i => i.id)), "alert-detail", "search", "profile"])
        try { const p = localStorage.getItem("og_page"); return known.has(p) ? p : "overview" } catch { return "overview" }
    })
    const [selectedId, setSelectedId] = useState(() => { try { return localStorage.getItem("og_selectedId") || null } catch { return null } })
    // which page the open alert was reached from, so "back" returns there
    const [cameFrom, setCameFrom] = useState(() => { try { return localStorage.getItem("og_cameFrom") || "alerts" } catch { return "alerts" } })

    // remember the current tab + open alert across reloads
    useEffect(() => { try { localStorage.setItem("og_page", page) } catch {} }, [page])
    useEffect(() => {
        try { selectedId ? localStorage.setItem("og_selectedId", selectedId) : localStorage.removeItem("og_selectedId") } catch {}
    }, [selectedId])
    useEffect(() => { try { localStorage.setItem("og_cameFrom", cameFrom) } catch {} }, [cameFrom])
    // if the remembered alert is gone (e.g. it was deleted), fall back to the list
    useEffect(() => {
        if (page === "alert-detail" && selectedId && alerts.length && !alerts.find(a => a.alert_id === selectedId)) {
            setPage("alerts"); setSelectedId(null)
        }
    }, [page, selectedId, alerts])
    const [filter, setFilter] = useState(null)
    const [srcFilter, setSrcFilter] = useState(null)
    const [dateFilter, setDateFilter] = useState(null)   // null|"today"|"yesterday"|"7d"|"30d"|"custom"
    const [dateFrom, setDateFrom] = useState("")
    const [dateTo, setDateTo] = useState("")
    const [assetTab, setAssetTab] = useState("hosts")
    const [query, setQuery] = useState("")          // live text in the search box
    const [searchTerm, setSearchTerm] = useState(() => { try { return localStorage.getItem("og_searchTerm") || "" } catch { return "" } }) // committed term (Enter)
    // the page a search / drill-down was opened from, so "Back" returns there
    const [searchFrom, setSearchFrom] = useState("overview")
    // the Alerts page's own search box: filters that list as you type
    const [alertQuery, setAlertQuery] = useState("")
    const [searchKind, setSearchKind] = useState(() => { try { return localStorage.getItem("og_searchKind") || "search" } catch { return "search" } }) // "search" (typed) | "filter" (chart click)
    const [recentSearches, setRecentSearches] = useState(() => {
        try { return JSON.parse(localStorage.getItem("og_recent_searches") || "[]") } catch { return [] }
    })
    useEffect(() => { try { localStorage.setItem("og_searchTerm", searchTerm) } catch {} }, [searchTerm])
    useEffect(() => { try { localStorage.setItem("og_searchKind", searchKind) } catch { /* private mode */ } }, [searchKind])

    // brief "something changed" flash + scroll-to-top when a filter is applied,
    // so an in-place dashboard change is perceptible instead of silently instant
    const contentRef = useRef(null);
    const [filtering, setFiltering] = useState(false);
    const didMountFilter = useRef(false);
    useEffect(() => {
        if (!didMountFilter.current) { didMountFilter.current = true; return; } // skip first render
        setFiltering(true);
        if (contentRef.current) contentRef.current.scrollTo({ top: 0, behavior: "smooth" });
        const t = setTimeout(() => setFiltering(false), 240);
        return () => clearTimeout(t);
    }, [searchTerm, page]);
    // which top-bar dropdown is open: null | "search" | "bell" | "profile"
    const [menu, setMenu] = useState(null)
    // the current time, refreshed each minute, for "in the last 24 hours" checks
    const [now, setNow] = useState(() => Date.now())
    useEffect(() => {
        const id = setInterval(() => setNow(Date.now()), 60000)
        return () => clearInterval(id)
    }, [])
    // "See in network graph": entities to light up on the graph tab, and what they came from
    const [graphFocus, setGraphFocus] = useState(null)   // { label, ids: [...] } | null
    const [theme, setTheme] = useState(() => {
        try { return localStorage.getItem("og-theme") || "dark" } catch { return "dark" }
    })

    // we will fetch the alerts from backend
    useEffect(() => {
        api(`/alerts`)
        .then((res) => res.json())
        .then((data) => setAlerts(data))
        .catch(err => setError(err.message))
    }, []);

    // poll /status so the system panel shows real health. runs now and every 10s.
    useEffect(() => {
        let alive = true
        const pull = () => {
            api(`/status`)
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
            socket = new WebSocket(wsUrl("/ws/alerts"))

            socket.onopen = () => {
                setError(null)
                if (dropped) {
                    api(`/alerts`).then(res => res.json()).then(setAlerts).catch(() => {})
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

    // set it on <html> so body and everything else inherit the palette.
    // theme-anim cross-fades the colours for a moment instead of snapping
    useEffect(() => {
        const root = document.documentElement;
        root.classList.add("theme-anim");
        root.setAttribute("data-theme", theme);
        try { localStorage.setItem("og-theme", theme) } catch { /* private mode */ }
        const id = setTimeout(() => root.classList.remove("theme-anim"), 450);
        return () => clearTimeout(id);
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
    const matchesTerm = (a, term) => {
        const t = (term || "").trim().toLowerCase();
        if (!t) return true;
        return [
            a.host, a.user, a.event_type, a.domain, a.src_ip, a.dst_ip,
            a.source, a.mitre_technique, a.description, a.brand_target, a.status,
            a.severity, a.target_url, a.action_endpoint, a.process_name, a.alert_id,
            a.mitre_technique && MITRE[a.mitre_technique],
        ].some(v => v && String(v).toLowerCase().includes(t));
    };
    // live typeahead (as you type) and the committed results (after Enter)
    const liveHits = query.trim() ? alerts.filter(a => matchesTerm(a, query)) : [];
    const looseHits = alerts
        .filter(a => matchesTerm(a, searchTerm))
        .sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp));
    // a chart click ("GitHub" in the brands chart) means exactly that value of
    // that field, so the drill-down matches the count on the bar. Typed
    // searches stay loose (substring across fields).
    const clickedKind = searchKind === "filter" ? entityKind(looseHits, searchTerm) : null;
    const searchHits = clickedKind
        ? looseHits.filter(a => ENTITY_FIELDS.some(([f, label]) =>
            label === clickedKind.label && String(a[f] ?? "").toLowerCase() === searchTerm.trim().toLowerCase()))
        : looseHits;

    // run a search: open the dedicated results page and remember the term
    const runSearch = (term) => {
        const t = (term || "").trim();
        if (!t) return;
        setSearchKind("search");
        if (page !== "search") setSearchFrom(page);
        setSearchTerm(t); setQuery(t); setSelectedId(null); setPage("search"); setMenu(null);
        setRecentSearches(prev => {
            const next = [t, ...prev.filter(x => x.toLowerCase() !== t.toLowerCase())].slice(0, 8);
            try { localStorage.setItem("og_recent_searches", JSON.stringify(next)) } catch {}
            return next;
        });
    };
    const clearRecent = () => { setRecentSearches([]); try { localStorage.removeItem("og_recent_searches") } catch {} };
    // a chart-click "filter" (technique/brand/host): same scoped view, framed as a filter you can remove
    const filterBy = (term) => {
        const t = (term || "").trim();
        if (!t) return;
        setSearchKind("filter");
        if (page !== "search") setSearchFrom(page);
        setSearchTerm(t); setQuery(""); setSelectedId(null); setPage("search"); setMenu(null);
    };

    // the dashboard/alert filters no longer react to the live search text —
    // only the severity + engine filters scope the panels below
    const scoped = alerts.filter(a =>
        (!filter || a.severity === filter) &&
        (!srcFilter || a.source === srcFilter)
    );

    const countOf = (sev) => scoped.filter(a => a.severity === sev).length;

    // severity counts that ignore the active severity filter, so the stat cards
    // keep showing every severity (and stay clickable) while a filter is applied
    const sevScoped = alerts.filter(a => (!srcFilter || a.source === srcFilter));
    const sevCount = (sev) => sevScoped.filter(a => a.severity === sev).length;

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
    const inDateRange = (a) => {
        if (!dateFilter) return true;
        const t = new Date(a.timestamp).getTime();
        if (isNaN(t)) return false;
        const startToday = new Date(); startToday.setHours(0, 0, 0, 0);
        if (dateFilter === "today") return t >= startToday.getTime();
        if (dateFilter === "yesterday") return t >= startToday.getTime() - 864e5 && t < startToday.getTime();
        if (dateFilter === "7d") return t >= Date.now() - 7 * 864e5;
        if (dateFilter === "30d") return t >= Date.now() - 30 * 864e5;
        if (dateFilter === "custom") {
            const from = dateFrom ? new Date(dateFrom).getTime() : -Infinity;
            const to = dateTo ? new Date(dateTo).getTime() + 864e5 : Infinity; // end day inclusive
            return t >= from && t < to;
        }
        return true;
    };
    const visible = [...scoped].filter(inDateRange).filter(a => matchesTerm(a, alertQuery)).sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp));
    const selected = alerts.find(a => a.alert_id === selectedId);
    const maxCount = Math.max(1, ...SEVERITIES.map(countOf));
    const engineCounts = countBy("source");

    // extra chart data (#25): detections by engine, top impersonated brands, triage status
    const engines = Object.entries(engineCounts).sort((a, b) => b[1] - a[1]);
    const engineMax = Math.max(1, ...engines.map(e => e[1]));
    const brands = topN("brand_target", 5);
    const brandMax = Math.max(1, ...brands.map(b => b[1]));
    const STATUSES = ["new", "triaged", "resolved"];
    const statusCounts = STATUSES.map(s => [s, scoped.filter(a => a.status === s).length]);
    const statusMax = Math.max(1, ...statusCounts.map(s => s[1]));
    // more charts: top targeted domains, alerts by user, confidence distribution
    const domains = topN("domain", 5);
    const domainMax = Math.max(1, ...domains.map(d => d[1]));
    const users = topN("user", 5);
    const userMax = Math.max(1, ...users.map(u => u[1]));
    const CONF_BANDS = [[0, 20], [20, 40], [40, 60], [60, 80], [80, 100]];
    const confBuckets = CONF_BANDS.map(([lo, hi]) => {
        const n = scoped.filter(a => a.confidence != null && a.confidence * 100 >= lo && (hi === 100 ? a.confidence * 100 <= 100 : a.confidence * 100 < hi)).length;
        return [`${lo}–${hi}%`, n];
    });
    const confMax = Math.max(1, ...confBuckets.map(c => c[1]));

    const byNewest = [...scoped].sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp));
    const recent = byNewest.slice(0, 7);
    const criticals = byNewest.filter(a => a.severity === "critical").slice(0, 3);
    const untriaged = scoped.filter(a => a.status === "new").length;

    // real alert volume over time, bucketed by severity
    const activity = buildActivity(alerts);
    const totalSeries = activity.map(b => b.critical + b.high + b.medium + b.low);
    const sevSeries = (k) => activity.map(b => b[k] || 0);

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

    // labels for the pages an alert can be opened from
    const pageTitle = (p) => p === "search" ? "Search" : p === "overview" ? "Dashboard"
        : (NAV.flatMap(s => s.items).find(i => i.id === p)?.label ?? "Alerts");
    // open the full graph with just these alerts' entities lit up
    const seeInGraph = (subset, label) => {
        setGraphFocus({ label, ids: [...scopeIds(subset)] });
        setSelectedId(null); setPage("graph"); setMenu(null);
    };
    const openAlert = (id) => {
        if (page !== "alert-detail") setCameFrom(page);
        setSelectedId(id); setPage("alert-detail");
    };

    // "What needs attention": the few things worth acting on first, worked out
    // from the alerts in view (so it follows the dashboard's filters).
    // Each finding: { tone: "bad" | "warn" | "good", body: <JSX> }
    const findings = [];
    // entity names in a finding open that entity's drill-down
    const entityLinks = (names) => names.map((n, i) => (
        <Fragment key={n}>{i ? ", " : ""}<button className="att-link" onClick={() => filterBy(n)}>{n}</button></Fragment>
    ));
    const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
    // lab / loopback addresses aren't attacker infrastructure
    const isLocal = (v) => /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(v || "");
    const hostsOf = (pred) => [...new Set(scoped.filter(pred).map(a => a.host).filter(Boolean))];
    const byHost = (list) => Object.entries(list.reduce((m, a) => (m[a.host] = (m[a.host] || 0) + 1, m), {}))
        .sort((x, y) => y[1] - x[1]);

    // 1. two different engines flagging the same machine
    const engineHosts = {};
    scoped.forEach(a => { if (a.host) (engineHosts[a.host] ||= new Set()).add(a.source); });
    const corroborated = Object.keys(engineHosts).filter(h => engineHosts[h].has("verifyeye") && engineHosts[h].has("spectrac2"));
    if (corroborated.length) findings.push({ tone: "bad", body: <>
        <b>{entityLinks(corroborated)}</b> {corroborated.length === 1 ? "has" : "have"} both a phishing and a C2 alert.
        Two engines agreeing on one machine usually means a real compromise — investigate first.
    </> });

    // 2. outside infrastructure that several hosts talk to
    const shared = [];
    [["domain", "domain"], ["dst_ip", "IP"]].forEach(([field, kind]) => {
        const hosts = {};
        scoped.forEach(a => { const v = a[field]; if (v && a.host && !isLocal(v)) (hosts[v] ||= new Set()).add(a.host); });
        Object.entries(hosts).filter(([, hs]) => hs.size > 1).forEach(([v, hs]) => shared.push({ v, kind, n: hs.size }));
    });
    shared.sort((x, y) => y.n - x.n).slice(0, 2).forEach(({ v, kind, n }) => findings.push({ tone: "bad", body: <>
        The {kind} <b>{entityLinks([v])}</b> is contacted by {plural(n, "host")} — shared attacker
        infrastructure. Blocking it cuts them all off at once.
    </> }));

    // 3. criticals nobody has looked at yet
    const openCrit = scoped.filter(a => a.severity === "critical" && a.status === "new");
    if (openCrit.length) {
        const top = byHost(openCrit).slice(0, 3);
        findings.push({ tone: "bad", body: <>
            <b>{plural(openCrit.length, "critical alert")}</b> still untriaged — most on{" "}
            {top.map(([h, n], i) => <Fragment key={h}>{i ? ", " : ""}<button className="att-link" onClick={() => filterBy(h)}>{h}</button> ({n})</Fragment>)}.
        </> });
    }

    // 4. what's new since yesterday
    const lastDay = scoped.filter(a => now - new Date(a.timestamp).getTime() < 864e5);
    if (lastDay.length) {
        const hosts = hostsOf(a => now - new Date(a.timestamp).getTime() < 864e5);
        findings.push({ tone: "warn", body: <>
            <b>{plural(lastDay.length, "new alert")}</b> in the last 24 hours
            {hosts.length ? <>, on {entityLinks(hosts.slice(0, 3))}{hosts.length > 3 ? ` and ${hosts.length - 3} more` : ""}</> : null}.
        </> });
    }

    // 5. the rest of the untriaged queue
    const openOther = scoped.filter(a => a.status === "new" && a.severity !== "critical").length;
    if (openOther) findings.push({ tone: "warn", body: <>
        <b>{openOther}</b> other {openOther === 1 ? "alert is" : "alerts are"} waiting for triage
        ({Math.round((scoped.filter(a => a.status === "new").length / Math.max(1, scoped.length)) * 100)}% of the queue).
    </> });

    if (!findings.length && scoped.length) findings.push({ tone: "good", body: <>
        All clear — no machines flagged by both engines, no shared attacker infrastructure, and every critical alert has been triaged.
    </> });

    const pageLabel = page === "alert-detail"
        ? pageTitle(cameFrom)
        : page === "profile"
        ? "Profile"
        : page === "search"
        ? (searchKind === "filter" ? "Filtered" : "Search")
        : NAV.flatMap(s => s.items).find(i => i.id === page)?.label ?? "Alerts";


    async function runAiTriage() {
        setAiLoading(true)
        setAiError(null)

        try {
            const res = await api(`/ai/summary`)
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
            const res = await api(`/ai/chat`, {
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
                                    className={`nav-item ${page === item.id || (page === "alert-detail" && item.id === cameFrom) ? "active" : ""}`}
                                    onClick={() => { setPage(item.id); setSelectedId(null); setGraphFocus(null); if (window.innerWidth <= 820) setNavOpen(false); }}
                                    title={item.label}
                                >
                                    <span className="nav-icon"><Icon />
                                        {item.id === "ask" && (askActivity.running.size > 0 || askActivity.unread.size > 0) && (
                                            <span className={`nav-ask-dot ${askActivity.running.size ? "running" : ""}`}
                                                title={askActivity.running.size ? "Ask AI is working on a reply" : "Ask AI has a new reply"} />
                                        )}
                                    </span>
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
                                <button className="back" onClick={() => setPage(cameFrom)}>{pageTitle(cameFrom)}</button>
                                <span className="slash">/</span>
                                {selected ? selected.event_type : "detail"}
                            </>
                        ) : pageLabel}
                    </div>
                    <div className="searchbox hasmenu">
                        <Search />
                        <input
                            className="search"
                            placeholder="Search alerts, hosts, domains, IPs… (Enter)"
                            value={query}
                            onChange={e => setQuery(e.target.value)}
                            onFocus={() => setMenu("search")}
                            onKeyDown={e => { if (e.key === "Enter") runSearch(query); }}
                        />
                        {query && (
                            <button className="search-clear" onClick={() => setQuery("")} aria-label="Clear search">
                                <X />
                            </button>
                        )}
                        {menu === "search" && (
                            <div className="dropdown wide">
                                {query ? (
                                    <>
                                        <button className="dropdown-item search-all" onMouseDown={() => runSearch(query)}>
                                            <Search />
                                            <span>See all {liveHits.length} result{liveHits.length === 1 ? "" : "s"} for “{query}”</span>
                                            <span className="kbd">Enter</span>
                                        </button>
                                        {liveHits.slice(0, 6).map(a => (
                                            <button
                                                key={a.alert_id}
                                                className="dropdown-item search-hit"
                                                onMouseDown={() => { openAlert(a.alert_id); setMenu(null); }}
                                            >
                                                <span className={`sev ${a.severity}`}>{a.severity}</span>
                                                <span className="search-hit-main">
                                                    <span className="search-hit-title">{a.event_type}</span>
                                                    <span className="search-hit-sub">{a.host}{a.domain ? ` · ${a.domain}` : ""}</span>
                                                </span>
                                            </button>
                                        ))}
                                        {liveHits.length === 0 && <div className="dropdown-empty-row">No matches.</div>}
                                    </>
                                ) : recentSearches.length > 0 ? (
                                    <>
                                        <div className="dropdown-head">
                                            Recent searches
                                            <button className="dropdown-head-action" onMouseDown={clearRecent}>Clear</button>
                                        </div>
                                        {recentSearches.map(term => (
                                            <button key={term} className="dropdown-item search-recent" onMouseDown={() => runSearch(term)}>
                                                <Search /> <span>{term}</span>
                                            </button>
                                        ))}
                                    </>
                                ) : (
                                    <div className="dropdown-row">
                                        <span className="dropdown-title">Search the SOC</span>
                                        <span className="dropdown-sub">
                                            Matches host, user, event type, domain, IP, engine, technique, brand and description. Press Enter for full results.
                                        </span>
                                    </div>
                                )}
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
                            <div className="dropdown notif-dd">
                                <div className="dropdown-head">
                                    Notifications
                                    {untriaged > 0 && <span className="dropdown-head-count">{untriaged} new</span>}
                                </div>
                                <div className="dropdown-hint">Untriaged alerts needing a look — click one to investigate.</div>
                                {(() => {
                                    const notifs = [...alerts]
                                        .filter(a => a.status === "new")
                                        .sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp))
                                        .slice(0, 7);
                                    return notifs.length === 0 ? (
                                        <div className="dropdown-empty"><Bell /><p>You're all caught up.</p></div>
                                    ) : notifs.map(a => (
                                        <button
                                            key={a.alert_id}
                                            className="dropdown-item notif-item"
                                            onMouseDown={() => { openAlert(a.alert_id); setMenu(null); }}
                                        >
                                            <span className={`notif-dot sev-${a.severity}`} />
                                            <span className="notif-main">
                                                <span className="notif-title">{a.event_type}</span>
                                                <span className="notif-sub">{a.host} · {timeAgo(a.timestamp)}</span>
                                            </span>
                                            <span className={`sev ${a.severity}`}>{a.severity}</span>
                                        </button>
                                    ));
                                })()}
                                {untriaged > 0 && (
                                    <button className="dropdown-item notif-all" onMouseDown={() => { setFilter(null); setSrcFilter(null); setMenu(null); setPage("alerts"); }}>
                                        View all alerts →
                                    </button>
                                )}
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

                <div className="content" ref={contentRef}>

                    {filtering ? (
                        <div className="content-spinner"><div className="spinner" /></div>
                    ) : (
                    // keyed by page so a page change remounts the content and the
                    // enter animation (.content > *) plays; live alerts don't change it
                    <Fragment key={page}>

                    {(filter || srcFilter) && (page === "overview" || page === "alerts") && (
                        <div className="active-filters">
                            <span className="af-label">Filtered by</span>
                            {filter && (
                                <button className="af-chip" onClick={() => setFilter(null)}>
                                    <span className={`dot sev-${filter}`} /> {filter}
                                    <X />
                                </button>
                            )}
                            {srcFilter && (
                                <button className="af-chip" onClick={() => setSrcFilter(null)}>
                                    {srcFilter}
                                    <X />
                                </button>
                            )}
                            <button className="af-clear" onClick={() => { setFilter(null); setSrcFilter(null); }}>Clear all</button>
                        </div>
                    )}

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

                            <Panel
                                title="Alerts"
                                note={alertQuery.trim() ? `${visible.length} match “${alertQuery.trim()}”` : `${visible.length} shown`}
                                flush
                            >
                                <div className="alerts-search">
                                    <Search />
                                    <input
                                        value={alertQuery}
                                        onChange={e => setAlertQuery(e.target.value)}
                                        onKeyDown={e => { if (e.key === "Escape") setAlertQuery("") }}
                                        placeholder="Search these alerts — host, user, domain, IP, URL, process, technique…"
                                        aria-label="Search alerts"
                                    />
                                    {alertQuery && (
                                        <button className="search-clear" onClick={() => setAlertQuery("")} aria-label="Clear alert search"><X /></button>
                                    )}
                                </div>
                                <div className="filterbar">
                                    <span className="label">Severity</span>
                                    <button className={`chip ${filter === null ? "on" : ""}`} onClick={() => setFilter(null)}>all</button>
                                    {SEVERITIES.map(sev => (
                                        <button key={sev} className={`chip ${filter === sev ? "on" : ""}`} onClick={() => setFilter(sev)}>
                                            {sev}
                                        </button>
                                    ))}
                                    <span className="filterbar-sep" />
                                    <span className="label">When</span>
                                    <DateRangePicker
                                        value={dateFilter}
                                        from={dateFrom}
                                        to={dateTo}
                                        onPreset={(k) => { setDateFilter(k); setDateFrom(""); setDateTo(""); }}
                                        onCustom={(f, t) => { setDateFrom(f); setDateTo(t); setDateFilter("custom"); }}
                                    />
                                </div>

                                {visible.length === 0 ? (
                                    alertQuery.trim() ? (
                                        <div className="empty">
                                            No alerts match “{alertQuery.trim()}”{(filter || dateFilter) ? " with the current filters" : ""}.{" "}
                                            <button className="link" onClick={() => setAlertQuery("")}>Clear search</button>
                                        </div>
                                    ) : (
                                        <div className="empty">
                                            No alerts. Post one at <code>localhost:8000/docs</code>.
                                        </div>
                                    )
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
                                                                <span className="cell-top"><Hl text={a.event_type} q={alertQuery} /></span>
                                                                <span className="cell-sub">{timeAgo(a.timestamp)} · {exactTime(a.timestamp)}</span>
                                                            </span>
                                                        </span>
                                                    </td>
                                                    <td><span className={`sev ${a.severity}`}>{a.severity}</span></td>
                                                    <td>
                                                        <span className="cell-main">
                                                            <span className="cell-top"><Hl text={a.host} q={alertQuery} /></span>
                                                            <span className="cell-sub">{a.user ? <Hl text={a.user} q={alertQuery} /> : "no user"}</span>
                                                        </span>
                                                    </td>
                                                    <td className={`td-mono td-wide ${a.domain ? "td-dim" : "td-faint"}`}>{a.domain ? <Hl text={a.domain} q={alertQuery} /> : "—"}</td>
                                                    <td><span className="tag"><Hl text={a.source} q={alertQuery} /></span></td>
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
                            <button className="detail-back" onClick={() => setPage(cameFrom)}>
                                <ArrowRight style={{ transform: "rotate(180deg)" }} /> Back to {pageTitle(cameFrom)}
                            </button>
                            <div className="detail-title">
                                <span className={`sev ${selected.severity}`}>{selected.severity}</span>
                                <h2>{selected.event_type}</h2>
                                <span className="tag">{selected.source}</span>
                                <span className="tag">{selected.status}</span>
                                <span className="when" title={new Date(selected.timestamp).toLocaleString()}>{exactTime(selected.timestamp)} · {timeAgo(selected.timestamp)}</span>
                            </div>

                            <div className="split">
                                <div>
                                    {selected.description && <p className="note">{selected.description}</p>}

                                    {/* what VerifyEye's agent saw at this page (#3) */}
                                    {selected.target_url && <EvidencePanel alert={selected} />}

                                    <Panel
                                        title="Attack graph"
                                        note={`neighbourhood of ${selected.host}`}
                                        action="See in network graph"
                                        onAction={() => seeInGraph([selected], `this ${selected.event_type} alert`)}
                                    >
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
                                <Stat icon={Flag}        label="Total alerts" value={sevScoped.length}    spark={totalSeries}        onClick={() => setFilter(null)} active={!filter} />
                                <Stat icon={ShieldAlert} label="Critical"     value={sevCount("critical")} spark={sevSeries("critical")} tone="critical" onClick={() => setFilter(f => f === "critical" ? null : "critical")} active={filter === "critical"} />
                                <Stat icon={TriangleAlert} label="High"       value={sevCount("high")}    spark={sevSeries("high")}   tone="high"   onClick={() => setFilter(f => f === "high" ? null : "high")} active={filter === "high"} />
                                <Stat icon={Activity}    label="Medium"       value={sevCount("medium")}  spark={sevSeries("medium")} tone="medium" onClick={() => setFilter(f => f === "medium" ? null : "medium")} active={filter === "medium"} />
                                <Stat icon={Inbox}       label="Low"          value={sevCount("low")}     spark={sevSeries("low")}    tone="low"    onClick={() => setFilter(f => f === "low" ? null : "low")} active={filter === "low"} />
                                <Stat icon={Target}      label="Untriaged"    value={untriaged}           spark={totalSeries}         tone="accent" />
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
                                    note={`${alerts.length} alerts by severity`}
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
                                        total={sevScoped.length}
                                        slices={SEVERITIES.map(sev => ({ key: sev, n: sevCount(sev) }))}
                                        onSlice={(key) => setFilter(f => f === key ? null : key)}
                                        activeKey={filter}
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
                                                    onClick={() => filterBy(id)}
                                                />
                                            ))}
                                        </div>
                                    )}
                                </Panel>
                            </div>

                            <div className="grid-3">
                                <Panel title="Detections by engine" note={`${countDistinct("source")} engine${countDistinct("source") === 1 ? "" : "s"}`}>
                                    <PieChart
                                        slices={engines.map(([src, n]) => ({ key: src, n, fill: src === "verifyeye" ? "var(--eng-1)" : src === "spectrac2" ? "var(--eng-2)" : "var(--eng-3)" }))}
                                        onSlice={(key) => setSrcFilter(f => f === key ? null : key)}
                                        activeKey={srcFilter}
                                    />
                                </Panel>

                                <Panel title="Top impersonated brands" note="phishing targets">
                                    {brands.length === 0 ? (
                                        <div className="empty">No brand impersonation seen.</div>
                                    ) : (
                                        <div className="barrows">
                                            {brands.map(([b, n]) => (
                                                <BarRow key={b} label={b} value={n} max={brandMax} tone="high" onClick={() => filterBy(b)} />
                                            ))}
                                        </div>
                                    )}
                                </Panel>

                                <Panel title="Triage status" note={`${scoped.length} alerts`}>
                                    <PieChart
                                        slices={statusCounts.map(([s, n]) => ({ key: s, n, fill: s === "new" ? "var(--fill-critical)" : s === "triaged" ? "var(--fill-medium)" : "var(--good)" }))}
                                        onSlice={(key) => filterBy(key)}
                                    />
                                </Panel>
                            </div>

                            <div className="grid-3">
                                <Panel title="Top targeted domains" note="by alert count">
                                    {domains.length === 0 ? (
                                        <div className="empty">No domains seen.</div>
                                    ) : (
                                        <div className="barrows">
                                            {domains.map(([d, n]) => (
                                                <BarRow key={d} label={d} value={n} max={domainMax} tone="high" onClick={() => filterBy(d)} />
                                            ))}
                                        </div>
                                    )}
                                </Panel>

                                <Panel title="Alerts by user" note="most affected accounts">
                                    {users.length === 0 ? (
                                        <div className="empty">No users attributed.</div>
                                    ) : (
                                        <BarChart
                                            data={users.map(([u, n]) => ({ label: u, value: n, fill: "var(--accent)" }))}
                                            onBar={(d) => filterBy(d.label)}
                                        />
                                    )}
                                </Panel>

                                <Panel title="Confidence distribution" note="detector confidence">
                                    <BarChart data={confBuckets.map(([band, n]) => ({ label: band, value: n, tone: "low" }))} />
                                </Panel>
                            </div>

                            <div className="grid-2">
                                <Panel
                                    title="Network graph"
                                    note={`${countDistinct("host")} hosts · ${countDistinct("domain")} domains`}
                                    // filtered: light up what's filtered. unfiltered: just open the graph
                                    action={(filter || srcFilter) ? "See in network graph" : "Open"}
                                    onAction={() => (filter || srcFilter)
                                        ? seeInGraph(scoped, [filter, srcFilter].filter(Boolean).join(" · ") + " alerts")
                                        : (setGraphFocus(null), setPage("graph"))}
                                >
                                    {alerts.length === 0 ? (
                                        <CardEmpty glyph={Share2} text="Graph is empty" />
                                    ) : (
                                        // follows the dashboard's severity/engine filters like every other panel
                                        <GraphCanvas compact refreshKey={alerts.length} scope={(filter || srcFilter) ? scoped : null} limit={150} />
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
                                                    onClick={() => filterBy(h.host)}
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
                                                        <td className="td-mono td-faint" title={exactTime(a.timestamp)}>{timeAgo(a.timestamp)}</td>
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
                                                    <td className="td-wide td-faint td-mono" title={exactTime(last)}>{timeAgo(last)}</td>
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
                                                <tr key={user} className="row-link" onClick={() => filterBy(user)}>
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
                                                    <td className="td-wide td-faint td-mono" title={exactTime(last)}>{timeAgo(last)}</td>
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
                            <GraphExplorer
                                alerts={alerts}
                                refreshKey={alerts.length}
                                onOpenAlert={openAlert}
                                onFilter={filterBy}
                                focus={graphFocus}
                                onClearFocus={() => setGraphFocus(null)}
                            />
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
                                                    <tr key={host} className="row-link" onClick={() => filterBy(host)}>
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
                                                    <tr key={user} className="row-link" onClick={() => filterBy(user)}>
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
                                                    <tr key={domain} className="row-link" onClick={() => filterBy(domain)}>
                                                        <td className="td-mono">{domain}</td>
                                                        <td><span className={`sev ${worst}`}>{worst}</span></td>
                                                        <td className="td-mono td-dim">{n}</td>
                                                        <td className="td-mono td-dim td-wide">{hosts.join(", ")}</td>
                                                        <td className="td-mono td-faint" title={exactTime(last)}>{timeAgo(last)}</td>
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
                                            <tr key={src} className="row-link" onClick={() => { setSrcFilter(src); setFilter(null); setQuery(""); setPage("alerts"); }}>
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

                    {/* ── the SOC agent: saved chats, tools, approvals ── */}
                    {page === "ask" && (
                        <AskAI
                            onOpenAlert={openAlert}
                            onFilter={filterBy}
                            // the dashboard's own views, for the agent to draw inside its replies
                            views={{
                                alerts,
                                dashboard: (subset, term) => (
                                    <ScopedDashboard alerts={subset} term={term} onOpen={openAlert} onFilter={filterBy} onSeeGraph={seeInGraph} />
                                ),
                                graph: (focus, onClear) => (
                                    <GraphExplorer alerts={alerts} refreshKey={alerts.length} onOpenAlert={openAlert}
                                        onFilter={filterBy} focus={focus} onClearFocus={onClear} />
                                ),
                                openGraph: seeInGraph,
                                openLedger: () => { setSelectedId(null); setPage("ledger") },
                            }}
                        />
                    )}

                    {/* ── search results: a full dashboard scoped to the term ── */}
                    {page === "search" && (
                        <>
                            <button className="detail-back" onClick={() => setPage(searchFrom)}>
                                <ArrowRight style={{ transform: "rotate(180deg)" }} /> Back to {pageTitle(searchFrom).toLowerCase() === "dashboard" ? "dashboard" : pageTitle(searchFrom)}
                            </button>
                            {searchKind === "filter" ? (
                                <div className="search-result-head">
                                    <div>
                                        <span className="search-eyebrow">Filtered view</span>
                                        <div className="filter-headline">
                                            <span>Filtered by</span>
                                            <button className="af-chip" onClick={() => setPage("overview")} title="Remove filter">
                                                {searchTerm} <X />
                                            </button>
                                        </div>
                                    </div>
                                    <span className="search-result-count">{searchHits.length} alert{searchHits.length === 1 ? "" : "s"}</span>
                                </div>
                            ) : (
                                <div className="search-result-head">
                                    <div>
                                        <span className="search-eyebrow">Search</span>
                                        <h2>Results for “{searchTerm}”</h2>
                                    </div>
                                    <span className="search-result-count">{searchHits.length} alert{searchHits.length === 1 ? "" : "s"}</span>
                                </div>
                            )}
                            {searchHits.length === 0 ? (
                                <CardEmpty glyph={Search} text={`No alerts match “${searchTerm}”`} />
                            ) : (
                                <ScopedDashboard alerts={searchHits} term={searchTerm} onOpen={openAlert} onFilter={filterBy} onSeeGraph={seeInGraph} asEntity={searchKind === "filter"} />
                            )}
                        </>
                    )}

                    </Fragment>
                    )}

                </div>
            </div>

            {/* rendered once, outside the pages: one chat, on every page,
                and the conversation survives switching pages. Not on Ask AI,
                which is the full version (and its send button sits there) */}
            {page !== "ask" && (
                <AiChat
                    messages={chatMessages}
                    loading={chatLoading}
                    onSend={sendChat}
                    onClear={() => setChatMessages([])}
                />
            )}
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
        api(`/auth/profile`, {
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
        const res = await api(`/ai/investigate/pipeline`, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hostname: alert.host }),
        })
        if (!res.ok) throw new Error()
        setInvestigation(await res.json())
    })
    const isolate = () => run("isolate", async () => {
        const res = await api(`/hosts/${encodeURIComponent(alert.host)}/isolate`, { method: "POST" })
        if (!res.ok) throw new Error()
        setIsolation(await res.json())
    })
    const exportOcsf = () => run("ocsf", async () => {
        const res = await api(`/alerts/${alert.alert_id}/ocsf`)
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
            {investigation && (
                <Modal onClose={() => setInvestigation(null)}>
                    <InvestigationResult
                        data={investigation}
                        onClose={() => setInvestigation(null)}
                        onIsolate={isolate}
                        isolating={busy === "isolate"}
                        isolated={isolation}
                    />
                </Modal>
            )}
            {ocsf && (
                <Modal onClose={() => setOcsf(null)}>
                    <OcsfCard data={ocsf} alertId={alert.alert_id} onClose={() => setOcsf(null)} />
                </Modal>
            )}
        </>
    )
}

// centered modal dialog: backdrop click or Escape closes it
function Modal({ onClose, children }) {
    useEffect(() => {
        const onKey = (e) => { if (e.key === "Escape") onClose() }
        window.addEventListener("keydown", onKey)
        return () => window.removeEventListener("keydown", onKey)
    }, [onClose])
    return (
        <div className="modal-backdrop" onClick={onClose}>
            <div className="modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
                {children}
            </div>
        </div>
    )
}

// a readable OCSF Class 2001 Security Finding card (not a raw JSON dump),
// with the raw form tucked behind a toggle + copy / download.
function OcsfCard({ data, alertId, onClose }) {
    const [showRaw, setShowRaw] = useState(false)
    const [copied, setCopied] = useState(false)
    const fi = data.finding_info || {}
    const dev = data.device || {}
    const sevTone = data.severity_id >= 5 ? "critical" : data.severity_id >= 4 ? "high" : data.severity_id >= 3 ? "medium" : "low"
    const when = data.time ? new Date(data.time).toLocaleString() : "—"

    const copy = () => {
        try { navigator.clipboard.writeText(JSON.stringify(data, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch (e) {}
    }
    const download = () => {
        try {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
            const url = URL.createObjectURL(blob)
            const a = document.createElement("a")
            a.href = url; a.download = `ocsf-${alertId || "finding"}.json`; a.click()
            URL.revokeObjectURL(url)
        } catch (e) {}
    }

    return (
        <div className="ocsf-card">
            <div className="ocsf-top">
                <div className="ocsf-title">
                    <span className={`sev ${sevTone}`}>{data.severity}</span>
                    <div className="ocsf-titletext">
                        <strong>{fi.title || "Security Finding"}</strong>
                        <span className="ocsf-badge">OCSF {data.metadata?.version || "1.2"} · Class {data.class_uid}</span>
                    </div>
                </div>
                <button className="icon-btn" onClick={onClose} aria-label="Close"><X /></button>
            </div>

            {fi.desc && <p className="note ocsf-desc">{fi.desc}</p>}

            <div className="ocsf-grid">
                <div className="ocsf-f"><span className="ocsf-k">Class</span>{data.class_name} ({data.class_uid})</div>
                <div className="ocsf-f"><span className="ocsf-k">Activity</span>{data.activity_name}</div>
                <div className="ocsf-f"><span className="ocsf-k">Status</span>{data.status}</div>
                <div className="ocsf-f"><span className="ocsf-k">Confidence</span>{data.confidence_score}%</div>
                <div className="ocsf-f"><span className="ocsf-k">Severity</span>{data.severity} ({data.severity_id})</div>
                <div className="ocsf-f"><span className="ocsf-k">Time</span>{when}</div>
                <div className="ocsf-f"><span className="ocsf-k">Device</span>{dev.hostname}{dev.ip ? ` · ${dev.ip}` : ""}</div>
                <div className="ocsf-f"><span className="ocsf-k">Product</span>{data.metadata?.product?.name} · {data.metadata?.product?.feature?.name}</div>
                <div className="ocsf-f ocsf-wide"><span className="ocsf-k">Finding UID</span><span className="mono">{fi.uid}</span></div>
            </div>

            {Array.isArray(data.attacks) && data.attacks.length > 0 && (
                <div className="ocsf-section">
                    <div className="ocsf-sec-title">MITRE ATT&CK</div>
                    <div className="chip-row">
                        {data.attacks.map((a, i) => (
                            <span className="mitre-chip" key={i}>
                                {a.technique?.uid} · {a.technique?.name}
                                <span className="mitre-tactic">{a.tactic?.name}</span>
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {Array.isArray(data.resources) && data.resources.length > 0 && (
                <div className="ocsf-section">
                    <div className="ocsf-sec-title">Affected resources</div>
                    <div className="chip-row">
                        {data.resources.map((r, i) => (
                            <span className="res-chip" key={i}><Globe /> {r.name} <span className="res-type">{r.type}</span></span>
                        ))}
                    </div>
                </div>
            )}

            <div className="ocsf-foot">
                <button className="btn" onClick={() => setShowRaw(v => !v)}>{showRaw ? "Hide raw JSON" : "View raw JSON"}</button>
                <button className="btn" onClick={copy}>{copied ? "Copied ✓" : "Copy JSON"}</button>
                <button className="btn" onClick={download}>Download .json</button>
            </div>
            {showRaw && <pre className="code-block">{JSON.stringify(data, null, 2)}</pre>}
        </div>
    )
}

// renders the multi-agent pipeline result (correlation -> triage -> containment)
// the multi-agent investigation, laid out the way it ran: three agents in a
// row, their verdict, the evidence, and a numbered response plan you can act on
function InvestigationResult({ data, onClose, onIsolate, isolating, isolated }) {
    const cor = data.correlation || {}, t = data.triage || {}, c = data.containment || {}
    const score = Math.max(0, Math.min(100, t.risk_score ?? 0))
    const tone = score >= 70 ? "critical" : score >= 40 ? "high" : "good"
    const actions = c.recommended_actions || []
    const sources = cor.sources || []
    const vectors = sources.includes("verifyeye") && sources.includes("spectrac2") ? "Phishing and C2"
        : cor.is_multi_vector ? "Multiple" : "Single"
    const steps = [
        { icon: GitMerge, name: "Correlate", result: `${cor.alert_count ?? 0} alerts · ${sources.length} engine${sources.length === 1 ? "" : "s"}` },
        { icon: Gauge, name: "Triage", result: label(t.classification) || "—" },
        { icon: ShieldCheck, name: "Contain", result: `${actions.length} action${actions.length === 1 ? "" : "s"} proposed` },
    ]
    // score ring: r=30 -> circumference ≈ 188.5
    const C = 2 * Math.PI * 30

    return (
        <div className="iv">
            <header className="iv-head">
                <div>
                    <span className="iv-eyebrow"><Sparkles /> AI investigation</span>
                    <h3 className="iv-host">{data.host}</h3>
                </div>
                {onClose && <button className="icon-btn" onClick={onClose} aria-label="Close"><X /></button>}
            </header>

            <ol className="iv-steps" aria-label="Agents that ran">
                {steps.map((st, i) => (
                    <li key={st.name} style={{ "--i": i }}>
                        <span className="iv-step-ico"><st.icon /></span>
                        <div><b>{st.name}</b><span>{st.result}</span></div>
                    </li>
                ))}
            </ol>

            <section className={`iv-verdict ${tone}`}>
                <svg className="iv-ring" viewBox="0 0 72 72" role="img" aria-label={`Risk ${score} out of 100`}>
                    <circle cx="36" cy="36" r="30" className="iv-ring-track" />
                    <circle cx="36" cy="36" r="30" className="iv-ring-fill"
                        strokeDasharray={`${(score / 100) * C} ${C}`} transform="rotate(-90 36 36)" />
                    <text x="36" y="40" textAnchor="middle">{score}</text>
                </svg>
                <div className="iv-verdict-body">
                    <span className="iv-k">Verdict · risk {score}/100</span>
                    <div className="iv-verdict-title">{label(t.classification) || "No verdict"}</div>
                    <div className="iv-meters">
                        {t.confidence != null && (
                            <div><span>Confidence</span><i><em style={{ width: `${Math.round(t.confidence * 100)}%` }} /></i><b>{Math.round(t.confidence * 100)}%</b></div>
                        )}
                        {t.false_positive_probability != null && (
                            <div><span>False positive</span><i><em className="fp" style={{ width: `${Math.round(t.false_positive_probability * 100)}%` }} /></i><b>{Math.round(t.false_positive_probability * 100)}%</b></div>
                        )}
                    </div>
                </div>
            </section>

            <section className="iv-evidence">
                <div><span className="iv-k">Scope</span><b>{label(cor.blast_radius) || "—"}</b></div>
                <div><span className="iv-k">Attack vectors</span><b>{vectors}</b></div>
                <div><span className="iv-k">Alerts correlated</span><b>{cor.alert_count ?? "—"}</b></div>
                <div className="wide">
                    <span className="iv-k">Engines</span>
                    <div className="iv-chips">
                        {sources.length ? sources.map(src => <span key={src} className={`iv-chip eng eng-${src}`}>{src}</span>) : "—"}
                    </div>
                </div>
                <div className="wide">
                    <span className="iv-k">MITRE ATT&amp;CK</span>
                    <div className="iv-chips">
                        {(cor.mitre_techniques || []).length ? cor.mitre_techniques.map(id => (
                            <span key={id} className="iv-chip"><b>{id}</b>{MITRE_NAMES[id] ? ` ${MITRE_NAMES[id]}` : ""}</span>
                        )) : "—"}
                    </div>
                </div>
            </section>

            <section>
                <div className="iv-sec-head">
                    Recommended response
                    {c.requires_human_approval && <span className="iv-approval"><UserCheck /> Needs your approval</span>}
                </div>
                <ol className="iv-actions">
                    {actions.map((a, i) => (
                        <li key={i} className="iv-action">
                            <span className="iv-action-n">{i + 1}</span>
                            <div className="iv-action-body">
                                <div className="iv-action-top">
                                    <b>{label(a.action)}</b>
                                    <span className={`urg ${(a.urgency || "").toLowerCase()}`}>{humanize(a.urgency)}</span>
                                </div>
                                <p>{a.description}</p>
                                {a.action === "NETWORK_ISOLATION" && onIsolate && (
                                    isolated
                                        ? <span className="iv-done"><Check /> Isolation recorded{isolated.simulated ? " (simulated)" : ""}</span>
                                        : <button className="btn danger iv-act" onClick={onIsolate} disabled={isolating}>
                                            {isolating ? <><span className="btn-spinner" /> Isolating…</> : <><ShieldOff /> Isolate {data.host}</>}
                                          </button>
                                )}
                            </div>
                        </li>
                    ))}
                </ol>
            </section>
        </div>
    )
}

// the decision ledger: lists hash-chained entries and verifies the chain
const shortHash = (h) => h ? `${h.slice(0, 10)}…${h.slice(-6)}` : "—"

// how each ledger stage looks, and a sentence for each entry
const LEDGER_STAGES = {
    AI_ANALYST_CONSULTATION: { icon: Bot, tone: "ai", name: "AI analyst" },
    EDR_CONTAINMENT: { icon: ShieldOff, tone: "contain", name: "Containment" },
}
const ledgerStage = (e) => LEDGER_STAGES[e.stage] || { icon: Activity, tone: "", name: humanize(e.stage) }
const ledgerTitle = (e) => (e.action_taken || "").startsWith("NETWORK_ISOLATION")
    ? `Isolated ${e.entity_id}` : label(e.action_taken)
const ledgerSimulated = (e) => (e.action_taken || "").endsWith("_SIMULATED")
const ledgerByAI = (e) => (e.analyst_user || "").startsWith("system")
function dayLabel(ts) {
    const d = new Date(ts); if (isNaN(d)) return "Undated"
    const start = new Date(); start.setHours(0, 0, 0, 0)
    if (d >= start) return "Today"
    if (d >= start - 864e5) return "Yesterday"
    return d.toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" })
}

function LedgerActor({ entry }) {
    const ai = ledgerByAI(entry)
    return (
        <span className={`lg-actor ${ai ? "ai" : "human"}`}>
            {ai ? <Bot /> : <UserRound />}
            {ai ? "AI" : entry.analyst_user}
        </span>
    )
}

function LedgerPage() {
    const [records, setRecords] = useState([])
    const [loading, setLoading] = useState(true)
    const [verify, setVerify] = useState(null)
    const [verifying, setVerifying] = useState(false)
    const [err, setErr] = useState(null)
    const [selected, setSelected] = useState(null)   // a ledger entry → detail view

    // brief spinner when moving between the ledger list and an entry detail
    const [switching, setSwitching] = useState(false)
    const didMountSel = useRef(false)
    useEffect(() => {
        if (!didMountSel.current) { didMountSel.current = true; return; }
        setSwitching(true)
        const t = setTimeout(() => setSwitching(false), 240)
        return () => clearTimeout(t)
    }, [selected])

    const load = () => {
        setLoading(true); setErr(null)
        api(`/investigations/ledger?limit=50`)
            .then(r => r.json())
            .then(d => setRecords(d.records || []))
            .catch(() => setErr("Can't reach the backend."))
            .finally(() => setLoading(false))
    }
    useEffect(load, [])

    if (switching) return <div className="content-spinner"><div className="spinner" /></div>

    const runVerify = () => {
        setVerifying(true); setVerify(null)
        api(`/investigations/ledger/verify`)
            .then(r => r.json())
            .then(setVerify)
            .catch(() => setErr("Verify failed."))
            .finally(() => setVerifying(false))
    }

    // newest first; block numbers count up from the genesis entry
    const blockNo = (e) => records.length - records.findIndex(r => r.ledger_id === e.ledger_id)

    if (selected) {
        return (
            <LedgerEntryDetail
                entry={selected}
                all={records}
                verify={verify}
                blockNo={blockNo(selected)}
                onBack={() => setSelected(null)}
                onOpen={setSelected}
            />
        )
    }

    const byAI = records.filter(ledgerByAI).length
    const state = verifying ? "checking" : !verify ? "unknown" : verify.valid ? "valid" : "broken"
    const days = []
    records.forEach(e => {
        const d = dayLabel(e.timestamp)
        if (!days.length || days[days.length - 1].label !== d) days.push({ label: d, items: [] })
        days[days.length - 1].items.push(e)
    })

    return (
        <Panel title="Decision ledger" note="every AI and analyst decision, hash-chained" action="Refresh" actionIcon={RefreshCw} onAction={load}>
            {err && <div className="login-error">{err}</div>}

            <section className={`lg-summary ${state}`}>
                <div className="lg-integrity">
                    <span className="lg-integrity-ico">
                        {state === "valid" ? <ShieldCheck /> : state === "broken" ? <ShieldAlert /> : <Link2 />}
                    </span>
                    <div>
                        <b>
                            {state === "valid" ? "Chain verified"
                                : state === "broken" ? "Tampering detected"
                                : state === "checking" ? "Checking every block…"
                                : "Integrity not checked yet"}
                        </b>
                        <span>
                            {state === "valid" ? `${verify.records_checked} blocks re-hashed — nothing has been altered.`
                                : state === "broken" ? `The chain breaks at entry ${verify.failing_ledger_id}.`
                                : "Re-hash every entry and check each one links to the one before it."}
                        </span>
                    </div>
                    <button className="btn" onClick={runVerify} disabled={verifying}>
                        {verifying ? <><span className="btn-spinner" /> Verifying…</> : "Verify chain"}
                    </button>
                </div>
                <dl className="lg-stats">
                    <div><dt>Blocks</dt><dd>{records.length}</dd></div>
                    <div><dt>By AI</dt><dd>{byAI}</dd></div>
                    <div><dt>By analysts</dt><dd>{records.length - byAI}</dd></div>
                    <div><dt>Latest</dt><dd>{records[0]?.timestamp ? timeAgo(records[0].timestamp) : "—"}</dd></div>
                </dl>
            </section>

            {loading ? <div className="panel-loading"><div className="spinner" /></div> : records.length === 0 ? (
                <p className="note">No ledger entries yet. Isolate a host or ask the AI analyst to create one.</p>
            ) : (
                <div className={`lg-chain ${state === "valid" ? "verified" : ""}`}>
                    {days.map(day => (
                        <div className="lg-day" key={day.label}>
                            <div className="lg-day-label">{day.label}</div>
                            {day.items.map(e => {
                                const st = ledgerStage(e)
                                return (
                                    <button className={`lg-block ${st.tone}`} key={e.ledger_id} onClick={() => setSelected(e)}>
                                        <span className="lg-node"><st.icon /></span>
                                        <div className="lg-main">
                                            <div className="lg-title">
                                                {ledgerTitle(e)}
                                                {ledgerSimulated(e) && <span className="tag">simulated</span>}
                                            </div>
                                            <div className="lg-meta">
                                                <LedgerActor entry={e} />
                                                <span>{st.name}</span>
                                                <span title={exactTime(e.timestamp)}>{e.timestamp ? timeAgo(e.timestamp) : "—"}</span>
                                            </div>
                                        </div>
                                        <div className="lg-side">
                                            <span className="lg-no">#{blockNo(e)}</span>
                                            <span className="lg-hash">{shortHash(e.entry_hash)}</span>
                                        </div>
                                    </button>
                                )
                            })}
                        </div>
                    ))}
                </div>
            )}
        </Panel>
    )
}

// one ledger entry: what was decided and by whom, then the proof (hashes) and
// its neighbours in the chain
function LedgerEntryDetail({ entry, all, verify, blockNo, onBack, onOpen }) {
    const prev = all.find(e => e.entry_hash === entry.prev_hash)
    const next = all.find(e => e.prev_hash === entry.entry_hash)
    const isGenesis = /^0+$/.test(entry.prev_hash || "")
    const [copied, setCopied] = useState(null)
    const copy = (t, which) => {
        try { navigator.clipboard.writeText(t); setCopied(which); setTimeout(() => setCopied(null), 1200) } catch { /* no clipboard */ }
    }
    const hasContext = entry.input_context && Object.keys(entry.input_context).length > 0
    const st = ledgerStage(entry)

    return (
        <>
            <button className="detail-back" onClick={onBack}><ArrowRight style={{ transform: "rotate(180deg)" }} /> Decision ledger</button>
            <Panel title={`Block #${blockNo}`} note="replayable, hash-chained decision record">
                <div className={`lg-detail-head ${st.tone}`}>
                    <span className="lg-node big"><st.icon /></span>
                    <div>
                        <div className="lg-title big">
                            {ledgerTitle(entry)}
                            {ledgerSimulated(entry) && <span className="tag">simulated</span>}
                        </div>
                        <div className="lg-meta">
                            <LedgerActor entry={entry} />
                            <span>{st.name}</span>
                            <span>{entry.timestamp ? `${exactTime(entry.timestamp)} · ${timeAgo(entry.timestamp)}` : "—"}</span>
                        </div>
                    </div>
                    {verify && (
                        <span className={`verify-badge ${verify.valid ? "good" : "bad"}`}>
                            {verify.valid ? "✓ chain verified" : "✗ tamper detected"}
                        </span>
                    )}
                </div>

                {entry.reasoning_output && (
                    <div className="lg-reason">
                        <span className="iv-k">Reasoning</span>
                        <p>{entry.reasoning_output}</p>
                    </div>
                )}

                <div className="tx-grid">
                    <div className="tx-row"><span className="tx-k">Entity</span><span>{humanize(entry.entity_type)} · {entry.entity_id}</span></div>
                    <div className="tx-row"><span className="tx-k">Incident</span><span>{entry.incident_id || "—"}</span></div>
                    <div className="tx-row"><span className="tx-k">Recorded as</span><span className="mono">{entry.stage} / {entry.action_taken}</span></div>
                </div>

                <div className="lg-proof">
                    <div className="iv-sec-head">Proof</div>
                    <div className="lg-proof-row">
                        <span className="tx-k">This block</span>
                        <button className="mono wrap lg-copy" onClick={() => copy(entry.entry_hash, "this")} title="Copy hash">
                            {entry.entry_hash} <Copy />{copied === "this" && <em>copied</em>}
                        </button>
                    </div>
                    <div className="lg-proof-row">
                        <span className="tx-k">Links to</span>
                        {isGenesis
                            ? <span className="mono wrap">{entry.prev_hash} <span className="tag">genesis</span></span>
                            : <span className="mono wrap">{entry.prev_hash}</span>}
                    </div>
                </div>

                <nav className="lg-nav" aria-label="Neighbouring blocks">
                    <button className="btn" disabled={!prev} onClick={() => prev && onOpen(prev)}>
                        <ArrowRight style={{ transform: "rotate(180deg)" }} /> {prev ? `Block #${blockNo - 1}` : "Genesis"}
                    </button>
                    <button className="btn" disabled={!next} onClick={() => next && onOpen(next)}>
                        {next ? `Block #${blockNo + 1}` : "Latest block"} <ArrowRight />
                    </button>
                </nav>

                {hasContext && (
                    <details className="lg-context">
                        <summary>Input context the decision was made from</summary>
                        <pre className="code-block">{JSON.stringify(entry.input_context, null, 2)}</pre>
                    </details>
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
function Panel({ title, note, children, flush = false, action, onAction, actionIcon: ActionIcon = ArrowRight, wide = false }) {
    return (
        <section className={`panel ${wide ? "panel-wide" : ""}`}>
            <div className="panel-head">
                <div className="panel-heading">
                    <span className="panel-title">{title}</span>
                    {note && <span className="panel-note">{note}</span>}
                </div>
                {action && (
                    <button className="panel-action" onClick={onAction}>
                        {action} <ActionIcon />
                    </button>
                )}
            </div>
            {flush ? children : <div className="panel-body">{children}</div>}
        </section>
    );
}

/* `spark` is a real per-bucket series from buildActivity; the delta is derived
   from it. `onClick` makes the card a drill-down into the filtered alert list. */
function Stat({ icon: Icon, label, value, tone, foot, spark, onClick, active }) {
    const hasSpark = Array.isArray(spark) && spark.length >= 2;
    const delta = hasSpark ? trendDelta(spark) : null;
    const up = delta != null && delta >= 0;
    const colour = tone && tone !== "accent" ? `var(--fill-${tone})` : "var(--accent)";
    const clickable = typeof onClick === "function";

    return (
        <div
            className={`stat ${clickable ? "clickable" : ""} ${active ? "active" : ""}`}
            onClick={onClick}
            role={clickable ? "button" : undefined}
            tabIndex={clickable ? 0 : undefined}
            onKeyDown={clickable ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(); } } : undefined}
        >
            <div className="stat-head">
                <span className="stat-label">{label}</span>
                {Icon && <span className={`stat-icon ${tone || ""}`}><Icon /></span>}
            </div>

            <div className="stat-row">
                <span className={`stat-value ${tone || ""}`}>{value}</span>
                {hasSpark && <Sparkline values={spark} stroke={colour} />}
            </div>

            {delta != null ? (
                <div className={`stat-delta ${up ? "up" : "down"}`} title="first half vs second half of the shown period">
                    {up ? <TrendingUp /> : <TrendingDown />}
                    {Math.abs(delta)}%
                    <em>over period</em>
                </div>
            ) : foot ? (
                <div className="stat-foot">{foot}</div>
            ) : null}
        </div>
    );
}

/* a dashboard scoped to a subset of alerts (used by the search results page):
   stats + charts + the full matching list, all computed from `alerts`. */
// which alert field a chart-click term is the value of — "Microsoft 365" is a
// brand, "LAPTOP-10" a host — so the filtered view can say what it's about (#30)
const ENTITY_FIELDS = [
    ["host", "Host"], ["user", "User"], ["domain", "Domain"], ["brand_target", "Impersonated brand"],
    ["mitre_technique", "MITRE technique"], ["source", "Detection engine"], ["event_type", "Event type"],
    ["src_ip", "IP address"], ["dst_ip", "IP address"],
];
function entityKind(alerts, term) {
    const t = (term || "").trim().toLowerCase();
    let best = null;
    ENTITY_FIELDS.forEach(([field, label]) => {
        const n = alerts.filter(a => String(a[field] ?? "").toLowerCase() === t).length;
        if (n > (best?.n || 0)) best = { field, label, n };
    });
    return best;
}

/* the top of a chart-click drill-down: what was clicked, when it was active,
   and how far it spread (hosts / users / domains) */
function EntitySummary({ alerts, term }) {
    const kind = entityKind(alerts, term);
    const times = alerts.map(a => new Date(a.timestamp).getTime()).filter(t => !isNaN(t));
    const distinct = (f) => new Set(alerts.map(a => a[f]).filter(Boolean)).size;
    const facts = [
        ["First seen", times.length ? exactTime(Math.min(...times)) : "—"],
        ["Last seen", times.length ? `${exactTime(Math.max(...times))} · ${timeAgo(Math.max(...times))}` : "—"],
        ["Hosts affected", distinct("host")],
        ["Users affected", distinct("user")],
        [kind?.field === "brand_target" ? "Impersonating domains" : "Domains", distinct("domain")],
    ];
    return (
        <section className="entity-summary">
            <div className="entity-id">
                <span className="search-eyebrow">{kind ? kind.label : "Filter"}</span>
                <div className="entity-name">
                    {term}
                    {kind?.field === "mitre_technique" && MITRE[term] && <span className="entity-sub">{MITRE[term]}</span>}
                </div>
            </div>
            <dl className="entity-facts">
                {facts.map(([k, v]) => (
                    <div key={k}><dt>{k}</dt><dd>{v}</dd></div>
                ))}
            </dl>
        </section>
    );
}

function ScopedDashboard({ alerts, term, onOpen, onFilter, onSeeGraph, asEntity = false }) {
    const SEV = ["critical", "high", "medium", "low"];
    const [sevFilter, setSevFilter] = useState(null);
    const toggleSev = (s) => setSevFilter(prev => prev === s ? null : s);

    // stat values stay on the full subset so every severity is always visible + clickable
    const countOf = (s) => alerts.filter(a => a.severity === s).length;
    const untriaged = alerts.filter(a => a.status === "new").length;
    const fullActivity = buildActivity(alerts);
    const totalSeries = fullActivity.map(b => b.critical + b.high + b.medium + b.low);
    const sevSeries = (k) => fullActivity.map(b => b[k] || 0);

    // everything below the stat row reflects the active severity filter
    const view = sevFilter ? alerts.filter(a => a.severity === sevFilter) : alerts;
    const vcountOf = (s) => view.filter(a => a.severity === s).length;
    const countBy = (field) => view.reduce((acc, a) => { const v = a[field]; if (v) acc[v] = (acc[v] || 0) + 1; return acc; }, {});
    const topN = (field, n) => Object.entries(countBy(field)).sort((x, y) => y[1] - x[1]).slice(0, n);
    const activity = buildActivity(view);
    const engines = Object.entries(countBy("source")).sort((a, b) => b[1] - a[1]);
    const engineMax = Math.max(1, ...engines.map(e => e[1]));
    const brands = topN("brand_target", 5);
    const brandMax = Math.max(1, ...brands.map(b => b[1]));
    const domains = topN("domain", 5);
    const domainMax = Math.max(1, ...domains.map(d => d[1]));
    const users = topN("user", 5);
    const userMax = Math.max(1, ...users.map(u => u[1]));
    const sorted = [...view].sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp));

    // who was hit: each host with its alert count, worst severity and last activity
    const affectedHosts = Object.entries(countBy("host"))
        .map(([host, n]) => {
            const mine = view.filter(a => a.host === host);
            return {
                host, n,
                worst: SEV.find(s => mine.some(a => a.severity === s)),
                last: Math.max(...mine.map(a => new Date(a.timestamp).getTime())),
            };
        })
        .sort((a, b) => SEV.indexOf(a.worst) - SEV.indexOf(b.worst) || b.n - a.n);

    return (
        <>
            {asEntity && <EntitySummary alerts={alerts} term={term} />}

            <div className="stats">
                <Stat icon={Flag}          label="Matches"   value={alerts.length}       spark={totalSeries} onClick={() => setSevFilter(null)} active={!sevFilter} />
                <Stat icon={ShieldAlert}   label="Critical"  value={countOf("critical")} spark={sevSeries("critical")} tone="critical" onClick={() => toggleSev("critical")} active={sevFilter === "critical"} />
                <Stat icon={TriangleAlert} label="High"      value={countOf("high")}     spark={sevSeries("high")}     tone="high"   onClick={() => toggleSev("high")}   active={sevFilter === "high"} />
                <Stat icon={Activity}      label="Medium"    value={countOf("medium")}   spark={sevSeries("medium")}   tone="medium" onClick={() => toggleSev("medium")} active={sevFilter === "medium"} />
                <Stat icon={Inbox}         label="Low"       value={countOf("low")}      spark={sevSeries("low")}      tone="low"    onClick={() => toggleSev("low")}    active={sevFilter === "low"} />
                <Stat icon={Target}        label="Untriaged" value={untriaged}           tone="accent" />
            </div>

            {sevFilter && (
                <div className="scoped-filterbar">
                    Showing <span className={`sev ${sevFilter}`}>{sevFilter}</span> only
                    <button className="reset" onClick={() => setSevFilter(null)}><X /> Clear</button>
                </div>
            )}

            <div className="grid-3">
                <Panel title="Threat activity" note={`${view.length} by severity`} wide>
                    <div className="chart-legend">
                        {SEV.map(s => (<span className="chart-legend-item" key={s}><span className={`chart-legend-dot sev-${s}`} />{s}</span>))}
                    </div>
                    <StackedArea data={activity} />
                </Panel>
                <Panel title="Severity distribution" note={`${view.length} alerts`}>
                    <Donut
                        total={alerts.length}
                        slices={SEV.map(s => ({ key: s, n: countOf(s) }))}
                        onSlice={(key) => setSevFilter(f => f === key ? null : key)}
                        activeKey={sevFilter}
                    />
                </Panel>
                <Panel title="Detections by engine" note="sources">
                    <PieChart
                        slices={engines.map(([src, n]) => ({ key: src, n, fill: src === "verifyeye" ? "var(--eng-1)" : src === "spectrac2" ? "var(--eng-2)" : "var(--eng-3)" }))}
                        onSlice={onFilter ? (key) => onFilter(key) : undefined}
                    />
                </Panel>
            </div>

            <div className="grid-3">
                <Panel title="Top targeted domains" note="by alert count">
                    {domains.length === 0 ? <div className="empty">No domains.</div> : (
                        <div className="barrows">
                            {domains.map(([d, n]) => (<BarRow key={d} label={d} value={n} max={domainMax} tone="high" onClick={onFilter ? () => onFilter(d) : undefined} />))}
                        </div>
                    )}
                </Panel>
                <Panel title="Alerts by user" note="most affected">
                    {users.length === 0 ? <div className="empty">No users attributed.</div> : (
                        <BarChart data={users.map(([u, n]) => ({ label: u, value: n, fill: "var(--accent)" }))} onBar={onFilter ? (d) => onFilter(d.label) : undefined} />
                    )}
                </Panel>
                <Panel title="Impersonated brands" note="phishing targets">
                    {brands.length === 0 ? <div className="empty">None in these results.</div> : (
                        <div className="barrows">
                            {brands.map(([b, n]) => (<BarRow key={b} label={b} value={n} max={brandMax} tone="high" onClick={onFilter ? () => onFilter(b) : undefined} />))}
                        </div>
                    )}
                </Panel>
            </div>

            <div className="grid-2">
                <Panel
                    title="Network graph"
                    note={`entities in ${view.length === 1 ? "this alert" : `these ${view.length} alerts`}`}
                    action={onSeeGraph && view.length ? "See in network graph" : null}
                    onAction={() => onSeeGraph(view, `“${term}”${sevFilter ? ` · ${sevFilter}` : ""}`)}
                >
                    <GraphCanvas compact refreshKey={alerts.length} scope={view} />
                </Panel>
                <Panel title="Affected hosts" note={`${affectedHosts.length} host${affectedHosts.length === 1 ? "" : "s"}`} flush>
                    {affectedHosts.length === 0 ? <div className="empty">No hosts in these alerts.</div> : (
                        <table className="table">
                            <thead>
                                <tr><th>Host</th><th>Worst</th><th>Alerts</th><th>Last seen</th></tr>
                            </thead>
                            <tbody>
                                {affectedHosts.map(h => (
                                    <tr
                                        key={h.host}
                                        className={onFilter && h.host !== term ? "row-link" : ""}
                                        onClick={onFilter && h.host !== term ? () => onFilter(h.host) : undefined}
                                        title={onFilter && h.host !== term ? `Drill into ${h.host}` : undefined}
                                    >
                                        <td className="td-mono">{h.host}</td>
                                        <td><span className={`sev ${h.worst}`}>{h.worst}</span></td>
                                        <td className="td-mono td-dim">{h.n}</td>
                                        <td className="td-mono td-faint" title={exactTime(h.last)}>{timeAgo(h.last)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </Panel>
            </div>

            {view.some(a => a.target_url) && (
                <div className="grid-1">
                    <Panel title="What the agent saw" note="screenshots of these pages, taken by VerifyEye's sandboxed agent">
                        <EvidenceGallery alerts={view} />
                    </Panel>
                </div>
            )}

            <div className="grid-1">
                <Panel title="All matching alerts" note={`${sorted.length} alert${sorted.length === 1 ? "" : "s"}`} flush>
                    <table className="table">
                        <thead>
                            <tr>
                                <th>Time</th><th>Severity</th><th>Type</th><th>Host</th>
                                <th>User</th><th className="td-wide">Domain / description</th><th>Engine</th>
                            </tr>
                        </thead>
                        <tbody>
                            {sorted.map(a => (
                                <tr key={a.alert_id} className="row-link" onClick={() => onOpen(a.alert_id)}>
                                    <td className="td-mono td-faint" title={exactTime(a.timestamp)}>{timeAgo(a.timestamp)}</td>
                                    <td><span className={`sev ${a.severity}`}>{a.severity}</span></td>
                                    <td className="td-mono">{a.event_type}</td>
                                    <td className="td-mono td-dim">{a.host}</td>
                                    <td className="td-mono td-dim">{a.user || "—"}</td>
                                    <td className="td-wide td-dim td-clip">{a.domain || a.description || "—"}</td>
                                    <td className="td-mono td-dim">{a.source}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </Panel>
            </div>
        </>
    );
}

/* one segmented control: "All" plus every option, joined into a single pill */
// themed month calendar with start→end range selection (no native date widget)
function RangeCalendar({ from, to, onChange }) {
    const [view, setView] = useState(() => {
        const d = from ? new Date(from + "T00:00") : new Date();
        return { y: d.getFullYear(), m: d.getMonth() };
    });
    const iso = (d) => `${view.y}-${String(view.m + 1).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
    const pick = (ds) => {
        if (!from || (from && to)) onChange(ds, "");          // start a new range
        else if (ds < from) onChange(ds, from);                // picked an earlier end → swap
        else onChange(from, ds);                               // complete the range
    };
    const first = new Date(view.y, view.m, 1);
    const daysInMonth = new Date(view.y, view.m + 1, 0).getDate();
    const cells = [];
    for (let i = 0; i < first.getDay(); i++) cells.push(null);
    for (let d = 1; d <= daysInMonth; d++) cells.push(d);
    const step = (n) => setView(v => {
        const m = v.m + n;
        return m < 0 ? { y: v.y - 1, m: 11 } : m > 11 ? { y: v.y + 1, m: 0 } : { y: v.y, m };
    });

    return (
        <div className="cal">
            <div className="cal-head">
                <button type="button" className="cal-nav" onClick={() => step(-1)} aria-label="Previous month"><ChevronDown style={{ transform: "rotate(90deg)" }} /></button>
                <span className="cal-title">{new Date(view.y, view.m).toLocaleDateString(undefined, { month: "long", year: "numeric" })}</span>
                <button type="button" className="cal-nav" onClick={() => step(1)} aria-label="Next month"><ChevronDown style={{ transform: "rotate(-90deg)" }} /></button>
            </div>
            <div className="cal-grid cal-dow">{["S", "M", "T", "W", "T", "F", "S"].map((d, i) => <span key={i}>{d}</span>)}</div>
            <div className="cal-grid">
                {cells.map((d, i) => d === null
                    ? <span key={i} />
                    : (() => {
                        const ds = iso(d);
                        const sel = ds === from || ds === to;
                        const mid = from && to && ds > from && ds < to;
                        return (
                            <button type="button" key={i} className={`cal-day ${sel ? "sel" : ""} ${mid ? "mid" : ""}`} onClick={() => pick(ds)}>{d}</button>
                        );
                    })()
                )}
            </div>
        </div>
    );
}

// GA-style date range picker: one trigger button → popover with presets + custom range
function DateRangePicker({ value, from, to, onPreset, onCustom }) {
    const [open, setOpen] = useState(false);
    const [pos, setPos] = useState({ top: 0, left: 0 });
    const [cFrom, setCFrom] = useState(from || "");
    const [cTo, setCTo] = useState(to || "");
    const ref = useRef(null);
    const trigger = useRef(null);
    const toggle = () => {
        if (!open && trigger.current) {
            const r = trigger.current.getBoundingClientRect();
            setPos({ top: r.bottom + 6, left: Math.min(r.left, window.innerWidth - 370) });
        }
        setOpen(o => !o);
    };
    useEffect(() => {
        if (!open) return;
        const onDown = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
        const onKey = (e) => { if (e.key === "Escape") setOpen(false); };
        document.addEventListener("mousedown", onDown);
        window.addEventListener("keydown", onKey);
        return () => { document.removeEventListener("mousedown", onDown); window.removeEventListener("keydown", onKey); };
    }, [open]);
    useEffect(() => { setCFrom(from || ""); setCTo(to || ""); }, [from, to]);

    const fmt = (d) => { try { return new Date(d + "T00:00").toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }); } catch { return d; } };
    const PRESETS = [["all", "All time"], ["today", "Today"], ["yesterday", "Yesterday"], ["7d", "Last 7 days"], ["30d", "Last 30 days"]];
    const label = value === "today" ? "Today"
        : value === "yesterday" ? "Yesterday"
        : value === "7d" ? "Last 7 days"
        : value === "30d" ? "Last 30 days"
        : value === "custom" ? (from && to ? `${fmt(from)} – ${fmt(to)}` : "Custom range")
        : "All time";

    return (
        <div className="drp" ref={ref}>
            <button className="drp-trigger" ref={trigger} onClick={toggle}>
                <Calendar /> <span>{label}</span> <ChevronDown />
            </button>
            {open && (
                <div className="drp-pop" style={{ position: "fixed", top: pos.top, left: pos.left }}>
                    <div className="drp-presets">
                        {PRESETS.map(([k, lbl]) => (
                            <button key={k} className={`drp-opt ${(value || "all") === k ? "on" : ""}`}
                                onClick={() => { onPreset(k === "all" ? null : k); setOpen(false); }}>
                                {lbl}
                            </button>
                        ))}
                    </div>
                    <div className="drp-custom">
                        <div className="drp-custom-title">Custom range</div>
                        <div className="drp-range-labels">
                            <div className={`drp-rl ${cFrom && !cTo ? "active" : ""}`}><span>Start</span><b>{cFrom ? fmt(cFrom) : "—"}</b></div>
                            <span className="drp-rl-dash">→</span>
                            <div className="drp-rl"><span>End</span><b>{cTo ? fmt(cTo) : "—"}</b></div>
                        </div>
                        <RangeCalendar from={cFrom} to={cTo} onChange={(f, t) => { setCFrom(f); setCTo(t); }} />
                        <button className="drp-apply" disabled={!cFrom || !cTo} onClick={() => { onCustom(cFrom, cTo); setOpen(false); }}>Apply range</button>
                    </div>
                </div>
            )}
        </div>
    );
}

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
function Donut({ slices, total, size = 132, thickness = 14, onSlice, activeKey }) {
    const r = (size - thickness) / 2;
    const circumference = 2 * Math.PI * r;
    const sum = slices.reduce((acc, s) => acc + s.n, 0);
    const clickable = typeof onSlice === "function";

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
                            className={`donut-arc sev-${a.key} ${clickable ? "clickable" : ""} ${activeKey && activeKey !== a.key ? "dim" : ""}`}
                            cx={size / 2} cy={size / 2} r={r}
                            fill="none"
                            strokeWidth={thickness}
                            strokeDasharray={`${a.len} ${circumference - a.len}`}
                            strokeDashoffset={-a.offset}
                            /* start at 12 o'clock instead of 3 */
                            transform={`rotate(-90 ${size / 2} ${size / 2})`}
                            onClick={clickable ? () => onSlice(a.key) : undefined}
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
                    <div
                        className={`donut-row ${clickable ? "clickable" : ""} ${activeKey === s.key ? "active" : ""}`}
                        key={s.key}
                        onClick={clickable ? () => onSlice(s.key) : undefined}
                        role={clickable ? "button" : undefined}
                        tabIndex={clickable ? 0 : undefined}
                        onKeyDown={clickable ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSlice(s.key); } } : undefined}
                    >
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

// highlight where the search text appears in a value
function Hl({ text, q }) {
    const t = (q || "").trim();
    const str = String(text ?? "");
    if (!t) return str;
    const i = str.toLowerCase().indexOf(t.toLowerCase());
    if (i < 0) return str;
    return <>{str.slice(0, i)}<mark className="hl-match">{str.slice(i, i + t.length)}</mark>{str.slice(i + t.length)}</>;
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
