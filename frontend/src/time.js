// shared time formatting for alerts (dashboard, graph explorer)

export function timeAgo(ts) {
    const secs = Math.floor((Date.now() - new Date(ts)) / 1000);
    if (secs < 60) return "just now";
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return days < 30 ? `${days}d ago` : new Date(ts).toLocaleDateString();
}

// full stored timestamp, for tooltips and the detail view (#10/#11)
export function exactTime(ts) {
    if (!ts) return "";
    try { return new Date(ts).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }); }
    catch { return ""; }
}
