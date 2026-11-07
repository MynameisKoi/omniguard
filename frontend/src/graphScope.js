// which graph nodes an alert touches. Must mirror how graph.py names nodes:
// `${label}:${key}`, with Process keyed as host:pid
export function alertEntityIds(a) {
    const ids = []
    const add = (type, v) => { if (v !== null && v !== undefined && v !== "") ids.push(`${type}:${v}`) }
    add("Host", a.host)
    add("User", a.user)
    add("Domain", a.domain)
    add("IP", a.src_ip)
    add("IP", a.dst_ip)
    add("URL", a.target_url)
    add("Technique", a.mitre_technique)
    if (a.pid !== null && a.pid !== undefined) add("Process", `${a.host}:${a.pid}`)
    return ids
}

// every node id touched by a set of alerts
export function scopeIds(alerts) {
    const ids = new Set()
    alerts.forEach(a => alertEntityIds(a).forEach(id => ids.add(id)))
    return ids
}
