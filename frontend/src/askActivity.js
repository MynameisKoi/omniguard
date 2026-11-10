// Which Ask AI chats are still replying in the background, and which finished
// while you were looking at something else. Shared by the Ask AI page (sidebar
// spinners and dots) and the main nav's "Ask AI" item, which stays mounted
// everywhere and polls while a reply is running.
import { useEffect, useSyncExternalStore } from "react"
import { api } from "./api"

const KEY = "og_ask_unread"
const load = () => { try { return JSON.parse(localStorage.getItem(KEY)) || [] } catch { return [] } }

let state = { running: new Set(), unread: new Set(load()) }
let viewing = null           // the chat open on the Ask AI page right now, if any
const subscribers = new Set()

function emit() {
    try { localStorage.setItem(KEY, JSON.stringify([...state.unread])) } catch { /* private mode */ }
    state = { running: new Set(state.running), unread: new Set(state.unread) }
    subscribers.forEach(f => f(state))
}

export function setViewing(id) {
    viewing = id || null
    if (id && state.unread.delete(id)) emit()
}

export function markRunning(id) {
    state.running.add(id)
    emit()
}

// a reply finished: a new-reply dot unless you're looking at that chat
export function markDone(id) {
    const was = state.running.delete(id)
    if (was && viewing !== id) state.unread.add(id)
    emit()
}

export function forget(id) {
    state.running.delete(id); state.unread.delete(id); emit()
}

// what the server says is running (from GET /conversations)
export function syncRunning(ids) {
    const now = new Set(ids)
    for (const id of state.running) if (!now.has(id) && viewing !== id) state.unread.add(id)
    state.running = now
    emit()
}

function subscribe(f) {
    subscribers.add(f)
    return () => { subscribers.delete(f) }
}

export function useAskActivity({ poll = false } = {}) {
    const snap = useSyncExternalStore(subscribe, () => state)
    useEffect(() => {
        if (!poll) return
        const check = () => api("/conversations").then(r => r.ok ? r.json() : null)
            .then(rows => rows && syncRunning(rows.filter(r => r.running).map(r => r.conversation_id)))
            .catch(() => {})
        check()
        const t = setInterval(() => { if (state.running.size) check() }, 4000)
        return () => clearInterval(t)
    }, [poll])
    return snap
}
