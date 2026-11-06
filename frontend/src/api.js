import { API_URL, WS_URL } from "./config"

// every dashboard call goes through here so it carries the session token (#18).
// main.jsx sets the token at sign-in and clears it at sign-out.
let token = null
export const setToken = (t) => { token = t || null }

// fetch an API path ("/alerts"). A 401 while we think we're signed in means the
// session ended (expired, or signed out elsewhere): main.jsx listens for this
// and sends the analyst back to the login screen.
export async function api(path, opts = {}) {
    const headers = { ...(opts.headers || {}) }
    if (token) headers.Authorization = `Bearer ${token}`
    const res = await fetch(`${API_URL}${path}`, { ...opts, headers })
    if (res.status === 401 && token) window.dispatchEvent(new Event("og-session-ended"))
    return res
}

// browsers can't put headers on a websocket, so the token rides in the query
export const wsUrl = (path) => `${WS_URL}${path}?token=${encodeURIComponent(token || "")}`
