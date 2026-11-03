// dev: go through the vite proxy (/api -> localhost:8000, see vite.config.js) so the
// dashboard works from any machine that can open the page. docker build: direct.
export const API_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? "/api" : "http://localhost:8000")
export const WS_URL = API_URL.startsWith("/")
    ? `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${API_URL}`
    : API_URL.replace(/^http/, "ws")
