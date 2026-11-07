import { useState } from 'react';
import { ShieldAlert, AlertTriangle, Check } from 'lucide-react';
import { API_URL } from "./config"

// v1 analyst login: checks email + password against the backend, then
// hands the user up to main.jsx which swaps in the dashboard
export default function Login({ onLogin, onBack, notice }) {
    const [email, setEmail] = useState("")
    const [password, setPassword] = useState("")
    const [error, setError] = useState(null)
    // idle -> checking (spinner on the button) -> welcome (short hand-off) -> dashboard
    const [phase, setPhase] = useState("idle")
    const [welcome, setWelcome] = useState(null)
    const [shake, setShake] = useState(0)   // bumps on a failed attempt to replay the shake
    const checking = phase === "checking"

    const submit = (e) => {
        e.preventDefault()
        setPhase("checking")
        setError(null)
        // the check is fast; keep the spinner up long enough to read as "working", not a flicker
        const minWait = new Promise(r => setTimeout(r, 500))
        const request = fetch(`${API_URL}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        })
        .then(res => {
            if (res.status === 401) throw new Error("Invalid email or password")
            if (!res.ok) throw new Error("Login failed — try again")
            return res.json()
        })
        Promise.all([request, minWait])
        .then(([user]) => {
            setWelcome(user)
            setPhase("welcome")
            setTimeout(() => onLogin(user), 900)
        })
        .catch(err => {
            setError(err.message === "Failed to fetch" ? "Can't reach the backend" : err.message)
            setPhase("idle")
            setShake(n => n + 1)
        })
    }

    if (phase === "welcome") {
        const name = (welcome?.name || welcome?.email || "").split(" ")[0]
        return (
            <div className="login-page">
                <div className="login-card login-welcome" role="status">
                    <span className="login-welcome-check"><Check /></span>
                    <div className="login-welcome-title">Welcome back{name ? `, ${name}` : ""}</div>
                    <div className="login-welcome-sub">
                        <span className="btn-spinner" aria-hidden="true" />
                        Loading your dashboard…
                    </div>
                </div>
            </div>
        )
    }

    return (
        <div className="login-page">
            <form key={shake} className={`login-card ${shake ? "shake" : ""}`} onSubmit={submit} aria-busy={checking}>
                <div className="login-brand">
                    <span className="login-logo"><ShieldAlert /></span>
                    <div>
                        <div className="nav-name">OmniGuard <em>SOC</em></div>
                        <div className="login-sub">Sign in to the analyst dashboard</div>
                    </div>
                </div>

                {notice && <div className="login-notice" role="status">{notice}</div>}

                <label className="login-field">
                    <span>Email</span>
                    <input
                        type="email"
                        autoComplete="username"
                        autoFocus
                        required
                        disabled={checking}
                        className={error ? "field-error" : ""}
                        value={email}
                        onChange={e => { setEmail(e.target.value); if (error) setError(null) }}
                    />
                </label>
                <label className="login-field">
                    <span>Password</span>
                    <input
                        type="password"
                        autoComplete="current-password"
                        required
                        disabled={checking}
                        className={error ? "field-error" : ""}
                        value={password}
                        onChange={e => { setPassword(e.target.value); if (error) setError(null) }}
                    />
                </label>

                {error && (
                    <div className="login-error" role="alert">
                        <AlertTriangle />
                        <span>{error}</span>
                    </div>
                )}

                <button className={`login-btn ${checking ? "busy" : ""}`} type="submit" disabled={checking}>
                    {checking && <span className="btn-spinner" aria-hidden="true" />}
                    {checking ? "Checking credentials…" : "Sign in"}
                </button>

                {onBack && (
                    <button type="button" className="login-back" onClick={onBack}>← Back to home</button>
                )}
            </form>
        </div>
    )
}
