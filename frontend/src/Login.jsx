import { useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import { API_URL } from "./config"

// v1 analyst login: checks email + password against the backend, then
// hands the user up to main.jsx which swaps in the dashboard
export default function Login({ onLogin }) {
    const [email, setEmail] = useState("")
    const [password, setPassword] = useState("")
    const [error, setError] = useState(null)
    const [loading, setLoading] = useState(false)

    const submit = (e) => {
        e.preventDefault()
        setLoading(true)
        setError(null)
        fetch(`${API_URL}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        })
        .then(res => {
            if (res.status === 401) throw new Error("Invalid email or password")
            if (!res.ok) throw new Error("Login failed — try again")
            return res.json()
        })
        .then(user => onLogin(user))
        .catch(err => setError(err.message === "Failed to fetch" ? "Can't reach the backend" : err.message))
        .finally(() => setLoading(false))
    }

    return (
        <div className="login-page">
            <form className="login-card" onSubmit={submit}>
                <div className="login-brand">
                    <span className="login-logo"><ShieldAlert /></span>
                    <div>
                        <div className="nav-name">OmniGuard <em>SOC</em></div>
                        <div className="login-sub">Sign in to the analyst dashboard</div>
                    </div>
                </div>

                <label className="login-field">
                    <span>Email</span>
                    <input
                        type="email"
                        autoComplete="username"
                        autoFocus
                        required
                        value={email}
                        onChange={e => setEmail(e.target.value)}
                    />
                </label>
                <label className="login-field">
                    <span>Password</span>
                    <input
                        type="password"
                        autoComplete="current-password"
                        required
                        value={password}
                        onChange={e => setPassword(e.target.value)}
                    />
                </label>

                {error && <div className="login-error">{error}</div>}

                <button className="login-btn" type="submit" disabled={loading}>
                    {loading ? "Signing in…" : "Sign in"}
                </button>
            </form>
        </div>
    )
}
