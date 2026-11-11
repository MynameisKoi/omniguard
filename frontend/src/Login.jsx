import { useState, useRef, useEffect } from 'react';
import { ShieldAlert, AlertTriangle, Check, Radio, Key, Nfc } from 'lucide-react';
import { API_URL } from "./config";

// Analyst login: supports both email/password credentials and physical
// Flipper Zero / RFID & NFC badge tap authentication.
export default function Login({ onLogin, onBack, notice }) {
    const [mode, setMode] = useState("password"); // "password" | "flipper"
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [badgeUid, setBadgeUid] = useState("");
    const [error, setError] = useState(null);
    // idle -> checking (spinner on button/tap) -> welcome (short hand-off) -> dashboard
    const [phase, setPhase] = useState("idle");
    const [welcome, setWelcome] = useState(null);
    const [shake, setShake] = useState(0); // bumps on failed attempt to replay shake
    const badgeInputRef = useRef(null);
    const checking = phase === "checking";

    // Auto-focus badge input when switching to Flipper mode
    useEffect(() => {
        if (mode === "flipper" && badgeInputRef.current) {
            badgeInputRef.current.focus();
        }
    }, [mode]);

    const handleSuccess = (user) => {
        setWelcome(user);
        setPhase("welcome");
        setTimeout(() => onLogin(user), 900);
    };

    const submitPassword = (e) => {
        e.preventDefault();
        setPhase("checking");
        setError(null);
        const minWait = new Promise(r => setTimeout(r, 500));
        const request = fetch(`${API_URL}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        })
        .then(res => {
            if (res.status === 401) throw new Error("Invalid email or password");
            if (!res.ok) throw new Error("Login failed — try again");
            return res.json();
        });

        Promise.all([request, minWait])
            .then(([user]) => handleSuccess(user))
            .catch(err => {
                setError(err.message === "Failed to fetch" ? "Can't reach the backend" : err.message);
                setPhase("idle");
                setShake(n => n + 1);
            });
    };

    const submitBadge = (uidToSubmit) => {
        const uid = (uidToSubmit || badgeUid).trim();
        if (!uid) return;
        setPhase("checking");
        setError(null);
        const minWait = new Promise(r => setTimeout(r, 500));
        const request = fetch(`${API_URL}/auth/badge-login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ badge_uid: uid }),
        })
        .then(res => {
            if (res.status === 401) throw new Error("Unrecognized badge or Flipper key");
            if (!res.ok) throw new Error("Badge authentication failed");
            return res.json();
        });

        Promise.all([request, minWait])
            .then(([user]) => handleSuccess(user))
            .catch(err => {
                setError(err.message === "Failed to fetch" ? "Can't reach the backend" : err.message);
                setPhase("idle");
                setShake(n => n + 1);
            });
    };

    if (phase === "welcome") {
        const name = (welcome?.name || welcome?.email || "").split(" ")[0];
        const isBadge = Boolean(welcome?.badge_uid);
        return (
            <div className="login-page">
                <div className="login-card login-welcome" role="status">
                    <span className="login-welcome-check"><Check /></span>
                    <div className="login-welcome-title">Welcome back{name ? `, ${name}` : ""}</div>
                    {isBadge && (
                        <div className="login-welcome-badge">
                            <Radio size={14} /> Flipper Zero Authenticated ({welcome.badge_uid})
                        </div>
                    )}
                    <div className="login-welcome-sub">
                        <span className="btn-spinner" aria-hidden="true" />
                        Loading your dashboard…
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="login-page">
            <div key={shake} className={`login-card ${shake ? "shake" : ""}`} aria-busy={checking}>
                <div className="login-brand">
                    <span className="login-logo"><ShieldAlert /></span>
                    <div>
                        <div className="nav-name">OmniGuard <em>SOC</em></div>
                        <div className="login-sub">Sign in to the analyst dashboard</div>
                    </div>
                </div>

                {/* Mode Selector Tabs */}
                <div className="login-modes" role="tablist">
                    <button
                        type="button"
                        className={`login-mode-btn ${mode === "password" ? "active" : ""}`}
                        onClick={() => { setMode("password"); setError(null); }}
                    >
                        <Key size={14} /> Password
                    </button>
                    <button
                        type="button"
                        className={`login-mode-btn ${mode === "flipper" ? "active" : ""}`}
                        onClick={() => { setMode("flipper"); setError(null); }}
                    >
                        <Radio size={14} /> 🐬 Flipper Zero / NFC
                    </button>
                </div>

                {notice && <div className="login-notice" role="status">{notice}</div>}

                {mode === "password" ? (
                    <form onSubmit={submitPassword} className="login-form">
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
                                onChange={e => { setEmail(e.target.value); if (error) setError(null); }}
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
                                onChange={e => { setPassword(e.target.value); if (error) setError(null); }}
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
                    </form>
                ) : (
                    <form onSubmit={e => { e.preventDefault(); submitBadge(); }} className="login-form">
                        <div className="flipper-tap-zone" onClick={() => badgeInputRef.current?.focus()}>
                            <div className={`flipper-icon-glow ${checking ? "pulsing" : ""}`}>
                                <Nfc size={36} />
                            </div>
                            <div className="flipper-tap-title">Tap Badge or Flipper Key</div>
                            <div className="flipper-tap-sub">
                                Present your RFID/NFC card to Flipper Zero or execute BadUSB fast-login.
                            </div>
                        </div>

                        <label className="login-field">
                            <span>Badge UID / Key Token</span>
                            <input
                                ref={badgeInputRef}
                                type="text"
                                placeholder="e.g. FLIPPER-SOC-7A39B1 or 7A:39:B1:04"
                                autoComplete="off"
                                required
                                disabled={checking}
                                className={error ? "field-error" : ""}
                                value={badgeUid}
                                onChange={e => { setBadgeUid(e.target.value); if (error) setError(null); }}
                            />
                        </label>

                        {error && (
                            <div className="login-error" role="alert">
                                <AlertTriangle />
                                <span>{error}</span>
                            </div>
                        )}

                        <div className="flipper-actions">
                            <button
                                className={`login-btn ${checking ? "busy" : ""}`}
                                type="submit"
                                disabled={checking || !badgeUid.trim()}
                            >
                                {checking && <span className="btn-spinner" aria-hidden="true" />}
                                {checking ? "Authenticating Key…" : "Authenticate Badge"}
                            </button>
                            <button
                                type="button"
                                className="flipper-demo-btn"
                                disabled={checking}
                                onClick={() => {
                                    setBadgeUid("FLIPPER-SOC-7A39B1");
                                    submitBadge("FLIPPER-SOC-7A39B1");
                                }}
                            >
                                ⚡ Simulate Flipper Key Tap (Demo)
                            </button>
                        </div>
                    </form>
                )}

                {onBack && (
                    <button type="button" className="login-back" onClick={onBack}>← Back to home</button>
                )}
            </div>
        </div>
    );
}
