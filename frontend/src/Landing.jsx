import { ShieldAlert, Flag, Activity, Share2, Bot, ArrowRight, Check } from 'lucide-react';

// marketing landing shown before login: what OmniGuard is, for visitors
// who land on the dashboard URL without an account yet.
const FEATURES = [
    { icon: ShieldAlert, title: "VerifyEye phishing detection", body: "A browser agent that scores login pages in real time and freezes credential theft before it happens — two-tier, with a sandboxed verifier." },
    { icon: Activity, title: "SpectraC2 beacon detection", body: "Spots encrypted command-and-control traffic by its timing fingerprint, even when the payload is unreadable." },
    { icon: Share2, title: "Live attack graph", body: "Every alert becomes nodes and edges in a Neo4j graph — hosts, users, domains and C2 IPs — so you see the blast radius, not just a row." },
    { icon: Bot, title: "AI analyst", body: "A local LLM reads your alerts and answers questions, triages incidents and drafts next steps — all on your own machine, nothing leaves." },
    { icon: Check, title: "Tamper-evident ledger", body: "Every decision is written to a SHA-256 hash-chained audit log, so who did what — human or AI — is provable and unalterable." },
    { icon: Flag, title: "OCSF-native export", body: "Alerts export as standard OCSF Security Findings, ready to stream into Splunk, AWS Security Lake or any modern SIEM." },
];

export default function Landing({ onSignIn }) {
    return (
        <div className="landing">
            <header className="lp-nav">
                <div className="lp-brand">
                    <span className="lp-logo"><ShieldAlert /></span>
                    <span className="nav-name">OmniGuard <em>SOC</em></span>
                </div>
                <nav className="lp-nav-links">
                    <a href="#features">Features</a>
                    <a href="#about">About</a>
                    <button className="lp-signin" onClick={onSignIn}>Sign in</button>
                </nav>
            </header>

            <section className="lp-hero">
                <span className="lp-eyebrow">Unified Security Operations Center</span>
                <h1>Detect, reason about, and contain threats<br />— in one place.</h1>
                <p className="lp-lede">
                    OmniGuard fuses phishing detection, C2 beacon analysis, an attack graph,
                    a local AI analyst and a tamper-evident audit ledger into a single
                    analyst dashboard. Private by design — everything runs on your own machine.
                </p>
                <div className="lp-cta">
                    <button className="lp-btn-primary" onClick={onSignIn}>
                        Open the dashboard <ArrowRight />
                    </button>
                    <a className="lp-btn-ghost" href="#features">See what it does</a>
                </div>
                <div className="lp-stats">
                    <div><b>2</b><span>detection engines</span></div>
                    <div><b>6</b><span>integrated subsystems</span></div>
                    <div><b>100%</b><span>local / zero-cloud</span></div>
                </div>
            </section>

            <section className="lp-section" id="features">
                <h2>One platform, the whole kill chain</h2>
                <p className="lp-section-sub">Producers feed a shared ingestion hub; the dashboard is where it all comes together.</p>
                <div className="lp-features">
                    {FEATURES.map(f => (
                        <div className="lp-feature" key={f.title}>
                            <span className="lp-feature-icon"><f.icon /></span>
                            <h3>{f.title}</h3>
                            <p>{f.body}</p>
                        </div>
                    ))}
                </div>
            </section>

            <section className="lp-section lp-about" id="about">
                <h2>About the project</h2>
                <p className="lp-about-body">
                    OmniGuard is a senior capstone project at San Francisco Bay University — a
                    team build of a modern, self-hosted SOC. The goal: show the full loop of a
                    security operation (detect → correlate → reason → respond → audit) running
                    end-to-end, without sending sensitive security data to anyone's cloud.
                </p>
                <div className="lp-about-grid">
                    <div><b>Detection</b><span>VerifyEye phishing agent · SpectraC2 beacon engine</span></div>
                    <div><b>Correlation</b><span>Neo4j attack graph · simhash alert fusion</span></div>
                    <div><b>Reasoning</b><span>Local Ollama analyst · multi-agent triage</span></div>
                    <div><b>Accountability</b><span>Hash-chained decision ledger · OCSF export</span></div>
                </div>
                <div className="lp-cta lp-about-cta">
                    <button className="lp-btn-primary" onClick={onSignIn}>Sign in to the dashboard <ArrowRight /></button>
                </div>
            </section>

            <footer className="lp-footer">
                <span>OmniGuard SOC — SFBU capstone</span>
                <span className="lp-footer-note">Private by design · runs entirely on your machine</span>
            </footer>
        </div>
    );
}
