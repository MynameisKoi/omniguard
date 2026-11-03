from collections import Counter

import httpx
from config import OLLAMA_URL, OLLAMA_MODEL

# writing the alert lines 
def alert_line(a):
    parts = [a.get("severity","?"), a.get("source","?"), a.get("event_type","?"), f"host={a.get('host','?')}"]
    if a.get("user"):
        parts.append(f"user={a['user']}")
    if a.get("domain"):
        parts.append(f"domain={a['domain']}")
    if a.get("brand_target"): 
        parts.append(f"brand={a['brand_target']}")
    if a.get("description"):  
        parts.append(f"- {a['description']}")

    return " | ".join(parts)

# now building the prompt for our model 
def build_prompt(alerts):
    lines = "\n".join(alert_line(a) for a in alerts) if alerts else "(no alerts)"
    return (
        "You are a SOC analyst assistatnt. Be concise and practical.\n\n"
        f"The {len(alerts)} most recent security alerts: \n{lines}\n\n"
        "Write a breifing with two sections:\n"
        "1. Summary — what's happening, 2-3 sentences.\n"
        "2. Next steps — a short prioritized list."
    )

def run_triage(alerts):
    # posting to our ai
    resp = httpx.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": OLLAMA_MODEL, "prompt": build_prompt(alerts), "stream": False},
        timeout=120.0
    )

    resp.raise_for_status()
    return resp.json()["response"].strip()


# ── chat ────────────────────────────────────────────────────────────

CHAT_RULES = """You are OmniGuard's SOC analyst assistant, talking to a security analyst.

What you answer:
- Questions about the alerts below. Use ONLY the counts and alerts given; never invent hosts, users, domains or numbers.
- General cybersecurity questions (phishing, C2, malware, MITRE ATT&CK, incident response, security tools). Answer from general knowledge.
- Questions about OmniGuard and the tools it uses (see below).
- Simple arithmetic.

What you decline: only topics with nothing to do with security, IT or the alerts (food, sports, celebrities, etc.).
Decline politely in one sentence, e.g. "I can only help with security questions and your alerts."
Judge every question on its own. Declining one question never means declining the next.

Key concepts (get these right):
- C2 beaconing: malware on an infected host repeatedly calls OUT to the attacker's command-and-control server on a regular timer, to check in and fetch instructions. The traffic goes host -> attacker. SpectraC2 detects this from the timing pattern of network traffic.
- Phishing page: a fake login page that imitates a real brand to steal credentials. VerifyEye detects these in the browser and freezes the form.

About OmniGuard, the system you are part of:
- VerifyEye: browser extension that detects phishing pages.
- SpectraC2: network engine that detects C2 beaconing.
- MongoDB stores the alerts; Neo4j is a graph database linking alerts to hosts, users, IPs and domains.
- Ollama runs local AI models on this machine (you are a llama3.2 model running in Ollama), so alert data never leaves the network.

Facts about the data:
- A "host" is a machine (e.g. LAPTOP-10). A "user" is a person's account. Never call a host a user.
- Many alerts have no user; that is normal for network-only detections.
- For ANY question about which or how many hosts, users, domains, engines or severities
  (e.g. "which users are involved?", "how many critical?", "most affected host?"),
  answer from the COUNTS section. Do not count the alert lines yourself;
  they only show the newest alerts, not all of them.
  Always name each one with its alert count, as a short list, most alerts first, for example:
    Users involved:
    - ktamang (6 alerts)
    - maharjan (3 alerts)
  Never answer with only a number.

Style: concise, plain language, short bullet points when listing. No preamble.
Never mention "COUNTS", "RECENT ALERTS" or "the section"; those are internal labels. Just give the answer."""


def _top(counter, n=5):
    return ", ".join(f"{k} ({v})" for k, v in counter.most_common(n)) or "none"


def alert_stats(alerts):
    # counting is done here, not by the model; small models miscount
    sev = Counter(a.get("severity") for a in alerts)
    return "\n".join([
        f"Total alerts: {len(alerts)}",
        "By severity: " + ", ".join(f"{s} {sev.get(s, 0)}" for s in ("critical", "high", "medium", "low")),
        f"By engine: {_top(Counter(a.get('source') for a in alerts))}",
        f"By event type: {_top(Counter(a.get('event_type') for a in alerts))}",
        f"Hosts with most alerts: {_top(Counter(a.get('host') for a in alerts if a.get('host')))}",
        f"Users with most alerts: {_top(Counter(a.get('user') for a in alerts if a.get('user')))}",
        f"Domains with most alerts: {_top(Counter(a.get('domain') for a in alerts if a.get('domain')))}",
        f"Hosts with BOTH phishing and C2 alerts: "
        + (", ".join(sorted(
            {a.get('host') for a in alerts if a.get('source') == 'verifyeye'}
            & {a.get('host') for a in alerts if a.get('source') == 'spectrac2'}
        )) or "none"),
    ])


def build_chat_messages(question, alerts, history=(), recent=50):
    # alerts arrive newest first: counts cover all of them, detail lines only the newest
    lines = "\n".join(alert_line(a) for a in alerts[:recent]) if alerts else "(no alerts)"
    context = (
        f"{CHAT_RULES}\n\n"
        f"COUNTS (across all {len(alerts)} alerts):\n{alert_stats(alerts)}\n\n"
        f"RECENT ALERTS (newest {min(recent, len(alerts))}):\n{lines}"
    )
    # earlier turns as real chat roles, so follow-ups ("what about that host?") work
    turns = [
        {"role": "user" if m["role"] == "user" else "assistant", "content": m["text"]}
        for m in history
    ]
    return [{"role": "system", "content": context}, *turns, {"role": "user", "content": question}]


def answer_question(question, alerts, history=()):
    resp = httpx.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": OLLAMA_MODEL,
            "messages": build_chat_messages(question, alerts, history),
            "stream": False,
            # keep the model in memory between questions (default unloads after 5 min,
            # and reloading makes the next answer take ~20s)
            "keep_alive": "30m",
            # low temperature: fewer made-up facts.
            # num_ctx: Ollama defaults to 4096 tokens and silently drops the
            # START of a longer prompt, which is where the rules and counts are.
            # num_predict caps the reply (~300 words): small models can loop and
            # write forever, which looks like a hang. repeat_penalty discourages that loop.
            "options": {"temperature": 0.2, "num_ctx": 8192, "num_predict": 400, "repeat_penalty": 1.15},
        },
        timeout=120.0
    )

    resp.raise_for_status()
    return resp.json()["message"]["content"].strip()