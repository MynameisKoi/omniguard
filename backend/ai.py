import httpx
from config import OLLAMA_URL, OLLAMA_MODEL

# writing the alert lines 
def alert_line(a):
    parts = [a.get("severity","?"), a.get("source","?"), a.get("event_type","?"), f"host={a.get('host','?')}"]
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