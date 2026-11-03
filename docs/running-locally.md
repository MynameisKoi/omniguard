# Running OmniGuard

Two ways to run it: **Docker** (one command for the core stack) and the **manual**
dev route (separate processes, what we use while coding). A couple of pieces —
Ollama and the Chrome extension — are host prerequisites either way.

## Prerequisites
- **Docker Desktop** (running) — the whale icon in the menu bar
- **Ollama** — powers the AI triage + chatbot:
  ```bash
  brew install ollama
  ollama pull llama3.2:3b
  ```
- **Google Chrome** — for the VerifyEye extension

---

## The easy way — Docker

From the project root:
```bash
git clone <repo-url> omniguard
cd omniguard
docker compose up -d --build
```

This brings up **MongoDB, Neo4j, the backend API, the VerifyEye agent, and the
dashboard**. Once it settles:

| Service | URL |
|---|---|
| Dashboard | http://localhost:8080 |
| API + Swagger | http://localhost:8000/docs |
| VerifyEye agent | http://localhost:8100/health |
| Neo4j browser | http://localhost:7474 |

### Then, two host-side steps

**1. Start Ollama** (the dockerized backend reaches it at `host.docker.internal:11434`):
```bash
ollama serve
```

**2. Create a login** (no public signup):
```bash
cd backend && python auth.py analyst@omniguard.io "SocPass123" "A. Analyst"
```
(Or run the same inside the container: `docker compose exec backend python auth.py ...`)

**3. Load the VerifyEye extension** in Chrome:
`chrome://extensions` → enable **Developer mode** → **Load unpacked** →
select `verifyeye-ingress/extension`.

You're up. Log in at the dashboard and you'll see live alerts, the graph, the AI
analyst, and the chatbot.

---

## The manual way (while developing)

Infra (MongoDB, Neo4j, Ollama) runs on the host; the app services run from the venvs.
A helper script starts them all on fixed ports:
```bash
./dev.sh          # starts core, verifyeye agent, dashboard, and the fake sites
./dev.sh stop     # stops them
```
`dev.sh` checks Neo4j/Mongo/Ollama and prints the start command for any that are down.

First-time setup of the venvs:
```bash
# backend
cd backend && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && cd ..
# verifyeye agent (needs a browser for the sandboxed crawler)
cd verifyeye-ingress && python3 -m venv venv && source venv/bin/activate && pip install playwright fastapi uvicorn httpx && playwright install chromium && cd ..
# frontend
cd frontend && npm install && cd ..
```

Ports: core `8000`, verifyeye agent `8100`, dashboard `5173`, fake sites `5500–6100`.

---

## Testing VerifyEye (the phishing detector)

The fake phishing sites are **local fixtures** (never deployed). Serve them:
```bash
./fake_sites/serve.sh        # starts them on 5500–6100
```
Then open e.g. http://localhost:5700 in Chrome — the extension freezes it and the
agent confirms it.

> Note: when the agent runs **inside Docker**, it can't reach the host's
> `localhost` fixtures (its `localhost` is the container). Real phishing URLs work
> fine; to test the local fixtures, run the agent on the host (`uvicorn service:app
> --port 8100` from `verifyeye-ingress`) instead.

---

## Notes / current limitations
- **Ollama is a host prerequisite** — it isn't containerized (the model is large and
  usually runs natively). The backend talks to it over `host.docker.internal`.
- **The VerifyEye extension is loaded by hand** in Chrome — a browser extension
  can't be shipped in a compose file.
- **Login is a UI gate** for now; the API itself isn't token-protected yet.
- **8 GB machines**: don't run everything at once (Neo4j + Ollama + all services +
  Chrome will swap). Start only what the task needs.
