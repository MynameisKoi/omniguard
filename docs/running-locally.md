# Running It Locally

Notes to myself (and anyone else on the team) for getting OmniGuard up on a
laptop. There are two ways: Docker (one command, good for a demo or for someone
who just wants it running) and the manual way (separate processes, what I use
while actually coding).

---

## The easy way — Docker

One command brings up all four pieces: MongoDB, Neo4j, the FastAPI backend, and
the React frontend.

You need **Docker Desktop** installed and running (whale icon in the menu bar):

```bash
brew install --cask docker
```

Then from the project root:

```bash
docker compose up -d --build
```

That's it. Once it settles:

- Dashboard: http://localhost:8080
- API + Swagger: http://localhost:8000/docs
- Neo4j browser: http://localhost:7474

Stop it with:

```bash
docker compose down
```

The databases keep their data between runs — `down` removes the containers but
not the named volumes. To wipe the data too, add `-v`.

Useful while it's running:

```bash
docker compose ps              # what's up
docker compose logs -f backend # tail the backend
docker compose up -d --build   # rebuild after code changes
```

The Neo4j password lives in `docker-compose.yml` (the `NEO4J_AUTH` line). The
backend reaches the databases by service name — `mongo:27017`, `neo4j:7687` —
not localhost, because inside a container localhost means the container itself.
The browser still uses localhost since it runs on your Mac, outside the Docker
network.

---

## The manual way — for development

Docker rebuilds the image on every change, which is slow while coding. For that,
run the four pieces yourself. Mongo and Neo4j sit in the background; the backend
and frontend each want their own terminal tab.

**Don't run both ways at once** — they both want ports 8000 / 27017 / 7687, so
`docker compose down` first if the stack is up.

### First time on a machine

You need Python 3.11+, Node 18+, MongoDB, and Neo4j Desktop.

Mongo isn't in the main Homebrew registry, it lives in MongoDB's own tap:

```bash
brew tap mongodb/brew
brew trust mongodb/brew
brew install mongodb-community
brew services start mongodb-community
```

The `brew trust` step is new-ish — Homebrew won't run formulas from a
third-party tap until you say it's okay.

Then the two apps:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

```bash
cd frontend
npm install
```

**Neo4j** is a desktop app:

```bash
brew install --cask neo4j-desktop
```

Open it, make a project, add a **Local DBMS** inside it, set a password and
write it down. Hit Start and wait for Active.

Then make `backend/.env` — it's gitignored because it holds that password.
Copy `backend/.env.example` and fill in the password:

```
MONGO_URI=mongodb://localhost:27017
MONGO_DB=omniguard
NEO4J_URI=neo4j://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=whatever-you-set
```

The frontend reads its API URL from `frontend/.env` (already committed, points
at localhost:8000). You only do all of this once.

### Every day after that

**Mongo** starts on its own at login via `brew services`. Check with
`brew services list` — `mongodb-community` should say `started`. Database is
`omniguard`, collection is `alerts`.

**Neo4j** — open the desktop app and click Start, or:

```bash
open "/Applications/Neo4j Desktop 2.app"
```

Check both without opening anything:

```bash
(nc -z localhost 27017 && echo "mongo up") || echo "mongo down"
(nc -z localhost 7687 && echo "neo4j up") || echo "neo4j down"
```

**Backend — terminal tab 1:**

```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload
```

API at http://localhost:8000, Swagger at http://localhost:8000/docs. `--reload`
restarts on save.

**Frontend — terminal tab 2:**

```bash
cd frontend
npm run dev
```

Dashboard at http://localhost:5173.

---

## Checking it actually works

1. Go to http://localhost:8000/docs
2. `POST /alerts` → Try it out → Execute. The form is pre-filled from the
   `examples` in the Pydantic model.
3. Open the dashboard. The alert shows up **live** — no refresh needed. New
   alerts arrive over a WebSocket (`/ws/alerts`) and the graph updates too,
   keeping existing node positions.

---

## When something breaks

**"address already in use"** — a server from last time didn't die, or the Docker
stack is still up:

```bash
lsof -ti:8000 | xargs kill      # or 5173 for Vite
docker compose down             # if you were running the stack
```

**Dashboard says 0 alerts** — check http://localhost:8000/health first. If
that's fine the backend is up, so it's an empty database or the fetch failing.
Browser console (Cmd+Option+J) will say which.

**CORS error in the console** — the backend only allows the origin in
`CORS_ORIGINS`. Manual dev that's `http://localhost:5173`; under Docker it's
`http://localhost:8080` (set in `docker-compose.yml`). If Vite grabbed a
different port, free up 5173 or add the new one.

**Mongo connection refused** — `brew services list` and start it. The client
connects lazily, so the error only shows on the first query, not at startup.

**Graph is empty but alerts exist** — the graph is built in Neo4j, separate from
Mongo. If Mongo has alerts but the graph is empty, Neo4j was probably down when
those alerts came in. Re-POST them, or check the Neo4j browser.

---

## Ports, all in one place

| Port  | What                         |
|-------|------------------------------|
| 5173  | frontend, manual dev (Vite)  |
| 8080  | frontend, Docker (nginx)     |
| 8000  | backend API                  |
| 27017 | MongoDB                      |
| 7474  | Neo4j browser                |
| 7687  | Neo4j bolt (what the app uses) |
