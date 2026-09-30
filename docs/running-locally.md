# Running It Locally

Notes to myself (and anyone else on the team) for getting OmniGuard up on a
laptop. Three pieces have to be running: MongoDB, the FastAPI backend, and the
React frontend. Mongo sits in the background, the other two each want their own
terminal tab.

---

## First time on a machine

You need Python 3.11+, Node 18+, and MongoDB.

Mongo isn't in the main Homebrew registry, it lives in MongoDB's own tap:

```bash
brew tap mongodb/brew
brew trust mongodb/brew
brew install mongodb-community
brew services start mongodb-community
```

The `brew trust` step is new-ish — Homebrew won't run formulas from a
third-party tap until you say it's okay. Check `brew tap-info mongodb/brew`
points at `github.com/mongodb/homebrew-brew` before trusting it.

Then set up the two apps:

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

Then make `backend/.env` — it's gitignored because it holds that password:

```
NEO4J_URI=neo4j://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=whatever-you-set
```

Mongo needs nothing in there; `config.py` falls back to localhost.

You only do all of that once.

---

## Every day after that

### Mongo

It's registered with `brew services`, so it starts on its own at login. Worth
checking if something seems off:

```bash
brew services list
```

`mongodb-community` should say `started`. If it doesn't:

```bash
brew services start mongodb-community
```

Database is `omniguard`, collection is `alerts`. Data files live in
`/opt/homebrew/var/mongodb`.

### Neo4j

No CLI for the desktop version — open the app and click Start on the DBMS.

```bash
open "/Applications/Neo4j Desktop 2.app"
```

Browser at http://localhost:7474 for running Cypher by hand. The backend uses
port 7687.

Check both databases without opening anything:

```bash
(nc -z localhost 27017 && echo "mongo up") || echo "mongo down"
(nc -z localhost 7687 && echo "neo4j up") || echo "neo4j down"
```

### Backend — terminal tab 1

```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload
```

- API at http://localhost:8000
- Swagger docs at http://localhost:8000/docs

`--reload` means it restarts whenever I save a file. Handy, but it also means
any in-memory state resets — not an issue anymore now that alerts live in Mongo.

### Frontend — terminal tab 2

```bash
cd frontend
npm run dev
```

Dashboard at http://localhost:5173.

---

## Checking it actually works

1. Go to http://localhost:8000/docs
2. `POST /alerts` → Try it out → Execute. The form comes pre-filled from the
   `examples` in the Pydantic model.
3. Open http://localhost:5173 and refresh. The alert should show up.

The dashboard only fetches once when the page loads, so a refresh is needed to
see new alerts. Polling or WebSockets will fix that later.

---

## Shutting down

`Ctrl+C` in both terminal tabs. Mongo keeps running in the background, which is
fine. Stop it too if you want:

```bash
brew services stop mongodb-community
```

---

## When something breaks

**"address already in use"** — a server from last time didn't die properly:

```bash
lsof -ti:8000 | xargs kill
```

Same thing for 5173 if Vite complains.

**Dashboard says 0 alerts** — check http://localhost:8000/health first. If
that's fine, the backend is up and the problem is either an empty database or
the fetch failing. Browser console (Cmd+Option+J) will tell you which.

**CORS error in the console** — the frontend has to be on port 5173. That's the
only origin allowlisted in `backend/main.py`. If Vite grabbed a different port
because 5173 was taken, either free up 5173 or add the new one to the list.

**Mongo connection refused** — `brew services list` and start it. The Python
client connects lazily, so the error won't show up until the first query, not
at startup.

---

## Still to do

- Neo4j instructions once the graph layer is in
- `docker compose up` to replace all of this with one command
- `.env` file instead of the hardcoded Mongo URI
