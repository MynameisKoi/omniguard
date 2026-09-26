# Dev Log

My notes while building the OmniGuard dashboard + backend + frontend + MongoDB. Newest on top.

---

## Fri, Sept 25, 2026

Got the graph building itself.

### ingest_alert()

Wrote it in `graph.py` and called it from `POST /alerts`, so every alert now
writes to Mongo *and* Neo4j. One core query that always runs (Alert + Host),
then five `if` blocks for the optional fields.

The `if` matters — without it a null user would create a `{name: null}` node,
and then every alert without a user would MERGE onto that same junk node and
link things that have nothing to do with each other.

### Schema we settled on

Nodes: Alert, Host, User, IP, Domain, Technique

From the alert (what it observed):
`AFFECTS`, `INVOLVES`, `TARGETS`, `FROM_IP`, `TO_IP`, `MAPS_TO`

Between entities (what's true about the network):
`LOGGED_INTO`, `HAS_IP`, `CONNECTED_TO`

That second group is the important one. It sticks around after the alert and is
what lets the next alert correlate. Siddik sent a list of ~15 node types, cut it
down to the 6 we can actually build from the alert contract. Process, Service,
segments etc. come later.

### Stuff that tripped me up

- The parameter name has to match the `$placeholder`, not the node property.
  `{address: $src_ip}` needs `src_ip=`, not `address=`. Spent a while on this.
- Both src and dst IPs store into `address`. If they used different property
  names the same IP would become two nodes and the correlation disappears.
- Never build Cypher with f-strings, use `$params`.

### Tested it

Posted 7 alerts. Alert count went to 7 but Host, User, Domain, IP all stayed
at 1 each — MERGE working.

- LAPTOP-10 has 2 alerts on it from 2 different engines (verifyeye + spectrac2)
- 198.51.100.42 has 3 alerts pointing at it, the shared C2
- shortestPath gives `LAPTOP-10 -> maharjan -> SRV-DB-02`

Also spent time going through how the whole system actually works end to end,
and what each engine can and can't see. SpectraC2 is network-only so it never
knows the username — the graph fills that in from the phishing alert.

### Next

- `GET /graph/host/{hostname}` returning {nodes, edges}
- React Flow canvas
- Make the alert list look like an actual dashboard

---

## Mon, Sept 22 2026

Backend cleanup

- Added `config.py` — one place that loads `.env` and holds every setting
- `db.py` and `main.py` read from it now instead of calling `os.getenv` themselves
- Added `graph.py` with the Neo4j driver, `verify_connectivity()` passes
- Neo4j password lives in `.env`, gitignored

Next: `ingest_alert()` so alerts go into the graph from POST /alerts, then a
graph endpoint for the frontend.

---

## Fri, Sept 18 2026
Worked on a lot of things

Mongo
- set up local mongodb 
- connected that with python drivers
- made alerts persist on mongodb collection


Integration of Khoi's engine with API 
- Ran Spectra2 and checked the API - worked the first try 
- Beacon -> his detector -> POST -> MONGO -> Dashboard
- Added dst_ip and confidence in the alert 


Integration of Rahim's verifeye 
- Ran the code and works for github login page

Neo4j
- Installed, and ran some tests locally 
- Siddik is working on it for now 



## Fri, Sep 11 2026

Goal for today: get one alert to go from the backend to the frontend and show up on screen. Basic frontend, basic backend, that's it. No Neo4j or Kafka yet, saving that for later.

Using FastAPI for the backend and React for the frontend.

Why FastAPI — it validates the data for me and gives me an auto docs page where I can test my endpoints without writing a frontend first. 

### Setting up the env

Made the virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install "fastapi[standard]" uvicorn
pip freeze > requirements.txt

Looks good