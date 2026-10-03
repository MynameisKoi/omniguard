# Dev Log

My notes while building the OmniGuard dashboard + backend + frontend + MongoDB. Newest on top.

---


## Thu–Fri, Oct 2 2026

Big week. Got the graph working end to end, made alerts live, rebuilt the
dashboard, and dockerized everything. Wrote all of this myself, used Claude as a
teacher to explain the parts I hadn't done before (neo4j reads, websockets,
docker).

### Attack graph

Built `GET /graph` — reads the entity graph out of Neo4j and returns
`{nodes, edges}` for the frontend. Key decision: filter by relationship type,
not node label, so Alert nodes never leak into the graph. Learned the hard way
why node ids have to be mine (`Host:LAPTOP-10`) and not neo4j's element id —
those change on restart.

Then `GET /graph/host/{hostname}` for the per-alert view — one host's
neighbourhood at depth 2. Depth 2 is nice because it pulls in the *other* hosts
that touched the same C2 / phishing domain, which is exactly the thing a list of
alerts can't show you.

Pulled the record→nodes/edges loop into one `_build_graph` helper so the two
read functions don't repeat it.

Frontend uses Cytoscape — shape per entity type, size by how many things a node
connects to, click to highlight a node's neighbourhood. Took a while to get the
live-update right: every new alert was re-running the layout and the whole graph
jumped. Fixed it by locking existing nodes so only new ones get placed.

### Live alerts

WebSocket at `/ws/alerts`. Small connection manager that keeps the list of open
sockets and broadcasts each new alert after it's written. `POST /alerts` became
async so it can await the broadcast; the blocking Mongo/Neo4j writes go through
a threadpool so they don't freeze the event loop. Didn't need motor — the socket
never touches the db.

### Dashboard

Redesigned it off some real SOC dashboards. Stat cards with sparklines, severity
donut, top MITRE techniques, a small graph preview, top affected hosts by a
simple risk score. Some panels (the 24h chart, the sparklines) are sample data
for now — marked them clearly, they need a /stats endpoint later. Light and dark
both work.

### Docker

`docker compose up` runs mongo, neo4j, backend, frontend. Learned what an image
vs a container is, why localhost doesn't work inside a container (it's the
container itself, so it's `mongo:27017` by service name), and why the frontend is
a two-stage build — node to build it, nginx to serve it. Pulled the config out
to env vars so the same code runs local or in docker. Slimmed requirements.txt
down to the 6 packages I actually import.

Left the engines out of compose on purpose — Khoi and Rahim own their
Dockerfiles, and the engines already talk to the backend over HTTP.

### Next

Scale stuff for the graph (limits, filters, counters on ingest), then Ollama.
Also want to try a VerifyEye test where it catches a fake login page locally.


## Mon 28 – Tue 29 Sept

Khoi pushed his branch and it turned out he'd built a second FastAPI service
with its own `POST /api/v1/alerts`, plus his own alert schemas. So we had the
same layer twice with different names for everything.

Merged it in and picked it apart.

Kept mine: one `AlertCreate`, lowercase severity, `host` not `host_id`,
`domain` not `sni`, and the server stamping `alert_id` + `timestamp` so nobody
can forge an ID or backdate an alert.

Kept his: the node model. `URL` and `Process` nodes, connection detail on the
edges, the constraints. The URL node is the good bit — it links every host that
hit the same phishing page, which my Domain-only version couldn't show.

Deleted his API. One way in.

Final relationship names:

```
Alert -[:REPORTED_HOST]->       Host
Alert -[:REPORTED_USER]->       User
Alert -[:REPORTED_DOMAIN]->     Domain
Alert -[:REPORTED_SRC_IP]->     IP
Alert -[:REPORTED_DST_IP]->     IP     {port, beacon_interval, mean_jitter}
Alert -[:MAPS_TO_TECHNIQUE]->   Technique
Alert -[:REPORTED_URL]->        URL
Alert -[:REPORTED_PROCESS]->    Process

User  -[:LOGGED_INTO]->         Host
Host  -[:HAS_IP]->              IP
Host  -[:CONNECTED_TO_DOMAIN]-> Domain
Host  -[:ACCESSED_URL]->        URL
Host  -[:SPAWNED_PROCESS]->     Process
URL   -[:BELONGS_TO]->          Domain
IP    -[:HOSTS_DOMAIN]->        Domain
Process -[:INITIATED_FLOW]->    IP
```

Skipped `INJECTED_INTO` — needs a parent and target process and we only carry
one, so there'd be nothing to put in it.

Renamed all the Alert edges to `REPORTED_*` after looking at the actual graph.
`Alert -[FROM_SRC_IP]-> IP` reads like the alert came from that IP, which it
didn't — an alert is an observation, not a thing that does stuff. Names that
were fine in the file were wrong on the canvas with arrows drawn.

Side effect: the two layers are now obvious at a glance. Every `REPORTED_*`
edge is evidence from one alert; everything else is a standing fact about the
network. Which matters for the frontend — the entity edges alone show that
LAPTOP-10 and WORKSTATION-CORP-42 both reach 198.51.100.42, so the canvas can
render entities only and keep alerts in a side panel. Alert nodes pile up with
volume, entities don't.

Other stuff:

- `ingest_alert()` runs in one transaction now. Before, the five `session.run`
  calls each committed separately, so a failure halfway left an Alert with no
  User on it.
- Alert is `MERGE`d on `alert_id` not `CREATE`d, so re-posting the same alert
  does nothing instead of blowing up on the constraint.
- Eight new optional fields — `dst_port`, `beacon_interval`, `mean_jitter`,
  `process_name`, `pid`, `target_url`, `action_endpoint`, `brand_target`.
- Repointed Khoi's consumer at `/alerts`.
- Rewrote the JSON schema, it still said `host_id` and uppercase severity which would've sent Rahim straight into 422s.

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