from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

from models import Alert

auth = (NEO4J_USER, NEO4J_PASSWORD)
driver = GraphDatabase.driver(NEO4J_URI, auth=auth)

# wiring the new function for ensuring that we have required schemas before building the graph
def ensure_schema():
    # these are the rules that the schema must follow
    rules = [
        "CREATE CONSTRAINT host_unique IF NOT EXISTS FOR (h:Host) REQUIRE h.hostname IS UNIQUE",
        "CREATE CONSTRAINT user_unique IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE",
        "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.domain_name IS UNIQUE",
        "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
        "CREATE CONSTRAINT alert_unique IF NOT EXISTS FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE",
        "CREATE CONSTRAINT technique_unique IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
        "CREATE CONSTRAINT url_unique IF NOT EXISTS FOR (u:URL) REQUIRE u.url IS UNIQUE",
        "CREATE CONSTRAINT process_unique IF NOT EXISTS FOR (p:Process) REQUIRE p.process_id IS UNIQUE",

        # things we filter and sort by, but that are not unique
        "CREATE INDEX alert_timestamp_idx IF NOT EXISTS FOR (a:Alert) ON (a.timestamp)",
        "CREATE INDEX alert_severity_idx IF NOT EXISTS FOR (a:Alert) ON (a.severity)",
    ]

    with driver.session() as session:
        for rule in rules:
            session.run(rule)

ensure_schema() # making sure that the rules are made before it does any alerts


# the actual writes, all inside the transaction tx
def _write_alert(tx, alert: Alert):
    tx.run(
        """
            MERGE (h:Host {hostname: $host})
            MERGE (a:Alert{ alert_id: $alert_id} )
            ON CREATE SET
                    a.severity= $severity,
                    a.event_type= $event_type,
                    a.source= $source,
                    a.timestamp= $timestamp,
                    a.confidence=$confidence,
                    a.status=$status,
                    a.description=$description,
                    a.mitre_technique=$mitre_technique
            MERGE (a)-[:REPORTED_HOST]->(h)
        """,
        host=alert.host,
        alert_id=alert.alert_id,
        severity=alert.severity,
        event_type=alert.event_type,
        source=alert.source,
        timestamp=alert.timestamp,
        confidence=alert.confidence,
        status=alert.status,
        description=alert.description,
        mitre_technique=alert.mitre_technique
    )

    if alert.user:
        tx.run(
            """
                MATCH (a: Alert {alert_id: $alert_id})
                MATCH (h: Host {hostname: $host})
                MERGE (u: User {username: $user})
                MERGE (a)-[:REPORTED_USER]->(u)
                MERGE (u)-[:LOGGED_INTO]->(h)
            """,
            alert_id=alert.alert_id,
            host=alert.host,
            user=alert.user
        )

    if alert.domain:
        tx.run(
            """
                MATCH (a: Alert {alert_id: $alert_id})
                MATCH (h: Host {hostname: $host})
                MERGE (d: Domain {domain_name: $domain})
                MERGE (a)-[:REPORTED_DOMAIN]->(d)
                MERGE (h)-[:CONNECTED_TO_DOMAIN]->(d)
            """,
            alert_id=alert.alert_id,
            host=alert.host,
            domain=alert.domain
        )

    if alert.target_url:
        tx.run(
            """
                MATCH (a: Alert {alert_id: $alert_id})
                MATCH (h: Host {hostname: $host})
                MERGE (u: URL {url: $target_url})
                ON CREATE SET
                    u.action_endpoint = $action_endpoint,
                    u.brand_target = $brand_target
                MERGE (a)-[:REPORTED_URL]->(u)
                MERGE (h)-[:ACCESSED_URL]->(u)
            """,
            alert_id=alert.alert_id,
            host=alert.host,
            target_url=alert.target_url,
            action_endpoint=alert.action_endpoint,
            brand_target=alert.brand_target
        )

    if alert.target_url and alert.domain:
        tx.run(
            """
                MATCH (u: URL {url: $target_url})
                MATCH (d: Domain {domain_name: $domain})
                MERGE (u)-[:BELONGS_TO]->(d)
            """,
            target_url=alert.target_url,
            domain=alert.domain
        )

    if alert.src_ip:
        tx.run(
            """
                MATCH (a: Alert {alert_id: $alert_id})
                MATCH (h: Host {hostname: $host})
                MERGE (i: IP {address: $src_ip})
                MERGE (a)-[:REPORTED_SRC_IP]->(i)
                MERGE (h)-[:HAS_IP]->(i)
            """,
            alert_id=alert.alert_id,
            host=alert.host,
            src_ip=alert.src_ip
        )

    if alert.dst_ip:
        tx.run(
            """
                MATCH (a: Alert {alert_id: $alert_id})
                MERGE (dip: IP {address: $dst_ip})
                MERGE (a)-[r:REPORTED_DST_IP]->(dip)
                SET
                    r.port = $dst_port,
                    r.beacon_interval = $beacon_interval,
                    r.mean_jitter = $mean_jitter
            """,
            alert_id=alert.alert_id,
            dst_ip=alert.dst_ip,
            dst_port=alert.dst_port,
            beacon_interval=alert.beacon_interval,
            mean_jitter=alert.mean_jitter
        )

    if alert.dst_ip and alert.domain: 
        tx.run(
            """
                MATCH (dip:IP {address: $dst_ip})
                MATCH (d:Domain {domain_name: $domain})
                MERGE (dip)-[:HOSTS_DOMAIN]->(d)
            """,
            dst_ip=alert.dst_ip,
            domain=alert.domain
        )

    # pid alone is not unique (reused over time, same pid on other machines),
    # so the key is host + pid, e.g. "LAPTOP-10:4920"
    if alert.pid is not None:
        process_id = f"{alert.host}:{alert.pid}"
        tx.run(
            """
                MATCH (a: Alert {alert_id: $alert_id})
                MATCH (h: Host {hostname: $host})
                MERGE (p: Process {process_id: $process_id})
                ON CREATE SET
                    p.pid = $pid,
                    p.name = $process_name
                MERGE (h)-[:SPAWNED_PROCESS]->(p)
                MERGE (a)-[:REPORTED_PROCESS]->(p)
            """,
            alert_id=alert.alert_id,
            host=alert.host,
            process_id=process_id,
            pid=alert.pid,
            process_name=alert.process_name
        )

    # which program on the host is talking to the C2 server
    if alert.pid is not None and alert.dst_ip:
        tx.run(
            """
                MATCH (p: Process {process_id: $process_id})
                MATCH (dip: IP {address: $dst_ip})
                MERGE (p)-[f:INITIATED_FLOW]->(dip)
                SET f.port = $dst_port
            """,
            process_id=f"{alert.host}:{alert.pid}",
            dst_ip=alert.dst_ip,
            dst_port=alert.dst_port
        )

    if alert.mitre_technique:
        tx.run(
            """
                MATCH (a:Alert {alert_id: $alert_id})
                MERGE (t:Technique {id: $mitre_technique})
                MERGE (a)-[:MAPS_TO_TECHNIQUE]->(t)
            """,
            alert_id=alert.alert_id,
            mitre_technique=alert.mitre_technique
        )

# what main.py calls. Opens one transaction so an alert is written
# completely or not at all.
def ingest_alert(alert: Alert):
    with driver.session() as session:
        session.execute_write(_write_alert, alert)


# ── Read functions for GET /graph ────────────────────────────────────────────

def _node_to_element(node) -> dict:
    """Convert a Neo4j node to a Cytoscape element dict."""
    label = list(node.labels)[0]
    props = dict(node)
    # pick a human-readable display name based on node type
    display = (
        props.get("hostname")
        or props.get("username")
        or props.get("address")
        or props.get("domain_name")
        or props.get("url")
        or props.get("process_id")
        or props.get("id")          # Technique
        or str(node.element_id)
    )
    return {
        "data": {
            "id": node.element_id,
            "label": label,
            "display": display,
            **props,
        }
    }


def _rel_to_element(rel) -> dict:
    """Convert a Neo4j relationship to a Cytoscape element dict."""
    props = dict(rel)
    return {
        "data": {
            "id": rel.element_id,
            "source": rel.start_node.element_id,
            "target": rel.end_node.element_id,
            "type": rel.type,
            **props,
        }
    }


def get_entity_graph() -> dict:
    """
    Return the full entity-layer graph as Cytoscape-ready {nodes, edges}.

    Only entity nodes are included (Host, IP, Domain, URL, Process, User,
    Technique). Alert nodes and REPORTED_* edges are intentionally excluded —
    alerts are fetched separately via GET /alerts. The entity layer shows
    standing network facts that survive any individual alert, and it stays
    readable at volume because the number of entities grows much slower than
    the number of alerts.
    """
    # The entity labels we want — everything except Alert.
    entity_labels = ["Host", "IP", "Domain", "URL", "Process", "User", "Technique"]
    label_match = " OR ".join(f"n:{lbl}" for lbl in entity_labels)

    # Standing-fact relationships only — no REPORTED_* edges.
    standing_types = [
        "HAS_IP", "LOGGED_INTO", "CONNECTED_TO_DOMAIN",
        "ACCESSED_URL", "SPAWNED_PROCESS", "BELONGS_TO",
        "INITIATED_FLOW", "HOSTS_DOMAIN",
    ]
    rel_match = "|".join(standing_types)

    with driver.session() as session:
        # Collect nodes
        node_result = session.run(
            f"MATCH (n) WHERE {label_match} RETURN n"
        )
        nodes = [_node_to_element(r["n"]) for r in node_result]

        # Collect standing-fact edges (both endpoints must be entity nodes)
        edge_result = session.run(
            f"""
            MATCH (a)-[r:{rel_match}]->(b)
            WHERE ({label_match.replace('n:', 'a:')})
              AND ({label_match.replace('n:', 'b:')})
            RETURN r, a, b
            """,
        )
        edges = []
        for r in edge_result:
            elem = _rel_to_element(r["r"])
            # element_id from the relationship node objects won't automatically
            # carry the endpoint element_ids — set them explicitly from the
            # matched nodes so Cytoscape source/target refs are correct.
            elem["data"]["source"] = r["a"].element_id
            elem["data"]["target"] = r["b"].element_id
            edges.append(elem)

    return {"nodes": nodes, "edges": edges}


def get_host_subgraph(hostname: str) -> dict:
    """
    Return a 2-hop subgraph centred on the given hostname as {nodes, edges}.
    Includes all nodes reachable within 2 hops via any relationship type,
    and all edges between those nodes. Alert nodes are still excluded.
    """
    entity_labels = ["Host", "IP", "Domain", "URL", "Process", "User", "Technique"]
    label_filter = " OR ".join(f"x:{lbl}" for lbl in entity_labels)

    with driver.session() as session:
        result = session.run(
            f"""
            MATCH (h:Host {{hostname: $hostname}})
            MATCH path = (h)-[*1..2]-(x)
            WHERE {label_filter}
            WITH nodes(path) AS ns, relationships(path) AS rs
            UNWIND ns AS n UNWIND rs AS r
            RETURN DISTINCT n, r,
                   startNode(r) AS src, endNode(r) AS tgt
            """,
            hostname=hostname,
        )

        seen_nodes: dict = {}
        seen_edges: dict = {}
        for row in result:
            n = row["n"]
            if n.element_id not in seen_nodes:
                seen_nodes[n.element_id] = _node_to_element(n)
            rel = row["r"]
            if rel.element_id not in seen_edges:
                elem = _rel_to_element(rel)
                elem["data"]["source"] = row["src"].element_id
                elem["data"]["target"] = row["tgt"].element_id
                seen_edges[rel.element_id] = elem

        # Always include the root Host node even if it has no edges
        if not seen_nodes:
            root = session.run(
                "MATCH (h:Host {hostname: $hostname}) RETURN h",
                hostname=hostname,
            ).single()
            if root:
                n = root["h"]
                seen_nodes[n.element_id] = _node_to_element(n)

    return {"nodes": list(seen_nodes.values()), "edges": list(seen_edges.values())}