from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

from models import Alert

auth = (NEO4J_USER, NEO4J_PASSWORD)
driver = GraphDatabase.driver(NEO4J_URI, auth=auth)


# this key value dictionary is to make sure that we can label the nodes
NODE_KEY = {
    "Host": "hostname",
    "User": "username", 
    "Domain": "domain_name",
    "IP": "address", 
    "URL": "url", 
    "Process": "process_id", 
    "Technique": "id",
}

LABEL_KEY = {"Process": "name"}



# # HELPER function 
def _get_node_payload(node) -> tuple:
    # # we are extracting all the details of this node and then sending it back 
    label = list(node.labels)[0] # first item is what we want
    id_key = NODE_KEY[label]

    # only for process 
    label_key = LABEL_KEY.get(label, id_key)
    node_id = f"{label}:{node[id_key]}"

    return node_id, {"id": node_id, "type": label, "label": node[label_key]}


# helper function to build the graph 
def _build_graph(results):
    # now going to use the helper function and getting the nodes back
    # these return nodes and edges 
    nodes = {} 
    edges = []

    for res in results: 
        # get each objects 
        # # first the record (first node), second the relationship and then the record(last node)
        record_src, relationship, record_dst = res 

        record_src_id, record_src_payload = _get_node_payload(record_src)
        record_dst_id, record_dst_payload = _get_node_payload(record_dst)

        # now we are storing these payloads so that they are not duplicated
        nodes[record_src_id] = record_src_payload
        nodes[record_dst_id] = record_dst_payload

        # then we will make the edge as well
        edges.append({
            "id": f"{record_src_id}->{record_dst_id}",
            "source": record_src_id,
            "target": record_dst_id,
            "type":   relationship.type,
        })


    return {"nodes": list(nodes.values()), "edges": edges}
    

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


# getting the overview of the graph 
def _read_overview(tx): 
    results = tx.run(
        """
            MATCH (a)-[r:HAS_IP|LOGGED_INTO|CONNECTED_TO_DOMAIN|ACCESSED_URL
            |SPAWNED_PROCESS|BELONGS_TO|INITIATED_FLOW|HOSTS_DOMAIN]->(b)
            RETURN a, r, b
        """
    ) 

    return _build_graph(results)

# now the function to read each alert 
def _read_host(tx, hostname):
    results = tx.run(
        """
        MATCH (h:Host {hostname: $hostname})
            -[rels:HAS_IP|LOGGED_INTO|CONNECTED_TO_DOMAIN|ACCESSED_URL
                    |SPAWNED_PROCESS|BELONGS_TO|INITIATED_FLOW|HOSTS_DOMAIN*1..2]-(far)
        UNWIND rels AS r
        RETURN DISTINCT startNode(r) AS a, r, endNode(r) AS b
        """,
        hostname=hostname,
    )

    return _build_graph(results)

# the function that gets called in the main function and also called the private function here
def get_overview_graph():
    with driver.session() as session: 
        return session.execute_read(_read_overview)


# now write the host graph 
def get_host_graph(hostname):
    with driver.session() as session: 
        return session.execute_read(_read_host, hostname)


