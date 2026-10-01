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