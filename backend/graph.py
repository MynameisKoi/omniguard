from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD 

from models import Alert

auth = (NEO4J_USER, NEO4J_PASSWORD)
driver = GraphDatabase.driver(NEO4J_URI, auth=auth)

# writing the ingest alert function 
def ingest_alert(alert: Alert): 
    with driver.session() as session: 
        session.run(
            """
                MERGE (h:Host {hostname: $host})
                CREATE (a:Alert 
                    {
                        alert_id: $alert_id, 
                        severity: $severity,
                        event_type: $event_type, 
                        source: $source,
                        timestamp: $timestamp
                    })
                CREATE (a)-[:AFFECTS]->(h)
            """,
            host=alert.host,
            alert_id=alert.alert_id,
            severity=alert.severity,
            event_type=alert.event_type,
            source=alert.source,
            timestamp=alert.timestamp
        )

        if alert.user: 
            session.run(
                """
                    MATCH (a: Alert {alert_id: $alert_id})
                    MATCH (h: Host {hostname: $host}) 
                    MERGE (u: User {name: $user})
                    MERGE (a)-[:INVOLVES]->(u)
                    MERGE (u)-[:LOGGED_INTO]->(h)
                """,
                alert_id=alert.alert_id,
                host=alert.host,
                user=alert.user
            )

        if alert.domain: 
            session.run(
                """
                    MATCH (a: Alert {alert_id: $alert_id})
                    MATCH (h: Host {hostname: $host}) 
                    MERGE (d: Domain {name: $domain})
                    MERGE (a)-[:TARGETS]->(d)
                    MERGE (h)-[:CONNECTED_TO]->(d)
                """,
                alert_id=alert.alert_id,
                host=alert.host,
                domain=alert.domain
            )
        
        if alert.src_ip:
            session.run(
                """
                    MATCH (a: Alert {alert_id: $alert_id})
                    MATCH (h: Host {hostname: $host}) 
                    MERGE (i: IP {address: $src_ip})
                    MERGE (a)-[:FROM_IP]->(i)
                    MERGE (h)-[:HAS_IP]->(i)
                """,
                alert_id=alert.alert_id,
                host=alert.host,
                src_ip=alert.src_ip
            )

        if alert.dst_ip:
            session.run(
                """
                    MATCH (a: Alert {alert_id: $alert_id})
                    MERGE (dip: IP {address: $dst_ip})
                    MERGE (a)-[:TO_IP]->(dip)
                """,
                alert_id=alert.alert_id,
                dst_ip=alert.dst_ip
            )

        if alert.mitre_technique:
            session.run(
                """
                    MATCH (a:Alert {alert_id: $alert_id})
                    MERGE (t:Technique {id: $mitre_technique})
                    MERGE (a)-[:MAPS_TO]->(t)
                """,
                alert_id=alert.alert_id,
                mitre_technique=alert.mitre_technique
            )