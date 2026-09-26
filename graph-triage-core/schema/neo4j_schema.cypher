// =====================================================================
// OmniGuard Neo4j Graph Schema: Constraints, Indexes, and Upsert Queries
// =====================================================================

// --- 1. Unique Constraints & Indexes ---
CREATE CONSTRAINT unique_host_id IF NOT EXISTS 
FOR (h:Host) REQUIRE h.host_id IS UNIQUE;

CREATE CONSTRAINT unique_username IF NOT EXISTS 
FOR (u:User) REQUIRE u.username IS UNIQUE;

CREATE CONSTRAINT unique_ip_address IF NOT EXISTS 
FOR (i:IP) REQUIRE i.address IS UNIQUE;

CREATE CONSTRAINT unique_domain_name IF NOT EXISTS 
FOR (d:Domain) REQUIRE d.domain_name IS UNIQUE;

CREATE CONSTRAINT unique_alert_id IF NOT EXISTS 
FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE;

CREATE INDEX alert_timestamp_idx IF NOT EXISTS 
FOR (a:Alert) ON (a.timestamp);

CREATE INDEX alert_severity_idx IF NOT EXISTS 
FOR (a:Alert) ON (a.severity);

// --- 2. Ingest VerifyEye Phishing Alert (Cypher Template) ---
// Expected parameters:
//   $alert_id, $source, $event_type, $severity, $confidence, $mitre_technique,
//   $timestamp, $description, $host_id, $user, $domain, $target_url, $src_ip, $brand_target
MERGE (a:Alert {alert_id: $alert_id})
ON CREATE SET a.source = $source,
              a.event_type = $event_type,
              a.severity = $severity,
              a.confidence = $confidence,
              a.mitre_technique = $mitre_technique,
              a.timestamp = $timestamp,
              a.status = 'new',
              a.description = $description

MERGE (h:Host {host_id: $host_id})
ON CREATE SET h.hostname = $host_id, 
              h.status = 'ACTIVE',
              h.last_seen = $timestamp
MERGE (a)-[:TARGETS_HOST]->(h)

// Link User if present
FOREACH (_ IN CASE WHEN $user IS NOT NULL AND $user <> '' THEN [1] ELSE [] END |
    MERGE (u:User {username: $user})
    MERGE (a)-[:INVOLVES_USER]->(u)
    MERGE (u)-[:LOGGED_INTO {timestamp: $timestamp}]->(h)
)

// Link Malicious Domain if present
FOREACH (_ IN CASE WHEN $domain IS NOT NULL AND $domain <> '' THEN [1] ELSE [] END |
    MERGE (d:Domain {domain_name: $domain})
    ON CREATE SET d.brand_impersonated = $brand_target,
                  d.target_url = $target_url,
                  d.reputation_score = 0.95,
                  d.is_sinkholed = false
    MERGE (a)-[:INDICATES_DOMAIN]->(d)
    MERGE (h)-[:RESOLVED_DOMAIN {timestamp: $timestamp}]->(d)
)

// Link Source IP if present
FOREACH (_ IN CASE WHEN $src_ip IS NOT NULL AND $src_ip <> '' THEN [1] ELSE [] END |
    MERGE (i:IP {address: $src_ip})
    ON CREATE SET i.is_internal = true
    MERGE (h)-[:HAS_IP]->(i)
);


// --- 3. Ingest SpectraC2 Beaconing Alert (Cypher Template) ---
// Expected parameters:
//   $alert_id, $source, $event_type, $severity, $confidence, $mitre_technique,
//   $timestamp, $host_id, $src_ip, $dst_ip, $dst_port, $proto, $service, $sni,
//   $beacon_interval, $mean_jitter
MERGE (a:Alert {alert_id: $alert_id})
ON CREATE SET a.source = $source,
              a.event_type = $event_type,
              a.severity = $severity,
              a.confidence = $confidence,
              a.mitre_technique = $mitre_technique,
              a.timestamp = $timestamp,
              a.status = 'new',
              a.description = 'Periodic C2 beaconing detected via FFT/LSTM spectral inference'

MERGE (src_host:Host {host_id: $host_id})
ON CREATE SET src_host.status = 'ACTIVE',
              src_host.last_seen = $timestamp
MERGE (a)-[:TARGETS_HOST]->(src_host)

MERGE (dst_ip:IP {address: $dst_ip})
ON CREATE SET dst_ip.is_internal = false
MERGE (a)-[:INDICATES_IP]->(dst_ip)

MERGE (src_host)-[r:COMMUNICATED_WITH {port: $dst_port, proto: $proto}]->(dst_ip)
SET r.beacon_interval = $beacon_interval,
    r.mean_jitter = $mean_jitter,
    r.service = $service,
    r.last_seen = $timestamp

FOREACH (_ IN CASE WHEN $sni IS NOT NULL AND $sni <> '' THEN [1] ELSE [] END |
    MERGE (d:Domain {domain_name: $sni})
    MERGE (a)-[:INDICATES_DOMAIN]->(d)
    MERGE (dst_ip)-[:HOSTS_DOMAIN]->(d)
    MERGE (src_host)-[:RESOLVED_DOMAIN {timestamp: $timestamp}]->(d)
);


// --- 4. Useful Triage & Blast Radius Queries ---

// A. Find all alerts and compromised entities related to a given host
// MATCH (h:Host {host_id: $host_id})<-[:TARGETS_HOST]-(a:Alert)
// OPTIONAL MATCH (h)-[r:COMMUNICATED_WITH]->(ip:IP)
// OPTIONAL MATCH (h)-[:RESOLVED_DOMAIN]->(d:Domain)
// RETURN h, a, r, ip, d;

// B. Calculate multi-hop blast radius around compromised host (2 hops)
// MATCH path = (h:Host {host_id: $host_id})-[*1..2]-(entity)
// RETURN path;
