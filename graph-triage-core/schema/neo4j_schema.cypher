// =====================================================================
// OmniGuard Neo4j Graph Schema: Constraints, Indexes, and Upsert Queries
// Version: 1.1.0 (Tier 1 Core + Tier 2 Process/URL + Tier 3 Properties)
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

CREATE CONSTRAINT unique_url IF NOT EXISTS 
FOR (url:URL) REQUIRE url.url IS UNIQUE;

CREATE CONSTRAINT unique_process_id IF NOT EXISTS 
FOR (p:Process) REQUIRE p.process_id IS UNIQUE;

CREATE CONSTRAINT unique_alert_id IF NOT EXISTS 
FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE;

CREATE INDEX alert_timestamp_idx IF NOT EXISTS 
FOR (a:Alert) ON (a.timestamp);

CREATE INDEX alert_severity_idx IF NOT EXISTS 
FOR (a:Alert) ON (a.severity);

CREATE INDEX host_subnet_idx IF NOT EXISTS 
FOR (h:Host) ON (h.subnet);


// --- 2. Ingest VerifyEye Phishing Alert (Cypher Template) ---
// Expected parameters:
//   $alert_id, $source, $event_type, $severity, $confidence, $mitre_technique,
//   $timestamp, $description, $host_id, $user, $domain, $target_url, $action_endpoint,
//   $src_ip, $brand_target
MERGE (a:Alert {alert_id: $alert_id})
ON CREATE SET a.source = $source,
              a.event_type = $event_type,
              a.severity = $severity,
              a.confidence = $confidence,
              a.mitre_technique = $mitre_technique,
              a.timestamp = $timestamp,
              a.status = 'new',
              a.description = $description

// Host (with Tier 3 Asset & Network Segment properties)
MERGE (h:Host {host_id: $host_id})
ON CREATE SET h.hostname = $host_id, 
              h.status = 'ACTIVE',
              h.last_seen = $timestamp,
              h.is_critical_asset = false,
              h.asset_tier = 'workstation'
MERGE (a)-[:TARGETS_HOST]->(h)

// Tier 2 Node: URL (explicit lure page)
FOREACH (_ IN CASE WHEN $target_url IS NOT NULL AND $target_url <> '' THEN [1] ELSE [] END |
    MERGE (url:URL {url: $target_url})
    ON CREATE SET url.action_endpoint = $action_endpoint,
                  url.brand_target = $brand_target,
                  url.is_phishing = true,
                  url.first_seen = $timestamp
    MERGE (a)-[:TARGETS_URL]->(url)
    MERGE (h)-[:ACCESSED_URL {timestamp: $timestamp}]->(url)

    // Connect URL to parent Domain
    FOREACH (__ IN CASE WHEN $domain IS NOT NULL AND $domain <> '' THEN [1] ELSE [] END |
        MERGE (d:Domain {domain_name: $domain})
        ON CREATE SET d.brand_impersonated = $brand_target,
                      d.reputation_score = 0.95,
                      d.is_sinkholed = false
        MERGE (url)-[:BELONGS_TO]->(d)
        MERGE (a)-[:INDICATES_DOMAIN]->(d)
        MERGE (h)-[:RESOLVED_DOMAIN {timestamp: $timestamp}]->(d)
    )
)

// User (with Tier 3 Account property)
FOREACH (_ IN CASE WHEN $user IS NOT NULL AND $user <> '' THEN [1] ELSE [] END |
    MERGE (u:User {username: $user})
    ON CREATE SET u.account_type = 'ActiveDirectory',
                  u.privilege_level = 'standard'
    MERGE (a)-[:INVOLVES_USER]->(u)
    MERGE (u)-[:LOGGED_INTO {timestamp: $timestamp}]->(h)
)

// Source IP (with Tier 3 Subnet / Internal flags)
FOREACH (_ IN CASE WHEN $src_ip IS NOT NULL AND $src_ip <> '' THEN [1] ELSE [] END |
    MERGE (i:IP {address: $src_ip})
    ON CREATE SET i.is_internal = true
    MERGE (h)-[:HAS_IP]->(i)
);


// --- 3. Ingest SpectraC2 Beaconing Alert (Cypher Template) ---
// Expected parameters:
//   $alert_id, $source, $event_type, $severity, $confidence, $mitre_technique,
//   $timestamp, $host_id, $src_ip, $dst_ip, $dst_port, $proto, $service, $sni,
//   $beacon_interval, $mean_jitter, $pid, $process_name
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

// COMMUNICATED_WITH edge with Tier 3 Service property
MERGE (src_host)-[r:COMMUNICATED_WITH {port: $dst_port, proto: $proto}]->(dst_ip)
SET r.beacon_interval = $beacon_interval,
    r.mean_jitter = $mean_jitter,
    r.service = $service,
    r.last_seen = $timestamp

// Tier 2 Node: Process (if EDR telemetry supplies PID or process name)
FOREACH (_ IN CASE WHEN $pid IS NOT NULL THEN [1] ELSE [] END |
    MERGE (p:Process {process_id: $host_id + ':' + toString($pid)})
    ON CREATE SET p.pid = $pid,
                  p.name = coalesce($process_name, 'unknown.exe'),
                  p.started_at = $timestamp,
                  p.status = 'RUNNING'
    MERGE (src_host)-[:SPAWNED_PROCESS {timestamp: $timestamp}]->(p)
    MERGE (p)-[:INITIATED_FLOW {port: $dst_port, proto: $proto, timestamp: $timestamp}]->(dst_ip)
)

FOREACH (_ IN CASE WHEN $sni IS NOT NULL AND $sni <> '' THEN [1] ELSE [] END |
    MERGE (d:Domain {domain_name: $sni})
    MERGE (a)-[:INDICATES_DOMAIN]->(d)
    MERGE (dst_ip)-[:HOSTS_DOMAIN]->(d)
    MERGE (src_host)-[:RESOLVED_DOMAIN {timestamp: $timestamp}]->(d)
);


// --- 4. Stage 3 Lateral Movement & Process Injection (LSASS / Pass-the-Hash) ---
// Expected parameters:
//   $source_host_id, $target_host_id, $attacker_pid, $target_pid, $timestamp, $technique
//
// MERGE (src_p:Process {process_id: $source_host_id + ':' + toString($attacker_pid)})
// MERGE (tgt_p:Process {process_id: $target_host_id + ':' + toString($target_pid)})
// MERGE (src_p)-[:INJECTED_INTO {technique: $technique, timestamp: $timestamp}]->(tgt_p);


// --- 5. SOC Analyst & Ollama LLM Triage Queries ---

// A. Trace end-to-end attack story (VerifyEye lure -> Host -> Process -> SpectraC2 beacon):
// MATCH (url:URL)<-[:ACCESSED_URL]-(h:Host)-[:SPAWNED_PROCESS]->(p:Process)-[:INITIATED_FLOW]->(ip:IP)
// RETURN url, h, p, ip;

// B. Find multi-victim phishing campaigns sharing the same lure URL across enterprise:
// MATCH (h:Host)-[:ACCESSED_URL]->(url:URL {is_phishing: true})
// RETURN url.url AS PhishingURL, count(DISTINCT h) AS ImpactedHosts, collect(h.host_id) AS Hosts;

// C. Calculate multi-hop blast radius (2 hops) around compromised host:
// MATCH path = (h:Host {host_id: $host_id})-[*1..2]-(entity)
// RETURN path;
