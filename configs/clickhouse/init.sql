-- =============================================================================
-- CyberSentinel WAF — ClickHouse Schema Initialization
-- Database: cybersentinel
-- Executed automatically on first container start via docker-entrypoint-initdb.d
-- =============================================================================

CREATE DATABASE IF NOT EXISTS cybersentinel;

-- =============================================================================
-- Table 1: waf_events — Core ModSecurity Audit Log
-- MergeTree with monthly partitions, 90-day TTL
-- =============================================================================
CREATE TABLE IF NOT EXISTS cybersentinel.waf_events
(
    -- Identity
    id                  String,
    timestamp           DateTime('Asia/Kolkata'),

    -- Request
    client_ip           String,
    country             LowCardinality(String) DEFAULT '',
    source_asn_org      String DEFAULT '',
    method              LowCardinality(String) DEFAULT '',
    uri                 String DEFAULT '',
    hostname            String DEFAULT '',
    http_code           LowCardinality(String) DEFAULT '',

    -- Threat classification
    rule_id             String DEFAULT '',
    message             String DEFAULT '',
    severity            LowCardinality(String) DEFAULT '',
    attack_type         LowCardinality(String) DEFAULT '',

    -- Headers stored as JSON strings
    request_headers     String DEFAULT '{}',
    response_headers    String DEFAULT '{}',

    -- Violations — JSON array of matched rules
    violations          String DEFAULT '[]',

    -- Full raw audit JSON (stored compressed)
    raw_log             String DEFAULT '',

    -- Ingestion metadata
    log_source          LowCardinality(String) DEFAULT 'modsec_audit',
    ingested_at         DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, client_ip, id)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;


-- =============================================================================
-- Table 2: ml_events — ML Engine Scoring Events
-- MergeTree with monthly partitions, 90-day TTL
-- =============================================================================
CREATE TABLE IF NOT EXISTS cybersentinel.ml_events
(
    unique_id           String DEFAULT '',
    timestamp           DateTime('Asia/Kolkata'),
    remote_addr         String DEFAULT '',

    -- Request features fed to ML models
    method              LowCardinality(String) DEFAULT '',
    uri                 String DEFAULT '',
    args                String DEFAULT '',
    ct                  String DEFAULT '',
    ua                  String DEFAULT '',
    body_len            Float32 DEFAULT 0.0,

    -- Signals
    crs_score           Float32 DEFAULT 0.0,
    matched_vars        String DEFAULT '',
    redis_rpm           Float32 DEFAULT 0.0,
    redis_rep           Float32 DEFAULT 0.0,
    abuse_score         Float32 DEFAULT 0.0,

    -- ML model outputs
    xgb_prob            Float32 DEFAULT 0.0,
    iso_score           Float32 DEFAULT 0.0,
    threat_score        Float32 DEFAULT 0.0,
    decision            LowCardinality(String) DEFAULT '',

    ingested_at         DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, remote_addr)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;


-- =============================================================================
-- Table 3: analyst_feedback — False Positives flagged by SOC analysts
-- ReplacingMergeTree so duplicate flags on the same log_id deduplicate
-- =============================================================================
CREATE TABLE IF NOT EXISTS cybersentinel.analyst_feedback
(
    id                  String DEFAULT toString(generateUUIDv4()),
    log_id              String,
    rule_id             String DEFAULT '',
    client_ip           String DEFAULT '',
    uri                 String DEFAULT '',
    event_timestamp     DateTime('Asia/Kolkata'),

    severity            LowCardinality(String) DEFAULT '',
    attack_type         LowCardinality(String) DEFAULT '',

    -- Analyst workflow
    status              LowCardinality(String) DEFAULT 'Pending',
    analyst_note        String DEFAULT '',
    created_by          LowCardinality(String) DEFAULT 'system',
    created_at          DateTime DEFAULT now(),

    -- Raw snapshot at time of flagging
    raw_log             String DEFAULT ''
)
ENGINE = ReplacingMergeTree(created_at)
PARTITION BY toYYYYMM(created_at)
ORDER BY (log_id, created_by)
SETTINGS index_granularity = 8192;


-- =============================================================================
-- Table 4: threat_intelligence — IP reputation events over time
-- MergeTree, 90-day TTL
-- =============================================================================
CREATE TABLE IF NOT EXISTS cybersentinel.threat_intelligence
(
    client_ip           String,
    timestamp           DateTime DEFAULT now(),
    country             LowCardinality(String) DEFAULT '',
    asn_org             String DEFAULT '',

    abuse_score         Float32 DEFAULT 0.0,
    redis_rep           Float32 DEFAULT 0.0,
    threat_level        LowCardinality(String) DEFAULT 'unknown',
    is_blocked          UInt8 DEFAULT 0,
    block_reason        String DEFAULT '',

    source              LowCardinality(String) DEFAULT 'ml_engine'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, client_ip)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;


-- =============================================================================
-- Table 5: api_discovery — Discovered API endpoints with counters
-- SummingMergeTree automatically sums counter columns on background merge
-- =============================================================================
CREATE TABLE IF NOT EXISTS cybersentinel.api_discovery
(
    uri                 String,
    method              LowCardinality(String),
    timestamp           DateTime,

    -- Counters — SummingMergeTree accumulates these
    hit_count           UInt64 DEFAULT 1,
    error_count         UInt64 DEFAULT 0,
    malicious_count     UInt64 DEFAULT 0,
    suspicious_count    UInt64 DEFAULT 0,
    external_hit_count  UInt64 DEFAULT 0,
    internal_hit_count  UInt64 DEFAULT 0,

    -- Static endpoint attributes
    has_https           UInt8 DEFAULT 1,
    has_versioning      UInt8 DEFAULT 0,
    content_encoding    LowCardinality(String) DEFAULT '',
    avg_response_time_ms Float32 DEFAULT 0.0,

    -- Query-param NAMES observed this batch — never values (see
    -- api_discovery.extract_param_names). Read path unions this across
    -- all batches per endpoint to build the full observed set.
    param_names          Array(String) DEFAULT [],

    first_seen          DateTime DEFAULT now()
)
ENGINE = SummingMergeTree((hit_count, error_count, malicious_count, suspicious_count, external_hit_count, internal_hit_count))
PARTITION BY toYYYYMM(timestamp)
ORDER BY (uri, method, timestamp)
SETTINGS index_granularity = 8192;


-- =============================================================================
-- Table 6: audit_log — System configuration change history
-- MergeTree, 365-day TTL (compliance / 1-year retention)
-- =============================================================================
CREATE TABLE IF NOT EXISTS cybersentinel.audit_log
(
    id                  String DEFAULT toString(generateUUIDv4()),
    timestamp           DateTime DEFAULT now(),
    entity_type         LowCardinality(String),
    entity_id           String,
    action              LowCardinality(String),
    username            LowCardinality(String),
    details             String DEFAULT '',
    ip_address          String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, entity_type, entity_id)
TTL timestamp + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;


-- =============================================================================
-- Table 7: alert_history — Fired alert records (append-only)
-- Replaces the alert_history table in alerts.db for historical queries
-- =============================================================================
CREATE TABLE IF NOT EXISTS cybersentinel.alert_history
(
    id                  UInt64,
    rule_id             UInt32 DEFAULT 0,
    rule_name           String DEFAULT '',
    event_type          LowCardinality(String) DEFAULT '',
    severity            LowCardinality(String) DEFAULT '',
    channels_notified   String DEFAULT '',
    event_data          String DEFAULT '',
    message             String DEFAULT '',
    status              LowCardinality(String) DEFAULT 'sent',
    error_message       String DEFAULT '',
    acknowledged_by     String DEFAULT '',
    acknowledged_at     Nullable(DateTime),
    created_at          DateTime DEFAULT now(),
    channel_results     String DEFAULT '[]'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (created_at, severity, rule_id)
TTL created_at + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;
