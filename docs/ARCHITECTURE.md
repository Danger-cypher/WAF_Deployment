# CyberSentinel WAF — System Architecture & Component Design

> **Document Type:** Technical Architecture Specification  
> **Status:** Active Production System  
> **Repository Base:** `/opt/ModSecurity/WAF_GUI`  
> **Verification Standards:** All component interactions, phases, network topologies, and lifecycle hooks are verified directly from source code and runtime configurations.

---

## 1. High-Level Architecture Topology

CyberSentinel WAF operates as a containerized security gateway and control plane deployed via Docker Compose on an isolated bridge network (`waf-network`, IPv4 subnet `172.20.0.0/16`, IPv6 subnet `fd00::/80`).

```mermaid
graph TB
    subgraph "Public / External Network"
        Users[Web Clients / Browsers]
        Attackers[Malicious Traffic / Bots]
        SIEM[Enterprise SIEM / Identity Provider]
    end

    subgraph "Host Interface Ports"
        P3443[Port 3443: HTTPS Dashboard TLS]
        P3020[Port 3020: HTTP Dashboard Legacy]
        P443[Port 443: HTTPS WAF Gateway]
        P80[Port 80: HTTP Redirect to 443]
        P8123[Port 127.0.0.1:8123: ClickHouse Admin]
    end

    subgraph "Docker Bridge: waf-network (172.20.0.0/16)"
        subgraph "Ingress & Enforcement Gateway"
            OpenResty["waf-openresty (OpenResty 1.25.3.2)<br/>• Lua Access Phase (ml_check.lua)<br/>• ModSecurity v3 (CRS v4)<br/>• Lua Content Phase (ml_decide.lua)<br/>• Nginx Reverse Proxy"]
        end

        subgraph "Intelligence & Threat Scoring"
            MLEngine["waf-ml (FastAPI Daemon :9000)<br/>• XGBoost Classifier<br/>• Isolation Forest Detector<br/>• Drift Monitor Loop (6h)"]
            ClamAV["waf-clamav (ClamAV Daemon :3310)<br/>• INSTREAM TCP Malware Scanning"]
        end

        subgraph "Control Plane & Management"
            Backend["waf-backend (FastAPI App :8000)<br/>• REST API & Auth Engine<br/>• 12 Concurrent Background Loops<br/>• WebSocket Event Broadcaster<br/>• Nginx Config Generator"]
            Frontend["waf-frontend (Nginx Alpine :80)<br/>• React Vite SPA Static Host"]
            SocketProxy["waf-docker-socket-proxy (:2375)<br/>• Scoped Docker API Guard"]
            Certbot["waf-certbot<br/>• Automated Let's Encrypt Renewal"]
        end

        subgraph "Persistence & Caching"
            Redis[("waf-redis (:6379)<br/>• RPM & Reputation Counters<br/>• CIDR Blacklists / Whitelists<br/>• JA4 Fingerprint Store<br/>• Active Sessions Hash")]
            ClickHouse[("waf-clickhouse (:8123, :9000)<br/>• waf_events (MergeTree)<br/>• ml_events (MergeTree)<br/>• api_discovery (SummingMergeTree)<br/>• audit_log & alert_history")]
            SQLiteDB[("SQLite Databases (WAL Mode)<br/>• users.db, alerts.db, false_positives.db<br/>• api_keys.db, ml_events.db")]
            Litestream["waf-litestream<br/>• Continuous SQLite WAL Streaming"]
        end
    end

    subgraph "Upstream Application Tier"
        ProtectedApp1[Protected Application A :8080]
        ProtectedApp2[Protected Application B :3000]
        ProtectedAPI[Internal Microservices / APIs]
    end

    Users --> P3443
    Users --> P443
    Attackers --> P443
    SIEM -.-> P3443

    P3443 --> OpenResty
    P3020 --> OpenResty
    P443 --> OpenResty
    P80 --> OpenResty
    P8123 --> ClickHouse

    OpenResty -->|Check IP/JA4/Geo/DDoS| Redis
    OpenResty -->|Inference Query :9000| MLEngine
    OpenResty -->|@inspectFile Stream| ClamAV
    OpenResty -->|Proxy Clean Traffic| ProtectedApp1
    OpenResty -->|Proxy Clean Traffic| ProtectedApp2
    OpenResty -->|Proxy Clean Traffic| ProtectedAPI
    OpenResty -->|Proxy /api/ & /logs/stream| Backend
    OpenResty -->|Serve UI Assets| Frontend

    Backend -->|Analytics & Logs| ClickHouse
    Backend -->|Throttle & Cache| Redis
    Backend -->|Model Queries| MLEngine
    Backend -->|Cert Upload Malware Scan| ClamAV
    Backend -->|Scoped Exec / Restart| SocketProxy
    Backend -->|Read / Write Control State| SQLiteDB

    MLEngine -->|Reputation & Abuse Cache| Redis
    MLEngine -->|Persist Inferences| ClickHouse
    MLEngine -->|POST /alerts/trigger| Backend

    Litestream -->|Stream WAL| SQLiteDB
    Certbot -->|HTTP-01 Challenge Webroot| OpenResty
```

---

## 2. Decoupled Dual-Phase Inspection Gateway

A core innovation in CyberSentinel WAF is the separation of request evaluation into distinct OpenResty execution phases: **Access Phase** ([`ml-waf/ml_check.lua`](file:///opt/ModSecurity/WAF_GUI/ml-waf/ml_check.lua)) and **Content Phase** ([`ml-waf/ml_decide.lua`](file:///opt/ModSecurity/WAF_GUI/ml-waf/ml_decide.lua)).

### 2.1 The Phase-Order Race Condition Problem
In standard OpenResty deployments, dynamic modules (such as `ngx_http_modsecurity_module.so` loaded via `load_module`) register their handlers inside the Nginx `ACCESS` phase. However, Nginx provides no execution order guarantees between dynamic modules and static Lua directives (`access_by_lua_file`) within the same phase. 

In earlier revisions, attempting to read ModSecurity's anomaly score from `access_by_lua_file` resulted in a silent race: Lua frequently ran *before* ModSecurity evaluated the request body, reading an unpopulated anomaly score of `0.0` even on severe attacks.

### 2.2 The Dual-Phase Solution

```text
[ Client Request ]
       │
       ▼
┌───────────────────────────────────────────────────────────┐
│ 1. OPENRESTY ACCESS PHASE (ml_check.lua)                  │
│    • Control vs Data Plane Exemption Check               │
│    • mTLS Client Certificate Validation                  │
│    • Exact IP & CIDR Whitelist / Blacklist (Redis)        │
│    • External Threat Feed CIDR Enforcement (Spamhaus)     │
│    • Self-Learned Auto-Reputation Blacklist               │
│    • JA4 TLS Client Fingerprint Matching                  │
│    • GeoIP2 Country Whitelist / Blacklist                 │
│    • Verified Good-Bot Verification (Googlebot/Bingbot)   │
│    • Adaptive Per-Identity Throttle (IP/JA4/ASN)          │
│    • Bad-Bot Rate Limiting (HTTP 444 or 429)              │
│    • Positive Security API Schema Validation              │
│    • API Enumeration Detection                            │
│    • Interactive JavaScript Challenge Interstitial        │
└───────────────────────────────────────────────────────────┘
       │ (Passes stateless gates)
       ▼
┌───────────────────────────────────────────────────────────┐
│ 2. MODSECURITY v3 ENGINE INSPECTION                       │
│    • Pre-CRS Exclusions (rules-exclusions-before-crs.conf)│
│    • OWASP CRS v4 Execution (SQLi, XSS, RCE, LFI, etc.)   │
│    • Malware Scan via @inspectFile (malware-scan.sh)      │
│    • Anomaly Score Accumulation in TX collection          │
│    • Connector Variable Export: $modsecurity_anomaly_score│
└───────────────────────────────────────────────────────────┘
       │ (Access phase fully completed)
       ▼
┌───────────────────────────────────────────────────────────┐
│ 3. OPENRESTY CONTENT PHASE (ml_decide.lua)                │
│    • SecRuleEngine Posture Check (On / DetectionOnly / Off│
│    • Read $modsecurity_anomaly_score (Guaranteed Valid)   │
│    • Extract JA4 & GeoIP2 ASN                             │
│    • Synchronous HTTP POST to waf-ml:9000/predict         │
│    • Fallback to crs_only_fallback() if Daemon Offline    │
│    • Decision Enforcement (Block 403 / RateLimit 429)     │
│    • Internal Handoff: ngx.exec(@upstream) on Allow       │
└───────────────────────────────────────────────────────────┘
       │
       ▼
[ Protected Upstream Application ]
```

---

## 3. Core Component Subsystems

### 3.1 OpenResty Gateway & Custom Connector Patches
OpenResty 1.25.3.2 is compiled from source in [`openresty/Dockerfile`](file:///opt/ModSecurity/WAF_GUI/openresty/Dockerfile) with custom patches applied to upstream ModSecurity:
1. **TX Variable Accessor Patch** ([`01-libmodsecurity-tx-variable-accessor.patch`](file:///opt/ModSecurity/WAF_GUI/openresty/patches/01-libmodsecurity-tx-variable-accessor.patch)):
   Adds `msc_get_tx_variable(Transaction *transaction, const char *variable_name)` to `libmodsecurity`. This exposes internal transactional variables (such as `TX:BLOCKING_INBOUND_ANOMALY_SCORE`) via the C API.
2. **Connector Variable Patch** ([`02-connector-anomaly-score-variable.patch`](file:///opt/ModSecurity/WAF_GUI/openresty/patches/02-connector-anomaly-score-variable.patch)):
   Integrates with ModSecurity-nginx connector to register `$modsecurity_anomaly_score` as a first-class Nginx variable, accessible directly in Lua scripts.

### 3.2 Machine Learning Threat Engine (`waf-ml`)
Running as a dedicated FastAPI daemon on port `9000`:
- **Supervised Model:** XGBoost classifier (`xgboost.pkl`) trained on 30 extracted numerical features, outputting `xgb_prob` (probability of known attack patterns).
- **Unsupervised Model:** Isolation Forest (`isolation_forest.pkl`) computing `iso_score` (novelty/anomaly score indicating zero-day or unusual structural payloads).
- **Behavioral Context:** Integrates with Redis to track request velocity (`redis_rpm`), historical client bad behavior (`redis_rep`), and queries external AbuseIPDB intelligence on cache misses.
- **Decision Engine:** Blends inputs into a normalized score ($0.0 - 1.0$) and applies decision thresholds (`block`, `rate_limit`, `log`, `allow`).

### 3.3 Control Plane Backend (`waf-backend`)
Implemented in FastAPI on port `8000`:
- **API Management:** Exposes RESTful endpoints for dashboard configuration, rule management, and log review.
- **Nginx Configuration Engine:** [`nginx_manager.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/services/nginx_manager.py) translates database state into validated Nginx virtual host configs, positive security directives, DDoS rate limit zones, and custom block HTML pages.
- **Docker Socket Isolation:** Interacts with the Docker daemon exclusively through `waf-docker-socket-proxy:2375`. Restricts permissions to container inspection, `openresty -t` execution, and container restarts (`EXEC`, `RESTART`, `CONTAINERS`).
- **Heartbeat & Watchdog Registry:** Monitors 12 background loops, tracking monotonic heartbeats and dispatching critical alerts if workers go silent.

### 3.4 Data Storage Architecture
- **ClickHouse Columnar Store:** Ingests high-volume access and audit logs. Optimized for time-range filtering, top-N aggregations, and geo-analytics. Employs `MergeTree` and `SummingMergeTree` engines with monthly partitions and automated TTL policies (90 days for events, 365 days for audit trails).
- **SQLite3 Relational Store:** Houses low-volume, high-criticality control-plane tables across 5 distinct database files operating in WAL mode.
- **Litestream WAL Streaming:** Replicates SQLite changes continuously, writing point-in-time state to `/backups/` to enable rapid recovery or standby node synchronization.

---

## 4. End-to-End System Flows

### 4.1 User Authentication Flow
```mermaid
sequenceDiagram
    autonumber
    actor Admin as SOC User
    participant UI as React Frontend
    participant Auth as Backend /auth/login
    participant UserDB as SQLite users.db
    participant Redis as Redis Cache
    participant Session as Session Service

    Admin->>UI: Enter Username & Password
    UI->>Auth: POST /auth/login
    Auth->>Auth: Check Admin-Login IP Allowlist
    Auth->>Redis: Rate Limit Check (IP & Username)
    alt Rate Limit Breached
        Auth-->>UI: HTTP 429 (Too Many Attempts)
    else Allowed
        Auth->>UserDB: Query user record by username
        Auth->>Auth: Verify bcrypt hash
        alt Invalid Credentials
            Auth-->>UI: HTTP 401 Unauthorized
        else Valid Credentials
            alt MFA Enabled (mfa_enabled = 1)
                Auth-->>UI: Set waf_mfa_pending_v1 cookie (5m), Return mfa_required=true
                Admin->>UI: Enter 6-digit TOTP code
                UI->>Auth: POST /auth/login/mfa (code)
                Auth->>Auth: Validate TOTP via pyotp
            end
            Auth->>Session: create_session(username, ip, ua)
            Session->>Redis: Store session:<user>:<sid> (TTL: 3600s)
            Auth->>Auth: Mint JWT (sub, role, tv, sid, exp)
            Auth-->>UI: Set-Cookie: waf_session_v3 (HttpOnly, SameSite=Lax)<br/>Set-Cookie: XSRF-TOKEN-V3 (Plaintext)
            UI->>UI: Transition to Dashboard View
        end
    end
```

### 4.2 SIEM SSO Mint-and-Redirect Token Exchange Flow
```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant SIEM as Corporate SIEM / IdP
    participant UI as React Frontend (/auth/sso)
    participant SSO as Backend /auth/sso/exchange
    participant JWKS as SIEM JWKS Endpoint
    participant UserDB as SQLite users.db

    Analyst->>SIEM: Click "Open CyberSentinel WAF"
    SIEM->>SIEM: Mint Signed JWT (sub, email, name, role)
    SIEM-->>Analyst: Redirect to https://waf.company.com/auth/sso#token=<JWT>
    Analyst->>UI: Browser loads /auth/sso (reads token from fragment)
    UI->>SSO: POST /auth/sso/exchange { token }
    SSO->>SSO: Check IP Rate Limit
    alt RS256 Signature Verification
        SSO->>JWKS: Fetch SIEM Public Keys (cached)
        SSO->>SSO: Verify RS256 Signature & Claims
    else HS256 Signature Verification
        SSO->>SSO: Verify with shared WAF_SSO_SECRET
    end
    SSO->>UserDB: Lookup user by sso_subject_id (or email)
    alt User Does Not Exist
        SSO->>UserDB: JIT Provision User (role mapped from SIEM)
    else User Exists
        SSO->>UserDB: Update role & profile if changed
    end
    SSO-->>UI: Set-Cookie: waf_session_v3 & XSRF-TOKEN-V3
    UI->>UI: Navigate to /dashboard (Authenticated)
```

### 4.3 Inbound HTTP Request & L7 Attack Detection Flow
```mermaid
sequenceDiagram
    autonumber
    actor Client as Web Client / Attacker
    participant Gateway as OpenResty Gateway
    participant LuaAccess as ml_check.lua (Access Phase)
    participant Redis as Redis State Cache
    participant ModSec as ModSecurity Engine (CRS v4)
    participant LuaContent as ml_decide.lua (Content Phase)
    participant MLServer as waf-ml Microservice (:9000)
    participant Upstream as Target Upstream Application

    Client->>Gateway: Inbound HTTP/HTTPS Request
    Gateway->>LuaAccess: access_by_lua_file
    LuaAccess->>Redis: Check Whitelist / Blacklist / JA4 / GeoIP
    alt Blacklist Hit (IP, JA4, or Geo)
        LuaAccess-->>Client: HTTP 403 Forbidden (WAF-LUA-BLOCK)
    else Passed Access Checks
        LuaAccess->>ModSec: Pass to ModSecurity Engine
        ModSec->>ModSec: Evaluate Inbound Rules (911-949)
        alt Multipart Upload Present
            ModSec->>ModSec: Execute malware-scan.sh (@inspectFile -> ClamAV)
        end
        ModSec->>Gateway: Populate $modsecurity_anomaly_score
        Gateway->>LuaContent: content_by_lua_file
        LuaContent->>MLServer: POST /predict (X-Internal-Key, Telemetry, Score)
        MLServer->>Redis: Get RPM & Reputation
        MLServer->>MLServer: Calculate 30-dim vector -> XGBoost & IsolationForest
        MLServer->>MLServer: Calculate Threat Score
        alt Decision == "block" (Score >= 0.85 or CRS >= 4.0)
            MLServer-->>LuaContent: HTTP 401 (decision: "block")
            LuaContent-->>Client: HTTP 403 (Custom Block HTML Page)
        else Decision == "rate_limit"
            MLServer-->>LuaContent: HTTP 429 (decision: "rate_limit")
            LuaContent-->>Client: HTTP 429 Too Many Requests
        else Decision == "allow"
            MLServer-->>LuaContent: HTTP 200 (decision: "allow")
            LuaContent->>Gateway: ngx.exec(@upstream)
            Gateway->>Upstream: Forward Clean Request
            Upstream-->>Gateway: Upstream Response
            Gateway-->>Client: HTTP Response
        end
    end
```

### 4.4 Asynchronous Log Ingestion & Real-Time Alerting Flow
```mermaid
sequenceDiagram
    autonumber
    participant Gateway as OpenResty
    participant FileSystem as Disk Log Files
    participant Ingestor as log_ingestor.py
    participant Queue as Async Event Queue
    participant ClickHouse as ClickHouse DB
    participant WS as WebSocket Manager
    participant AlertMgr as Alert Manager
    participant Channels as Notification Channels

    Gateway->>FileSystem: Write /var/log/modsecurity/audit/<date>/<id>.json
    Gateway->>FileSystem: Append to /var/log/nginx/error.log
    FileSystem->>Ingestor: Watchdog Inotify Event (File Created)
    Ingestor->>Ingestor: Parse ModSecurity JSON / Nginx Error Line
    Ingestor->>Queue: Enqueue LogEntry
    loop Flush Loop (Every 5s or 100 items)
        Queue->>Ingestor: Drain Batch
        Ingestor->>ClickHouse: Batch Insert into cybersentinel.waf_events
        Ingestor->>WS: Broadcast JSON { type: "log", data: entry }
        WS-->>UI: Real-Time Update on Live Logs & Threat Globe
        Ingestor->>AlertMgr: trigger_event("attack_detected", entry)
        AlertMgr->>AlertMgr: Evaluate Rule Conditions & Cooldowns
        alt Alert Triggered
            AlertMgr->>ClickHouse: Record in cybersentinel.alert_history
            AlertMgr->>WS: Broadcast JSON { type: "alert", data: alert }
            AlertMgr->>Channels: Dispatch to SMTP / Slack / Webhook / PagerDuty
            AlertMgr->>Channels: Stream to Syslog (Unthrottled RFC 5424)
        end
    end
```

### 4.5 Configuration Update & Safe Nginx Reload Flow
```mermaid
sequenceDiagram
    autonumber
    actor Admin as Administrator
    participant UI as React Settings UI
    participant Backend as FastAPI Backend
    participant NginxMgr as nginx_manager.py
    participant Proxy as waf-docker-socket-proxy
    participant Gateway as waf-openresty

    Admin->>UI: Save New Configuration (e.g. Add Whitelist IP)
    UI->>Backend: POST /settings/hardening (with X-CSRF-Token)
    Backend->>Backend: Enforce require_admin
    Backend->>NginxMgr: apply_hardening_settings()
    NginxMgr->>NginxMgr: Generate updated config / update Redis sets
    NginxMgr->>Proxy: POST /containers/waf-openresty/exec ("openresty -t")
    Proxy->>Gateway: Run openresty -t
    Gateway-->>Proxy: Return Syntax Test Results
    Proxy-->>NginxMgr: Exit Code (0 = Success, 1 = Failure)
    alt Syntax Error Detected
        NginxMgr->>NginxMgr: Revert configuration files
        NginxMgr-->>Backend: Raise ConfigurationError
        Backend-->>UI: HTTP 400 Bad Request (Syntax Error Details)
    else Configuration Valid
        NginxMgr->>Proxy: POST /containers/waf-openresty/exec ("openresty -s reload")
        Proxy->>Gateway: Send SIGHUP / reload
        Gateway-->>Proxy: Reload complete
        Backend->>Backend: Log change to ClickHouse audit_log
        Backend-->>UI: HTTP 200 OK (Applied Successfully)
    end
```

---

## 5. Active-Passive High Availability Architecture (Phase B Design)

The repository provides an active-passive failover design documented in [`configs/keepalived/keepalived.conf.example`](file:///opt/ModSecurity/WAF_GUI/configs/keepalived/keepalived.conf.example) and [`scripts/ha/README.md`](file:///opt/ModSecurity/WAF_GUI/scripts/ha/README.md):

```mermaid
graph TB
    subgraph "Virtual IP (VIP): 192.168.1.100"
        ClientTraffic[Client Traffic directed to VIP]
    end

    subgraph "Node 1: Active Master (Priority 150)"
        Node1Keepalived[Keepalived Daemon]
        Node1Probe[scripts/ha/waf-health-check.sh]
        Node1Stack[CyberSentinel Docker Compose Stack]
        Node1Litestream[Litestream WAL Producer]
    end

    subgraph "Node 2: Passive Standby (Priority 100)"
        Node2Keepalived[Keepalived Daemon]
        Node2Probe[scripts/ha/waf-health-check.sh]
        Node2Stack[CyberSentinel Docker Compose Stack]
        Node2Litestream[Litestream WAL Consumer]
    end

    ClientTraffic --> Node1Keepalived
    Node1Probe -->|Poll GET /health every 2s| Node1Stack
    Node2Probe -->|Poll GET /health every 2s| Node2Stack

    Node1Keepalived -.->|VRRP Advertisements 1s| Node2Keepalived
    Node1Litestream -->|Continuous WAL Sync via SFTP/Local| Node2Litestream

    Node1Probe -.->|Failure: Weight -20| Node1Keepalived
    Node2Keepalived -.->|Promote to Master upon missed VRRP| ClientTraffic
```

### High Availability Invariants:
1. **Health Verification:** The keepalived probe script [`scripts/ha/waf-health-check.sh`](file:///opt/ModSecurity/WAF_GUI/scripts/ha/waf-health-check.sh) validates `GET /health` (requiring ClickHouse, Redis, and Gateway to report healthy) rather than a simple TCP socket check.
2. **State Synchronization:** Litestream continuously replicates SQLite WAL changes between nodes, guaranteeing that user accounts, active sessions, API keys, and false-positive exceptions match identically upon failover.
