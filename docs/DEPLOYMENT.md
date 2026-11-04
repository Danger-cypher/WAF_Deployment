# CyberSentinel WAF — Production Deployment & Operations Guide

**Version:** 3.0.0  
**Scope:** Bare-metal, Virtualized (VMware/KVM), and Cloud Infrastructure (AWS, GCP, Azure)  
**Security Classification:** Enterprise Operations Manual  
**Status:** Verified from Codebase (`docker-compose.yml`, `setup.sh`, `scripts/configure-production.sh`)

---

## Table of Contents

1. [Hardware & System Prerequisites](#1-hardware--system-prerequisites)
2. [Network Topology & Port Allocations](#2-network-topology--port-allocations)
3. [Turnkey Installation Walkthrough](#3-turnkey-installation-walkthrough)
4. [Environment Configuration Reference (`.env`)](#4-environment-configuration-reference-env)
5. [SSL/TLS & mTLS Management](#5-ssltls--mtls-management)
6. [Container Orchestration & Resource Allocation](#6-container-orchestration--resource-allocation)
7. [Database Persistence & Encrypted Backups](#7-database-persistence--encrypted-backups)
8. [High Availability: Litestream & Keepalived VRRP](#8-high-availability-litestream--keepalived-vrrp)
9. [Post-Deployment Verification & Smoke Tests](#9-post-deployment-verification--smoke-tests)

---

## 1. Hardware & System Prerequisites

### Host Operating System
- **Certified Supported OS:** Ubuntu 22.04 LTS / 24.04 LTS, Debian 12 (Bookworm), Rocky Linux 9, or RHEL 9.
- **Kernel Requirements:** Linux Kernel ≥ 5.15 with overlayfs, netfilter/iptables, and cgroup v2 enabled.

### Minimum vs. Recommended Hardware Sizing

| Sizing Tier | Concurrency / Bandwidth | vCPU | System RAM | Storage Requirements |
| :--- | :--- | :--- | :--- | :--- |
| **Minimum (PoC / Staging)** | Up to 250 req/sec (< 50 Mbps) | 4 Cores | 8 GB | 60 GB SSD (ext4/xfs) |
| **Standard Production** | 250 – 2,500 req/sec (< 500 Mbps) | 8 Cores | 16 GB | 250 GB NVMe SSD |
| **Enterprise High-Throughput** | 2,500 – 10,000 req/sec (> 1 Gbps) | 16 Cores | 32 GB | 500 GB+ High-IOPS NVMe |

> [!IMPORTANT]
> **ClickHouse Disk I/O:** ClickHouse performs columnar compression and asynchronous block merging (`MergeTree` engine). Deploy `/opt/ModSecurity/WAF_GUI/clickhouse_data` on high-speed NVMe storage. Avoid slow network-attached NFS mounts for ClickHouse data directories.

### Required Software Packages
Before executing deployment, ensure Docker Engine and Docker Compose V2 are installed:
```bash
# Verify Docker Engine (>= 24.0.0 recommended)
docker --version

# Verify Docker Compose V2 (>= 2.20.0 recommended)
docker compose version
```

---

## 2. Network Topology & Port Allocations

All CyberSentinel containers communicate across an isolated internal Docker bridge network (`waf-network`, subnet `172.20.0.0/16`). Only hardened gateway ports are bound to the host interfaces.

```
                    Internet / Upstream Clients
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
      Port 80/tcp (HTTP)                   Port 443/tcp (HTTPS)
   (Redirect to HTTPS or                (Protected Web Applications
   ACME HTTP-01 Challenges)                and Reverse Proxy)
             │                                     │
             └──────────────────┬──────────────────┘
                                │
                                ▼
                   ┌─────────────────────────┐
                   │    waf-nginx (OpenResty)│
                   └────────────┬────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
            ▼                   ▼                   ▼
    Port 3443/tcp       Port 3020/tcp       Port 8123/tcp
   (CyberSentinel WAF   (Internal HTTP      (ClickHouse HTTP
    Admin Dashboard     Admin Loopback)     - Localhost Only)
       TLS UI)
```

### Ingress Port Mapping Table

| Port / Protocol | Container Service | Scope / Binding | Description |
| :--- | :--- | :--- | :--- |
| **`80/tcp`** | `waf-nginx` | `0.0.0.0:80` | ACME Let's Encrypt validation & automatic HTTP→HTTPS 301 redirection. |
| **`443/tcp`** | `waf-nginx` | `0.0.0.0:443` | Primary ingress for all protected web applications and APIs. |
| **`3443/tcp`** | `waf-nginx` | `0.0.0.0:3443` | Secure HTTPS portal for CyberSentinel Management Console & REST APIs. |
| **`3020/tcp`** | `waf-nginx` | `127.0.0.1:3020` or Host-bound | Plain HTTP admin vhost used for SIEM SSO internal redirects and testing. |
| **`8123/tcp`** | `waf-clickhouse` | `127.0.0.1:8123` | Direct ClickHouse SQL interface (restricted strictly to host localhost). |

---

## 3. Turnkey Installation Walkthrough

### Step 1: Clone Repository and Set Permissions
```bash
sudo git clone https://github.com/Danger-cypher/WAF_Deployment.git /opt/ModSecurity/WAF_GUI
cd /opt/ModSecurity/WAF_GUI
sudo chmod +x setup.sh scripts/*.sh scripts/ha/*.sh
```

### Step 2: Run the Automated Zero-Dependency Installer
The master setup script [`setup.sh`](file:///opt/ModSecurity/WAF_GUI/setup.sh) automates:
1. Docker daemon and compose runtime verification.
2. In-use port collision checks with dynamic alternative allocation.
3. Cryptographic secret generation and `.env` initialization.
4. MaxMind GeoIP2 Lite City database download and extraction.
5. Local self-signed SSL/TLS certificate seeding (`configs/nginx/ssl/`).
6. Core container building and healthcheck verification.

```bash
sudo ./setup.sh
```

### Step 3: Interactive Configuration Prompts
During installation, the installer will prompt for:
- **Admin Password:** Provide a strong root password (minimum 12 characters).
- **Admin Email:** Used for Let's Encrypt expiry warnings and system alerts.
- **Domain Name:** Hostname or FQDN for the WAF management dashboard.
- **MaxMind License Key (Optional):** If left blank, the installer automatically pulls the bundled GeoIP mirror dataset.

---

## 4. Environment Configuration Reference (`.env`)

Production secrets are stored in `/opt/ModSecurity/WAF_GUI/.env`. This file is generated with `chmod 600` permissions.

```dotenv
# =============================================================================
# CyberSentinel WAF — Production Environment Configuration
# =============================================================================

# Project Metadata
PROJECT_NAME="CyberSentinel WAF"
ENVIRONMENT="production"
DEBUG=False

# Host Network Bindings
WAF_HTTP_PORT=80
WAF_HTTPS_PORT=443
WAF_DASHBOARD_HTTPS_PORT=3443
WAF_DASHBOARD_HTTP_PORT=3020

# JWT & Authentication Security
JWT_SECRET_KEY=<generate_with_openssl_rand_hex_32>
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480

# Database Encryption at Rest
BACKUP_ENCRYPTION_KEY=gAAAAABlZ3...== # Fernet 32-byte Base64 key
CHANNEL_ENCRYPTION_KEY=gAAAAABlZ3...== # Alert notification credential key

# Internal Microservice Shared Secrets
INTERNAL_ALERT_TRIGGER_KEY=<generate_with_openssl_rand_hex_32>
ML_INTERNAL_API_KEY=<generate_with_openssl_rand_hex_32>

# ClickHouse Analytic Engine
CLICKHOUSE_HOST=waf-clickhouse
CLICKHOUSE_PORT=8123
CLICKHOUSE_DB=waf_logs
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=clickhouse_strong_prod_pass

# Redis Distributed Cache & State Store
REDIS_HOST=waf-redis
REDIS_PORT=6379
REDIS_PASSWORD=redis_strong_prod_pass

# Storage & Engine Paths
LOG_DIR=/opt/ModSecurity/WAF_GUI/logs
MODSEC_AUDIT_LOG_DIR=/var/log/modsec
SETTINGS_FILE_PATH=/opt/ModSecurity/WAF_GUI/backend/app/config/settings.json

# CORS Allowed Origins (Comma-separated)
BACKEND_CORS_ORIGINS=["https://waf.company.com:3443","http://localhost:3020"]
```

> [!WARNING]
> **Secret Regeneration:** If secrets ever need rotation, execute `scripts/generate-secrets.sh`. **Do not edit `.env` during live request handling**, as changing `JWT_SECRET_KEY` invalidates all logged-in sessions, and changing `BACKUP_ENCRYPTION_KEY` renders existing `.tar.gz.enc` backup files unreadable without the old key.

---

## 5. SSL/TLS & mTLS Management

### Option A: Automated Let's Encrypt Certificates
Use the production configuration utility [`scripts/configure-production.sh`](file:///opt/ModSecurity/WAF_GUI/scripts/configure-production.sh) to issue valid trusted certificates via Certbot:
```bash
sudo ./scripts/configure-production.sh
# Select: [1] Update SSL/TLS Certificates -> [2] Generate Let's Encrypt certificate
```
Certbot automates certificate generation into `configs/nginx/ssl/` and mounts renewal hooks inside `waf-certbot`.

### Option B: Commercial Enterprise Certificates (DigiCert, Sectigo, Custom PKI)
To deploy commercial certificates, copy PEM-formatted certificates to the standard path:
```bash
# Copy certificate chain and private key
sudo cp your_domain_bundle.crt configs/nginx/ssl/cybersentinel.crt
sudo cp your_domain.key configs/nginx/ssl/cybersentinel.key

# Ensure strict file permissions
sudo chmod 644 configs/nginx/ssl/cybersentinel.crt
sudo chmod 600 configs/nginx/ssl/cybersentinel.key

# Reload OpenResty to apply without dropping active connections
sudo docker exec waf-nginx openresty -s reload
```

### Option C: Mutual TLS (mTLS) for Protected Apps
For high-security APIs (banking, zero-trust partner endpoints):
1. Navigate to **Applications** in the CyberSentinel UI or call `POST /apps/{app_id}/mtls/ca-cert`.
2. Upload your internal Enterprise Root / Intermediate CA certificate bundle (`ca_bundle.pem`).
3. Set `mtls_mode` to `required` (enforces client certificates at TLS handshake) or `optional` (passes client cert fingerprints in `X-Client-Cert-SHA256` headers to upstream services).

---

## 6. Container Orchestration & Resource Allocation

The production deployment consists of 10 microservices configured in [`docker-compose.yml`](file:///opt/ModSecurity/WAF_GUI/docker-compose.yml):

```yaml
version: "3.8"

networks:
  waf-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

services:
  waf-nginx:
    image: cybersentinel-openresty:latest
    container_name: waf-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "3443:3443"
    networks:
      - waf-network
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 2048M
        reservations:
          cpus: "1.0"
          memory: 512M

  waf-backend:
    image: cybersentinel-backend:latest
    container_name: waf-backend
    restart: unless-stopped
    networks:
      - waf-network
    depends_on:
      - waf-clickhouse
      - waf-redis
      - waf-docker-socket-proxy
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 1024M

  waf-ml:
    image: cybersentinel-ml:latest
    container_name: waf-ml
    restart: unless-stopped
    networks:
      - waf-network
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 3072M
        reservations:
          cpus: "1.0"
          memory: 1024M

  waf-clickhouse:
    image: clickhouse/clickhouse-server:24.3-alpine
    container_name: waf-clickhouse
    restart: unless-stopped
    networks:
      - waf-network
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 4096M
        reservations:
          cpus: "2.0"
          memory: 2048M

  waf-redis:
    image: redis:7.2-alpine
    container_name: waf-redis
    restart: unless-stopped
    networks:
      - waf-network
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M

  waf-docker-socket-proxy:
    image: tecnativa/docker-socket-proxy:latest
    container_name: waf-docker-socket-proxy
    restart: unless-stopped
    networks:
      - waf-network
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CONTAINERS=1
      - EXEC=1
      - RESTART=1

  waf-litestream:
    image: litestream/litestream:0.3.13
    container_name: waf-litestream
    restart: unless-stopped
    networks:
      - waf-network
```

---

## 7. Database Persistence & Encrypted Backups

### Persistent Storage Bind Mounts
All system data is stored deterministically in host subdirectories:
- `backend/app/data/`: Active SQLite databases (`users.db`, `alerts.db`, `api_keys.db`, `ml_events.db`).
- `backend/app/config/`: System configuration and exclusions (`false_positives.db`, `settings.json`).
- `clickhouse_data/`: Compressed columnar ClickHouse storage.
- `logs/modsec/`: ModSecurity audit JSON logs (`modsec_audit.log`).
- `configs/nginx/`: Nginx configurations (`nginx.conf`, `rules-exclusions.conf`, `custom-rules.conf`).

### Automated Backup Generation
CyberSentinel packages all configuration files, rule exclusions, and SQLite databases into a Fernet-encrypted archive.

**Trigger Backup via API:**
```bash
curl -X POST "https://localhost:3443/api/system/backups" \
  -H "X-API-Key: <your_admin_api_key>" \
  -k
```

**Restoring an Encrypted Backup Archive:**
```bash
curl -X POST "https://localhost:3443/api/system/backups/backup_20260923_120000/restore" \
  -H "X-API-Key: <your_admin_api_key>" \
  -k
```

---

## 8. High Availability: Litestream & Keepalived VRRP

CyberSentinel supports active-passive high availability across two independent host nodes with a shared Virtual IP (VIP).

```
                      Client Traffic
                            │
                            ▼
                     [ 192.168.1.100 ]
                     (Floating VRRP VIP)
                            │
             ┌──────────────┴──────────────┐
             │                             │
             ▼ (MASTER: Priority 101)      ▼ (BACKUP: Priority 100)
    ┌─────────────────┐           ┌─────────────────┐
    │  WAF Node 1     │           │  WAF Node 2     │
    │  Active Traffic │           │  Hot Standby    │
    └────────┬────────┘           └────────▲────────┘
             │                             │
             └────── Litestream WAL ───────┘
                 (Continuous Replication)
```

### Phase A: Local Litestream Replication (Single Node)
Verified active in codebase via [`configs/litestream/litestream.yml`](file:///opt/ModSecurity/WAF_GUI/configs/litestream/litestream.yml):
Litestream continuously monitors the SQLite WAL journal frames for all 5 databases and writes continuous point-in-time recovery checkpoints to `/backups/litestream/`.

### Phase B: Dual-Node Active-Passive Keepalived Setup
1. **Host Prerequisites:** Install Keepalived on both hosts:
   ```bash
   sudo apt-get install -y keepalived
   ```
2. **Deploy Configuration Template:** Copy [`configs/keepalived/keepalived.conf.example`](file:///opt/ModSecurity/WAF_GUI/configs/keepalived/keepalived.conf.example) to `/etc/keepalived/keepalived.conf`.
3. **Configure Node 1 (MASTER):**
   ```text
   vrrp_script check_waf {
       script "/opt/ModSecurity/WAF_GUI/scripts/ha/waf-health-check.sh"
       interval 2
       weight 2
   }

   vrrp_instance VI_WAF {
       state MASTER
       interface eth0
       virtual_router_id 51
       priority 101
       advert_int 1
       authentication {
           auth_type PASS
           auth_pass StrongClusterSecret123
       }
       virtual_ipaddress {
           192.168.1.100/24
       }
       track_script {
           check_waf
       }
   }
   ```
4. **Configure Node 2 (BACKUP):**
   Set `state BACKUP` and `priority 100`.
5. **Start Keepalived:**
   ```bash
   sudo systemctl enable --now keepalived
   ```

---

## 9. Post-Deployment Verification & Smoke Tests

Execute these verification checks to confirm the deployment is fully operational:

```bash
# 1. Verify container status (All 10 services should show Up/Healthy)
docker compose ps

# 2. Check unified platform health endpoint
curl -s http://localhost:8000/health | jq .

# Expected output:
# {
#   "status": "healthy",
#   "services": {
#     "sqlite": "connected",
#     "redis": "connected",
#     "clickhouse": "connected",
#     "openresty": "running"
#   }
# }

# 3. Test ModSecurity SQLi Block Protection (Should return HTTP 403)
curl -i "http://localhost:80/?test=%27+OR+1%3D1--"

# 4. Verify ClickHouse Ingestion
docker exec -it waf-clickhouse clickhouse-client -q \
  "SELECT count(), max(timestamp) FROM waf_logs.waf_events"

# 5. Check Background Task Watchdogs
curl -s "http://localhost:8000/health/background-tasks" \
  -H "X-API-Key: <your_admin_api_key>" | jq .
```
