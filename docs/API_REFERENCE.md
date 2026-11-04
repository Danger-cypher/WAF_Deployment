# CyberSentinel WAF — REST & WebSocket API Reference Specification

**Version:** 3.0.0  
**Base URL:** `http://<waf-host>:8000` (or `https://<waf-host>:3443/api` via OpenResty TLS Reverse Proxy)  
**Security Classification:** Enterprise Confidential / Operations Reference  
**Status:** Verified from Codebase (`backend/app/main.py` and `backend/app/routes/`)

---

## Table of Contents

1. [Authentication & Authorization Model](#1-authentication--authorization-model)
   - [Authentication Modes](#authentication-modes)
   - [CSRF Protection Architecture](#csrf-protection-architecture)
   - [RBAC Matrix](#rbac-matrix)
   - [Common Error Codes & Formats](#common-error-codes--formats)
2. [Authentication & SSO Endpoints (`/auth`)](#2-authentication--sso-endpoints-auth)
3. [User & Session Management (`/users`)](#3-user--session-management-users)
4. [Machine Credentials & API Keys (`/api-keys`)](#4-machine-credentials--api-keys-api-keys)
5. [WAF Rules & Canary Management (`/rules`, `/paranoia-level`)](#5-waf-rules--canary-management-rules-paranoia-level)
6. [CVE Virtual Patching Library (`/virtual-patches`)](#6-cve-virtual-patching-library-virtual-patches)
7. [Targeted Exclusions & Exceptions (`/exclusions`)](#7-targeted-exclusions--exceptions-exclusions)
8. [False Positive Management (`/false-positives`)](#8-false-positive-management-false-positives)
9. [Auto-Learning Engine (`/auto-learning`)](#9-auto-learning-engine-auto-learning)
10. [Protected Applications & Routing (`/apps`)](#10-protected-applications--routing-apps)
11. [Global Settings & Security Modules (`/settings`)](#11-global-settings--security-modules-settings)
12. [Alerts, Integrations & Webhooks (`/alerts`)](#12-alerts-integrations--webhooks-alerts)
13. [API Discovery & OpenAPI Drift Protection (`/api-protection`)](#13-api-discovery--openapi-drift-protection-api-protection)
14. [DDoS & Bot Mitigation Analytics (`/ddos`)](#14-ddos--bot-mitigation-analytics-ddos)
15. [Machine Learning Engine (`/ml`)](#15-machine-learning-engine-ml)
16. [Security Events & Audit Logs (`/logs`, `/debug/logs`)](#16-security-events--audit-logs-logs-debuglogs)
17. [Aggregated Statistics & Metrics (`/stats`, `/top-ips`, etc.)](#17-aggregated-statistics--metrics-stats-top-ips-etc)
18. [SIEM Pull-Export Engine (`/siem/export`)](#18-siem-pull-export-engine-siemexport)
19. [System Administration & Backups (`/system`)](#19-system-administration--backups-system)
20. [Platform Health & Watchdogs (`/health`)](#20-platform-health--watchdogs-health)
21. [Administrative Audit Trails (`/security`)](#21-administrative-audit-trails-security)
22. [Real-Time WebSocket Stream (`/logs/stream`)](#22-real-time-websocket-stream-logsstream)

---

## 1. Authentication & Authorization Model

CyberSentinel WAF provides defense-in-depth protection across all management interfaces.

### Authentication Modes

1. **Interactive Session (Browser / Cookie-based):**
   - Cookie: `waf_session_v3` (HTTPOnly, SameSite=`lax`, Secure when HTTPS).
   - Contains a cryptographically signed HMAC-SHA256 JWT containing `sub` (username), `role`, `tv` (token session version), and `sid` (Redis session UUID).
2. **Machine-to-Machine API Keys:**
   - Header: `X-API-Key: waf_<base62-secret>`
   - Authenticated via [`app.services.auth.get_current_user`](file:///opt/ModSecurity/WAF_GUI/backend/app/services/auth.py). Key hashes are looked up in SQLite `api_keys.db`.
3. **Internal Microservice Key:**
   - Header: `X-Internal-Key: <INTERNAL_ALERT_TRIGGER_KEY>`
   - Used for trusted container-to-container calls (`waf-ml` to `waf-backend` on `/alerts/trigger`, and `waf-backend` to `waf-ml:9000`).

### CSRF Protection Architecture

State-modifying HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`) require double-submit cookie verification managed by [`app.utils.csrf.verify_csrf_token`](file:///opt/ModSecurity/WAF_GUI/backend/app/utils/csrf.py):
- Client receives readable cookie `XSRF-TOKEN-V3` at login.
- Client must echo the value in request header `X-CSRF-Token: <token>` or `X-XSRF-Token: <token>`.
- **Exemptions:** Unauthenticated login (`/auth/login`, `/auth/login/mfa`, `/auth/sso/exchange`), internal trigger routes (`/alerts/trigger`), and machine calls carrying a valid `X-API-Key`.

### RBAC Matrix

The system enforces three distinct administrative roles via FastAPI dependencies:

| Role | Hierarchy / Capabilities | Typical Scope |
| :--- | :--- | :--- |
| **`admin`** | Full superuser access. Modifies rules, apps, SSL, backups, users, keys, and global settings. | Security Operations Lead, System Admin |
| **`analyst`** | Read-only across logs, stats, and rule definitions. Can flag false positives, label ML events, and export SIEM/CSV data. | SOC Level 1 / Level 2 Analysts |
| **`app_admin`** | Scoped administrator. Full control over assigned apps (configured in `app_user_access` SQLite table); read-only elsewhere. | DevOps / Application Owners |

---

## 2. Authentication & SSO Endpoints (`/auth`)

Mounted from [`backend/app/routes/auth.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/auth.py) and [`backend/app/routes/sso.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/sso.py).

### `POST /auth/login`
Authenticates user credentials using form-data. Checks IP allowlist, sliding-window rate limit, verifies bcrypt hash, and issues session cookies.

- **Auth Required:** None (Public, subject to IP allowlist & rate limits).
- **Content-Type:** `application/x-www-form-urlencoded`
- **Request Body:**
  ```text
  username=<string>&password=<string>
  ```
- **Responses:**
  - `200 OK` (Standard Login Successful):
    ```json
    {
      "message": "Login successful",
      "role": "admin",
      "mfa_required": false
    }
    ```
    *Sets Cookies:* `waf_session_v3` (HTTPOnly), `XSRF-TOKEN-V3`.
  - `200 OK` (MFA Step Required):
    ```json
    {
      "message": "MFA code required",
      "role": null,
      "mfa_required": true
    }
    ```
    *Sets Cookie:* `waf_mfa_pending_v1` (5-minute TTL).
  - `401 Unauthorized`: `{"detail": "Incorrect username or password"}`
  - `403 Forbidden`: `{"detail": "Access to the dashboard is not permitted from this network."}`
  - `429 Too Many Requests`: `{"detail": "Too many login attempts. Locked for 900s."}`

### `POST /auth/login/mfa`
Submits a 6-digit TOTP code to complete authentication when MFA is enabled.

- **Auth Required:** `waf_mfa_pending_v1` cookie.
- **Request Body:**
  ```json
  {
    "code": "123456"
  }
  ```
- **Responses:**
  - `200 OK`: `{"message": "Login successful", "role": "admin", "mfa_required": false}`
  - `401 Unauthorized`: `{"detail": "Invalid MFA code"}`

### `POST /auth/logout`
Revokes the current session record in Redis and deletes authentication cookies.

- **Auth Required:** Session Cookie + `X-CSRF-Token`
- **Responses:**
  - `200 OK`: `{"message": "Logged out successfully"}`

### `GET /auth/me`
Retrieves authenticated user profile claims from the current token.

- **Auth Required:** Any authenticated role (`admin`, `analyst`, `app_admin`).
- **Responses:**
  - `200 OK`:
    ```json
    {
      "username": "admin",
      "role": "admin",
      "session_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
    }
    ```

### `POST /auth/sso/exchange`
Exchanges an external SIEM/IdP signed JWT for an authenticated CyberSentinel session.

- **Auth Required:** None (Rate-limited, cryptographic signature validated).
- **Request Body:**
  ```json
  {
    "token": "<valid_jwt_idp_sso_token>"
  }
  ```
- **Responses:**
  - `200 OK`: `{"message": "SSO login successful", "role": "analyst"}`
  - `401 Unauthorized`: `{"detail": "Invalid or expired SSO token"}`

---

## 3. User & Session Management (`/users`)

Mounted from [`backend/app/routes/users.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/users.py).

### `GET /users`
Lists all local dashboard user accounts.

- **Auth Required:** `admin`
- **Responses:**
  - `200 OK`:
    ```json
    [
      {
        "id": 1,
        "username": "admin",
        "display_name": "System Administrator",
        "email": "admin@cybersentinel.local",
        "role": "admin",
        "enabled": true,
        "mfa_enabled": true,
        "created_at": "2026-01-01 00:00:00",
        "last_login": "2026-09-23 10:14:22",
        "app_ids": []
      }
    ]
    ```

### `POST /users`
Creates a new local user account.

- **Auth Required:** `admin`
- **Request Body:**
  ```json
  {
    "username": "sec_analyst",
    "password": "SecurePassword123!",
    "role": "analyst",
    "display_name": "Security Analyst",
    "email": "analyst@example.com",
    "app_ids": []
  }
  ```
- **Responses:**
  - `201 Created`: Returns created `UserOut` model.
  - `409 Conflict`: `{"detail": "Username already exists."}`

### `PATCH /users/{user_id}`
Updates user details, roles, enabled status, or scoped application access.

- **Auth Required:** `admin` (Guarded: cannot disable or demote the last remaining active admin).
- **Request Body:**
  ```json
  {
    "role": "app_admin",
    "enabled": true,
    "display_name": "App Lead",
    "email": "lead@app.local",
    "app_ids": ["app-core-api"]
  }
  ```
- **Responses:**
  - `200 OK`: Returns updated `UserOut` model.
  - `400 Bad Request`: `{"detail": "Cannot remove the last remaining administrator account."}`

### `POST /users/{user_id}/reset-password`
Administrative override to reset a user's password.

- **Auth Required:** `admin`
- **Request Body:**
  ```json
  {
    "new_password": "NewSecurePassword456!"
  }
  ```
- **Responses:**
  - `200 OK`: `{"message": "Password reset successfully."}`

### `DELETE /users/{user_id}`
Deletes a user account. Cannot delete self or last remaining admin.

- **Auth Required:** `admin`
- **Responses:**
  - `200 OK`: `{"message": "User deleted successfully."}`

### `GET /users/me/sessions`
Lists all active browser/device sessions for the calling user.

- **Auth Required:** Any authenticated role.
- **Responses:**
  - `200 OK`:
    ```json
    [
      {
        "session_id": "01b8e4e9-0268-45e3-92f7-e435e2373c68",
        "ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0 ...",
        "created_at": "2026-09-23T08:00:00Z",
        "last_seen_at": "2026-09-23T12:00:00Z",
        "is_current": true
      }
    ]
    ```

### `DELETE /users/me/sessions/{session_id}`
Revokes a specific active session.

- **Auth Required:** Any authenticated role.
- **Responses:**
  - `200 OK`: `{"message": "Session revoked."}`

### `POST /users/me/mfa/setup`
Initializes TOTP MFA secret and returns provisioning URI and Base64 QR code.

- **Auth Required:** Any authenticated role.
- **Responses:**
  - `200 OK`:
    ```json
    {
      "secret": "JBSWY3DPEHPK3PXP",
      "otpauth_uri": "otpauth://totp/CyberSentinel%20WAF:admin?secret=JBSWY3DPEHPK3PXP&issuer=CyberSentinel%20WAF",
      "qr_code_png_base64": "iVBORw0KGgoAAAANSUhEUgAA..."
    }
    ```

### `POST /users/me/mfa/confirm`
Confirms and activates TOTP MFA using first valid 6-digit code.

- **Auth Required:** Any authenticated role.
- **Request Body:** `{"code": "123456"}`
- **Responses:**
  - `200 OK`: `{"enabled": true}`

### `POST /users/me/mfa/disable`
Disables TOTP MFA. Requires both account password and current TOTP token.

- **Auth Required:** Any authenticated role.
- **Request Body:**
  ```json
  {
    "current_password": "MyPassword123!",
    "code": "123456"
  }
  ```
- **Responses:**
  - `200 OK`: `{"enabled": false}`

---

## 4. Machine Credentials & API Keys (`/api-keys`)

Mounted from [`backend/app/routes/api_keys.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/api_keys.py).

### `GET /api-keys`
Lists metadata for all provisioned API keys. Never exposes raw secret hashes.

- **Auth Required:** `admin`
- **Responses:**
  - `200 OK`:
    ```json
    [
      {
        "id": 1,
        "name": "SIEM Log Shipper",
        "key_prefix": "waf_live_a1b2",
        "role": "analyst",
        "enabled": true,
        "created_by": "admin",
        "created_at": "2026-09-01T10:00:00Z",
        "expires_at": null,
        "last_used_at": "2026-09-23T11:45:00Z",
        "last_used_ip": "172.20.0.1"
      }
    ]
    ```

### `POST /api-keys`
Mints a new high-entropy API key. **The raw secret is displayed once only.**

- **Auth Required:** `admin`
- **Request Body:**
  ```json
  {
    "name": "Automated Backup Daemon",
    "role": "admin",
    "expires_in_days": 90
  }
  ```
- **Responses:**
  - `201 Created`:
    ```json
    {
      "id": 2,
      "name": "Automated Backup Daemon",
      "key_prefix": "waf_live_xxxx",
      "role": "admin",
      "enabled": true,
      "api_key": "waf_live_sample_dummy_api_key_for_testing_1234567890"
    }
    ```

### `POST /api-keys/{key_id}/revoke`
Immediately invalidates an active API key.

- **Auth Required:** `admin`
- **Responses:**
  - `200 OK`: Returns updated `ApiKeyOut` with `enabled=false`.

---

## 5. WAF Rules & Canary Management (`/rules`, `/paranoia-level`)

Mounted from [`backend/app/routes/rules.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/rules.py).

### `GET /rules`
Paginated search and retrieval across the OWASP Core Rule Set (CRS 3.3.4) database.

- **Auth Required:** Any authenticated role.
- **Query Parameters:**
  - `page` (int, default: 1)
  - `size` (int, default: 15, max: 100)
  - `category` (string, optional: `sqli`, `xss`, `lfi`, `rce`, `protocol`, etc.)
  - `severity` (string, optional: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  - `enabled` (boolean, optional)
  - `search` (string, optional: rule ID or description substring)
- **Responses:**
  - `200 OK`:
    ```json
    {
      "data": [
        {
          "id": "942100",
          "name": "SQL Injection Attack Detected via libinjection",
          "category": "sqli",
          "severity": "CRITICAL",
          "paranoia_level": 1,
          "enabled": true,
          "canary": false,
          "description": "Detects SQL injection signatures..."
        }
      ],
      "total": 348,
      "page": 1,
      "size": 15
    }
    ```

### `GET /rules/{id}`
Returns granular rule definition including raw SecRule directives and regex patterns.

- **Auth Required:** Any authenticated role.
- **Responses:**
  - `200 OK`: Returns complete `RuleEntry` object.
  - `404 Not Found`: If rule ID does not exist in CRS database.

### `POST /rules/enable` & `POST /rules/disable`
Toggles CRS rule enforcement. Disabling requires an audit trail justification reason.

- **Auth Required:** `admin`
- **Request Body (`/rules/disable`):**
  ```json
  {
    "id": "942100",
    "reason": "Temporary bypass during legacy billing migration ticket SEC-9021"
  }
  ```
- **Responses:**
  - `200 OK`: `{"message": "Rule 942100 disabled successfully."}`
  - `400 Bad Request`: If justification is missing or shorter than 3 characters.

### `POST /rules/canary`
Flags or unflags a rule for shadow evaluation without altering blocking behavior.

- **Auth Required:** `admin`
- **Request Body:**
  ```json
  {
    "id": "942100",
    "canary": true
  }
  ```
- **Responses:**
  - `200 OK`: `{"message": "Rule 942100 marked as canary."}`

### `GET /rules/{id}/canary-report`
Analyzes historical ClickHouse telemetry to determine whether the rule was a sole blocker vs. co-matched by other CRS rules.

- **Auth Required:** Any authenticated role.
- **Query Parameters:** `hours` (int, default: 168, range: 1–8760).
- **Responses:**
  - `200 OK`:
    ```json
    {
      "rule_id": "942100",
      "hours": 168,
      "total_matches": 142,
      "sole_blocker_count": 18,
      "co_matched_count": 124,
      "sole_blocker_percent": 12.68
    }
    ```

### `GET /rules/custom` & `POST /rules/custom`
Reads and writes raw virtual patching directives stored in `/etc/nginx/modsec/custom-rules.conf`. The POST endpoint executes atomic pre-save syntax validation (`openresty -t`) with automated rollback if compilation fails.

- **Auth Required:** Read (`require_any_role`), Write (`admin`).
- **Request Body (POST):**
  ```json
  {
    "rules_content": "SecRule REQUEST_URI \"@beginsWith /admin/\" \"id:10000002,phase:1,deny,status:403\""
  }
  ```
- **Responses:**
  - `200 OK`: `{"message": "Custom rules saved and applied successfully."}`
  - `400 Bad Request`: Validation failure message and Nginx stderr output.

### `POST /paranoia-level`
Updates the global CRS paranoia level (1 to 4).

- **Auth Required:** `admin`
- **Request Body:** `{"level": 2}`
- **Responses:**
  - `200 OK`: `{"message": "CRS Paranoia Level set to 2."}`

---

## 6. CVE Virtual Patching Library (`/virtual-patches`)

Mounted from [`backend/app/routes/virtual_patches.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/virtual_patches.py).

### `GET /virtual-patches`
Returns the curated CVE template catalog (Log4j, Spring4Shell, Atlassian Confluence, Citrix Bleed, etc.) annotated with current deployment state.

- **Auth Required:** Any authenticated role.
- **Responses:**
  - `200 OK`: List of CVE metadata objects with `deployed` (bool), `mode` (`detect`|`block`), and rule IDs.

### `POST /virtual-patches/{cve_id}/deploy`
Compiles and activates virtual patch directives for a CVE.

- **Auth Required:** `admin`
- **Request Body:**
  ```json
  {
    "mode": "block"
  }
  ```
- **Responses:**
  - `200 OK`: `{"message": "CVE-2021-44228 deployed in block mode."}`

### `POST /virtual-patches/{cve_id}/undeploy`
Safely purges virtual patch directives and triggers zero-downtime Nginx reload.

- **Auth Required:** `admin`
- **Responses:**
  - `200 OK`: `{"message": "CVE-2021-44228 removed."}`

---

## 7. Targeted Exclusions & Exceptions (`/exclusions`)

Mounted from [`backend/app/routes/exclusions.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/exclusions.py).

### `POST /exclusions/preview`
Generates the exact `SecRuleUpdateTargetById` or `SecRuleRemoveById` syntax without applying it.

- **Auth Required:** Any authenticated role.
- **Request Body:** Base64-encoded JSON payload (`EncodedPayloadModel`).
  ```json
  {
    "payload": "<base64_encoded_ExclusionPreviewRequest>"
  }
  ```
- **Responses:**
  - `200 OK`: `{"modsec_rule": "SecRuleUpdateTargetById 942100 \"!ARGS:comment\""}`

### `POST /exclusions`
Creates an exception, saves it to SQLite `false_positives.db`, regenerates `rules-exclusions.conf`, and reloads Nginx.

- **Auth Required:** `admin`
- **Request Body:** Base64-encoded JSON (`ExclusionCreateRequest`):
  ```json
  {
    "rule_id": "942100",
    "exclusion_type": "uri_parameter",
    "uri": "/api/v1/comments",
    "parameter_name": "comment",
    "http_method": "POST",
    "client_ip": null,
    "notes": "Rich text markdown payload triggers false SQLi alert"
  }
  ```
- **Responses:**
  - `201 Created`: Returns created `ExclusionResponse`.
  - `400 Bad Request`: Rejects broad exclusions (e.g. URI=`/`).

### `GET /exclusions`
Lists all active and disabled rule exclusions.

- **Auth Required:** Any authenticated role.
- **Query Parameters:** `status` (`Active`|`Disabled`), `search`.

### `DELETE /exclusions/{id}`
Deletes an exclusion and restores native CRS enforcement.

- **Auth Required:** `admin`
- **Responses:** `204 No Content`

---

## 8. False Positive Management (`/false-positives`)

Mounted from [`backend/app/routes/false_positives.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/false_positives.py).

### `POST /false-positives`
Flags a blocked security log entry as an investigated false positive.

- **Auth Required:** Any authenticated role.
- **Request Body:**
  ```json
  {
    "log_id": "1727078400.123456-abc123",
    "analyst_note": "Legitimate API call from automated payment processor"
  }
  ```
- **Responses:**
  - `201 Created`: Returns `FalsePositiveResponse` with automated tuning suggestions.

### `GET /false-positives`
Queries flagged false positives with status filters (`Pending`, `Reviewed`, `Resolved`).

- **Auth Required:** Any authenticated role.

### `POST /false-positives/{id}/status`
Updates investigation status. Resolving requires `admin`.

- **Auth Required:** Any role for `Reviewed`; `admin` only for `Resolved`.

---

## 9. Auto-Learning Engine (`/auto-learning`)

Mounted from [`backend/app/routes/auto_learning.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/auto_learning.py).

### `GET /auto-learning/suggestions`
Retrieves algorithmically suggested tuning exclusions.

- **Auth Required:** Any authenticated role.
- **Responses:**
  - `200 OK`: Returns suggestions with `confidence_score` (0–100), `occurrence_count`, and recommended ModSecurity exclusion directive.

### `POST /auto-learning/run`
Forces an immediate heuristic evaluation across recent ClickHouse telemetry.

- **Auth Required:** `admin`
- **Responses:** `200 OK` with evaluation summary.

### `POST /auto-learning/suggestions/{id}/approve`
Transforms a pending recommendation into a live WAF exclusion rule.

- **Auth Required:** `admin`

### `POST /auto-learning/suggestions/{id}/reject`
Dismisses a recommendation and flags the pattern to prevent future suggestions.

- **Auth Required:** `admin`

---

## 10. Protected Applications & Routing (`/apps`)

Mounted from [`backend/app/routes/apps.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/apps.py).

### `GET /apps`
Lists all protected upstream web applications and reverse proxy configurations.

- **Auth Required:** Any authenticated role (Filtered by `app_admin` assigned scope).

### `POST /apps`
Provisions a new protected application, generating Nginx `server {}` and `upstream {}` blocks.

- **Auth Required:** `admin`
- **Request Body (`ProtectedAppCreate`):**
  ```json
  {
    "app_id": "app-payments",
    "name": "Payments Portal",
    "domain": "pay.company.com",
    "upstream_url": "http://10.0.5.20:8080",
    "waf_mode": "On",
    "ssl_enabled": true,
    "ssl_cert_path": "/etc/ssl/certs/pay.crt",
    "ssl_key_path": "/etc/ssl/private/pay.key",
    "schema_validation_enabled": false,
    "mtls_enabled": false
  }
  ```
- **Responses:**
  - `201 Created`: Returns provisioned application model.

### `PUT /apps/{app_id}`
Updates application settings, upstream destinations, or WAF operating modes (`On`, `DetectionOnly`, `Off`).

- **Auth Required:** `admin` or assigned `app_admin`.

### `DELETE /apps/{app_id}`
Decommissions an application and purges Nginx routing blocks.

- **Auth Required:** `admin`

### `POST /apps/{app_id}/provision-ssl`
Triggers automated Let's Encrypt ACME certificate issuance via Certbot HTTP-01 challenge.

- **Auth Required:** `admin` or assigned `app_admin`.

### `POST /apps/{app_id}/upload-cert`
Uploads custom SSL/TLS X.509 certificate and private key files.

- **Auth Required:** `admin` or assigned `app_admin`.
- **Form Data:** `cert_file` (PEM), `key_file` (PEM).

### `GET /apps/{app_id}/mtls` & `PUT /apps/{app_id}/mtls`
Manages mutual TLS client certificate verification (`required`, `optional`, `off`).

- **Auth Required:** `admin` or assigned `app_admin`.

---

## 11. Global Settings & Security Modules (`/settings`)

Mounted from [`backend/app/routes/settings.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/settings.py).

All configuration endpoints support `GET` (view configuration) and `POST` (update configuration). All updates require `admin` role and CSRF validation.

| Endpoint | Managed Subsystem | Description |
| :--- | :--- | :--- |
| `/settings/general` | Core Dashboard | Timezones, dashboard refresh intervals, host branding. |
| `/settings/waf` | ModSecurity Engine | Anomaly score limits (default: 5), body limit, inspect request bodies. |
| `/settings/logs` | ClickHouse Retention | Event retention windows (default: 90 days), sampling parameters. |
| `/settings/response` | Custom Response | HTTP 403 block page HTML and transaction ID placeholder injection. |
| `/settings/positive-security` | Schema Validation | OpenAPI 3.0 schema enforcement and drift detection parameters. |
| `/settings/auto-learning` | ML Tuning Scheduler | Sensitivity thresholds, minimum false positive occurrences. |
| `/settings/ddos-bot` | L7 Anti-DDoS | Rate limits, burst buckets, JavaScript proof-of-work challenges. |
| `/settings/hardening` | Cloaking & HSTS | Server header stripping, HSTS preload header toggles. |
| `/settings/admin-login-allowlist` | Zero Trust Admin Access | IP/CIDR subnets authorized to access the management portal. |
| `/settings/geo-block` | GeoIP2 Filtering | Country code blacklist and whitelist rules. |
| `/settings/threat-intel` | Threat Intelligence | Spamhaus DROP/EDROP synchronization toggles. |
| `/settings/threat-intel/sync-now` | Threat Sync Trigger | Immediate fetch and Redis load of external IP blocklists. |
| `/settings/good-bots` | Verified Search Bots | Googlebot/Bingbot reverse DNS and IP verification allowlists. |
| `/settings/good-bots/sync-now` | Bot Allowlist Trigger | Immediate fetch of published crawler IP blocks. |
| `/settings/auto-reputation` | Adaptive IP Banning | Auto-blocks repeat offenders exceeding threshold scores. |
| `/settings/auto-reputation/blocked` | Ban List Visibility | Lists dynamically blacklisted IPs and TTL expiries. |
| `/settings/auto-reputation/release/{ip}`| Manual IP Unban | Releases an automatically banned IP address. |
| `/settings/anti-defacement` | Web Integrity | Periodic SHA-256 hash validation for static upstream assets. |
| `/settings/threat-globe` | 3D Visualization | Telemetry aggregation coordinates and server location overrides. |
| `/settings/malware-scanning` | Antivirus Integration | ClamAV stream inspection parameters and max file upload size. |
| `/settings/malware-scanning/check-now`| ClamAV Health Check | Validates ClamAV daemon socket/TCP reachability. |
| `/settings/audit-log` | Admin Change Log | Detailed administrative change history log. |

---

## 12. Alerts, Integrations & Webhooks (`/alerts`)

Mounted from [`backend/app/routes/alerts.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/alerts.py).

### Notification Channels (`/alerts/channels`)
- `GET /alerts/channels`: Lists configured channels (Slack, Teams, Discord, Webhook, Email/SMTP, Syslog). Sensitive credentials are encrypted at rest with Fernet and redacted in responses.
- `POST /alerts/channels`: Creates a new alert channel (`admin` only).
- `GET /alerts/channels/{channel_id}`: Retrieves single channel configuration.
- `PUT /alerts/channels/{channel_id}`: Updates notification destination.
- `DELETE /alerts/channels/{channel_id}`: Removes channel.
- `POST /alerts/channels/{channel_id}/test`: Fires a test payload to verify destination reachability.
- `GET /alerts/channels/health`: Reports success/failure delivery rates and last failure timestamps.

### Alert Rules (`/alerts/rules`)
- `GET /alerts/rules`: Lists threshold-based and event-based alerting rules.
- `POST /alerts/rules`: Creates an alert rule (`admin` only). Supports triggers: `high_severity_attack`, `sqli_attack`, `ddos_burst`, `system_error`, `ml_anomaly_spike`, `anti_defacement`.
- `PUT /alerts/rules/{rule_id}`: Updates rule condition or target channel IDs.
- `DELETE /alerts/rules/{rule_id}`: Deletes rule.

### Alert History & Stats
- `GET /alerts/history`: Paginated log of past alerts dispatched to notification channels.
- `POST /alerts/history/{alert_id}/acknowledge`: Acknowledges an alert event.
- `GET /alerts/stats`: Aggregated dispatch volume, channel health status, and failure counts.

### `POST /alerts/trigger` (Internal Microservice Route)
Ingests security events from external sidecars (such as `waf-ml`).
- **Auth Required:** `X-Internal-Key` matching `INTERNAL_ALERT_TRIGGER_KEY`.
- **Request Body:**
  ```json
  {
    "event_type": "ml_anomaly_spike",
    "event_data": {
      "ip": "203.0.113.5",
      "threat_score": 0.985,
      "uri": "/api/v1/checkout"
    },
    "message": "Critical ML threat score spike detected from 203.0.113.5"
  }
  ```

---

## 13. API Discovery & OpenAPI Drift Protection (`/api-protection`)

Mounted from [`backend/app/routes/api_protection.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/api_protection.py).

### `GET /api-protection/endpoints`
Returns the inventory of discovered REST endpoints mined from traffic logs.

- **Auth Required:** Any authenticated role.
- **Query Parameters:** `page`, `page_size`, `search`, `method`, `auth_status`.

### `GET /api-protection/analytics`
Summarizes API ecosystem metrics: total endpoints, authenticated vs shadow APIs, sensitive data exposures (PII), and error rates.

### `POST /api-protection/spec`
Uploads an official OpenAPI 3.0 / Swagger JSON/YAML specification to serve as the positive security baseline.

- **Auth Required:** `admin`

### `GET /api-protection/drift`
Calculates delta between live observed API calls and the uploaded OpenAPI baseline (identifies undocumented shadow endpoints, unexpected HTTP verbs, and unlisted query parameters).

### `POST /api-protection/endpoints/block` & `POST /api-protection/endpoints/unblock`
Controls schema-level blocking for rogue or unverified endpoints.

---

## 14. DDoS & Bot Mitigation Analytics (`/ddos`)

Mounted from [`backend/app/routes/ddos.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/ddos.py).

### `GET /ddos/analytics`
Returns time-series telemetry on rate-limiting actions, burst throttling, and active IP tarpits.

- **Auth Required:** `admin`
- **Query Parameters:** `hours` (default: 24, max: 168).

### `GET /ddos/bot-traffic`
Provides traffic volume breakdown by client classification (Human, Good Bot, Bad Bot, Scraper, Search Crawler).

- **Auth Required:** `admin`

### `GET /ddos/bot-identities`
Ranks top automated User-Agent signatures detected across the gateway.

- **Auth Required:** `admin`

---

## 15. Machine Learning Engine (`/ml`)

Mounted from [`backend/app/routes/ml.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/ml.py).

### Telemetry & Stats (Direct SQLite `ml_events.db`)
- `GET /ml/stats`: Returns evaluation count, inference decision breakdown (`allow`, `block`, `rate_limit`, `log`), average anomaly score, and top anomalous endpoints.
- `GET /ml/logs`: Paginated search of ML inference records including raw feature vectors and Shapley contribution scores.
- `GET /ml/timeline`: Historical 15-minute bucketed threat score trends.
- `POST /ml/events/{event_id}/label`: Records human analyst ground-truth feedback (`true_positive` vs `false_positive`) to feed model drift metrics.

### Sidecar Orchestration (Proxied to `waf-ml:9000`)
- `GET /ml/model-info`: Retrieves running model version, XGBoost tree parameters, and memory footprint.
- `POST /ml/retrain`: Initiates asynchronous retraining job against fresh ClickHouse telemetry (`admin` only).
- `GET /ml/retrain/status`: Polls status of active retraining pipeline.
- `GET /ml/backups`: Lists restorable model checkpoints.
- `POST /ml/rollback`: Reverts active inference model to a previous backup snapshot (`admin` only).
- `GET /ml/feature-importance`: Ranks input feature weights (entropy, special characters, token distributions).
- `GET /ml/drift-history`: Tracks population stability index (PSI) and prediction distribution drift over time.

---

## 16. Security Events & Audit Logs (`/logs`, `/debug/logs`)

Mounted from [`backend/app/routes/logs.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/logs.py).

### `GET /logs`
Primary security event search querying ClickHouse table `waf_events`. Returns blocked and flagged requests.

- **Auth Required:** Any authenticated role.
- **Query Parameters:**
  - `page` (int, default: 1)
  - `size` (int, default: 50, max: 3000)
  - `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  - `min_severity` (Threshold filter)
  - `rule_id`, `ip`, `attack_type`, `status_code`
  - `search` (Full-text search)
  - `uri_type` (`web` or `api`)
  - `hours` (Timeframe window)
- **Responses:**
  - `200 OK`: `PaginatedLogs` model.

### `GET /logs/grouped`
Collapses duplicate security events into unique `(client_ip, rule_id)` pairs with match counts and first/last seen timestamps.

### `GET /logs/{log_id}`
Returns complete transaction detail for a single event ID, including raw ModSecurity audit payload.

### `GET /logs/{log_id}/explain`
Root-cause threat explanation engine. Synthesizes triggered CRS rules, variable matches, and corresponding ML inference scores into a plain-English security summary.

### `GET /debug/logs`
Diagnostics endpoint inspecting audit log directory permissions, file descriptors, and ClickHouse connectivity (`admin` only).

---

## 17. Aggregated Statistics & Metrics (`/stats`, `/top-ips`, etc.)

Mounted from [`backend/app/routes/stats.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/stats.py).

- `GET /stats`: Overall KPIs (total requests, total blocks, block percentage, top attack types, active threat level).
- `GET /stats/trend`: Comparative window analysis (current period vs previous period delta).
- `GET /top-ips`: Top attacking IP addresses with geolocation metadata.
- `GET /top-uris`: Most targeted endpoints and API routes.
- `GET /attack-types`: Distribution of threat categories (SQLi, XSS, RCE, LFI, Scanners, Protocol Violations).
- `GET /timeline`: Hourly attack volume breakdown for chart rendering.
- `GET /top-rules`: Top triggered ModSecurity rule IDs.
- `GET /severity-distribution`: Ratio of Critical, High, Medium, and Low severity matches.
- `GET /stats/export/csv`: Streaming CSV download of filtered security events.

---

## 18. SIEM Pull-Export Engine (`/siem/export`)

Mounted from [`backend/app/routes/siem.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/siem.py).

Bulk export endpoint designed for SOC collectors (Splunk, IBM QRadar, Microsoft Sentinel, Elastic, Logstash).

- **Auth Required:** Any authenticated role or `X-API-Key` machine header.
- **Query Parameters:**
  - `format` (string, default: `cef`, options: `cef` | `leef`)
  - `source` (string, default: `both`, options: `waf` | `ml` | `both`)
  - `since` (ISO 8601 timestamp string, e.g. `2026-09-23T10:00:00Z`)
  - `limit` (int, default: 500, range: 1–5000)
- **Response Format:**
  - Content-Type: `text/plain; charset=utf-8`
  - Response Headers:
    - `X-Next-Cursor`: Timestamp cursor to supply in the subsequent poll request.
    - `X-Events-Count`: Count of records returned in this batch.
- **Sample Output (CEF):**
  ```text
  CEF:0|CyberSentinel|WAF|3.0.0|942100|SQL Injection Attack Detected|9|src=198.51.100.22 dst=172.20.0.10 spt=54122 dpt=443 request=/api/login method=POST act=block
  ```

---

## 19. System Administration & Backups (`/system`)

Mounted from [`backend/app/routes/system.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/system.py) with prefix `/system`.

### Gateway Operations
- `GET /system/waf-ip`: Resolves the gateway's public outbound IP address.
- `POST /system/verify-dns`: Validates whether a protected application's domain resolves to this WAF instance.
- `POST /system/nginx-reload` / `POST /system/reload-nginx`: Signals OpenResty to hot-reload configuration files without dropping connections (`admin` only).
- `POST /system/restart`: Gracefully restarts backend services (`admin` only).
- `POST /system/purge-cache`: Clears internal Redis caches and temporary fast buffers (`admin` only).
- `POST /system/sync-signatures`: Checks for and updates CRS threat signatures (`admin` only).

### Encrypted Backups
- `POST /system/backups`: Generates an encrypted snapshot (`.tar.gz.enc`) containing all SQLite databases and configuration files. Encrypted using `BACKUP_ENCRYPTION_KEY`.
- `GET /system/backups`: Lists available backup files, sizes, and timestamps.
- `GET /system/backups/{backup_id}/download`: Streams encrypted backup archive.
- `POST /system/backups/{backup_id}/restore`: Restores system state and databases from archive (`admin` only).
- `DELETE /system/backups/{backup_id}`: Deletes backup archive (`admin` only).

---

## 20. Platform Health & Watchdogs (`/health`)

Mounted from [`backend/app/routes/health.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/health.py).

### `GET /health`
Liveness and readiness probe used by Docker healthchecks and monitoring consoles.

- **Auth Required:** None (Public).
- **Responses:**
  - `200 OK`:
    ```json
    {
      "status": "healthy",
      "version": "3.0.0",
      "services": {
        "sqlite": "connected",
        "redis": "connected",
        "clickhouse": "connected",
        "openresty": "running"
      },
      "total_events_ingested": 142058
    }
    ```
  - `503 Service Unavailable`: If critical database components are unreachable.

### `GET /health/background-tasks`
Monitors the execution health of all asynchronous background loops (Heartbeat watchdog).

- **Auth Required:** Any authenticated role.
- **Monitored Tasks:**
  - `audit_log_ingestor`
  - `log_retention_service`
  - `api_discovery_service`
  - `ssl_monitor`
  - `auto_learning_scheduler`
  - `canary_rollout_scheduler`
  - `redis_degraded_monitor`
  - `auto_reputation_service`
  - `threat_intel_service`
  - `malware_scan_monitor`
  - `good_bot_service`

---

## 21. Administrative Audit Trails (`/security`)

Mounted from [`backend/app/routes/security_audit.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/security_audit.py) with prefix `/security`.

### `GET /security/events`
Paginated administrative change history and security events.

- **Auth Required:** Any authenticated role.
- **Query Parameters:** `event_type`, `hours`, `page`, `page_size`.
- **Event Types:** `AUTH_ATTEMPT`, `RATE_LIMIT_TRIGGER`, `RULE_CHANGE`, `APP_CONFIG_CHANGE`, `USER_CHANGE`, `BACKUP_OPERATION`.

### Sub-filters
- `GET /security/events/auth`: Dedicated authentication attempts log.
- `GET /security/events/rate-limits`: Rate limiter trigger events.
- `GET /security/statistics`: Summary metrics of security actions and admin activities.
- `GET /security/ip/{ip_address}`: Full audit history associated with a specific administrative or client IP.

---

## 22. Real-Time WebSocket Stream (`/logs/stream`)

Mounted from [`backend/app/routes/ws.py`](file:///opt/ModSecurity/WAF_GUI/backend/app/routes/ws.py).

### `WebSocket /logs/stream`
Full-duplex WebSocket connection delivering real-time security events and triggered notifications directly to browser dashboards.

- **Protocol:** `ws://` or `wss://`
- **Handshake Authentication:**
  - Browser automatically transmits `waf_session_v3` cookie during the HTTP upgrade handshake.
  - The server verifies token signature, checks expiration, and validates the `Origin` header against `BACKEND_CORS_ORIGINS`.
  - Rejection: HTTP `403` or WebSocket close code `1008` (Policy Violation).
- **Outbound Stream Message Format (JSON):**
  ```json
  {
    "type": "waf_event",
    "data": {
      "id": "1727078400.987654-def456",
      "timestamp": "2026-09-23 12:30:00",
      "client_ip": "198.51.100.88",
      "method": "POST",
      "uri": "/wp-login.php",
      "severity": "CRITICAL",
      "attack_type": "Credential Stuffing / Bad Bot",
      "action": "blocked"
    }
  }
  ```
- **Heartbeat & Keepalive:**
  - The client may transmit standard ping frames; the server keeps the socket open until browser disconnect or token invalidation.
