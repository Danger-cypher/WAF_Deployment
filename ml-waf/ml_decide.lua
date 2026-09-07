package.path = "/opt/ml-waf/lualib/?.lua;/opt/ml-waf/?.lua;" .. package.path
local http = require("resty.http")
local json = require("cjson")
local bot_challenge = require("bot_challenge")
local waf_redis = require("waf_redis")

-- CONTENT-phase handler (content_by_lua_file), run per-location for any
-- location that opted in via `set $waf_upstream_location "@some_name";`.
-- nginx guarantees the entire access phase — every handler in it, both
-- ml_check.lua (static) and ModSecurity's ngx_http_modsecurity_module
-- (dynamically loaded via load_module) — has fully completed before the
-- content phase starts, regardless of the two modules' relative order
-- *within* the access phase. That ordering-within-a-phase is what made the
-- CRS score unreliable when read from access_by_lua_file (ml_check.lua):
-- confirmed live, a request ModSecurity itself blocked with a real
-- computed score of 20 was logged by the old single-script version with
-- crs_score=0 and decision=allow. Reading it here instead is reliable
-- without needing to change module load order or how OpenResty is built.
--
-- On allow, hands off to the location's own proxy_pass via ngx.exec() —
-- an internal redirect (same mechanism `error_page 403 = @json_forbidden`
-- already uses elsewhere in this codebase), not a subrequest, so the
-- target location's native proxy_pass handles the actual proxying
-- (headers, streaming, WebSocket upgrade, request body forwarding)
-- exactly as it would if reached directly. This script never calls
-- ngx.req.read_body(), so the client body — if any — is left untouched
-- for that proxy_pass to read/stream normally.

-- Must mirror ml_check.lua's is_admin_request() exactly: those paths never
-- reach the ML daemon, and the content phase runs independently of what
-- the access phase decided, so this check has to be repeated here rather
-- than relied upon from access_by_lua_file.
--
-- Reads $request_uri (original, pre-rewrite), not $uri — see ml_check.lua's
-- matching comment. cybersentinel's `location /api/` does `rewrite
-- ^/api/(.*) /$1 break;` in the REWRITE phase, which runs before the
-- CONTENT phase this script executes in, so $uri here for a request to
-- /api/health has already become /health and every exemption below
-- silently stopped matching. Confirmed live via ClickHouse ml_events: these
-- paths were reaching the ML daemon instead of being skipped.
local function request_path()
    local full = ngx.var.request_uri or ngx.var.uri or ""
    local qmark = full:find("?", 1, true)
    if qmark then
        return full:sub(1, qmark - 1)
    end
    return full
end

local function is_admin_request(path)
    local telemetry_reads = {
        ["/api/stats"]                  = true,
        ["/api/logs"]                   = true,
        ["/api/rules"]                  = true,
        ["/api/health"]                 = true,
        ["/api/top-ips"]               = true,
        ["/api/attack-types"]           = true,
        ["/api/timeline"]               = true,
        ["/api/top-rules"]              = true,
        ["/api/severity-distribution"]  = true,
        ["/api/ddos/analytics"]         = true,
        ["/api/ml/stats"]               = true,
        ["/api/ml/logs"]                = true,
        ["/api/ml/timeline"]            = true,
    }
    if telemetry_reads[path] then
        return true
    end
    if string.match(path, "^/api/auth/") then
        return true
    end
    if string.match(path, "^/api/ml/") then
        return true
    end
    if string.match(path, "^/static/") or
       string.match(path, "%.js$") or
       string.match(path, "%.css$") or
       string.match(path, "%.ico$") or
       string.match(path, "%.png$") or
       string.match(path, "%.woff2?$") then
        return true
    end
    return false
end

local upstream_location = ngx.var.waf_upstream_location
if not upstream_location or upstream_location == "" then
    -- Misconfiguration: a location set content_by_lua_file to this script
    -- without also setting $waf_upstream_location. Fail closed rather than
    -- silently generating an empty 200.
    ngx.log(ngx.ERR, "ml_decide.lua: $waf_upstream_location not set for ", ngx.var.uri or "")
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

-- Mirrors ml_check.lua's is_control_plane(): the path exemption list above
-- is a control-plane concern only. It exists so the dashboard's own 3s
-- polling isn't scored by the engine it administers (feedback loops, and
-- the 2026-09-04 self-lockout). Applied on the data plane it was a scoring
-- bypass — `GET /anything.js?<payload>` against a protected application
-- skipped the ML engine entirely, since the query string is stripped before
-- matching (audit finding P1-03, confirmed live against ml_events).
--
-- pcall-guarded for the same reason as everywhere else in these two files:
-- reading an nginx variable that is never `set` in any server block raises.
local function is_control_plane()
    local ok, v = pcall(function() return ngx.var.waf_control_plane end)
    return ok and v == "1"
end

if is_control_plane() and is_admin_request(request_path()) then
    return ngx.exec(upstream_location)
end

-- Read the real ModSecurity anomaly score, exposed by the connector's
-- $modsecurity_anomaly_score variable (backed by CRS v4's
-- TX:BLOCKING_INBOUND_ANOMALY_SCORE via msc_get_tx_variable()) — reliable
-- here because the access phase has fully completed (see header comment).
local headers = ngx.req.get_headers()
local crs_score = tonumber(ngx.var.modsecurity_anomaly_score) or 0.0
local matched_vars = ngx.var.modsec_matched_var_names or ""

-- JA4 fingerprint, cached by ja4.lua during the TLS handshake — a short,
-- independent Redis round trip (own connect/keepalive, same shape as
-- bot_challenge.check_risk_triggered()'s own connection further down in
-- this file) rather than threading it through from ml_check.lua's access-
-- phase connection, which is already closed out by the time this
-- content-phase script runs. Empty string, not nil, when unavailable —
-- ml_server.py's RequestTelemetry field defaults to "" and treats that as
-- "no fingerprint", so a degraded Redis here just means this request
-- doesn't contribute to JA4 reputation, same fail-open shape as
-- ml_check.lua's own checks.
local ja4 = ""
do
    local red = waf_redis.connect()
    if red then
        local v = red:get("ja4:" .. (ngx.var.remote_addr or ""))
        if v and v ~= ngx.null then
            ja4 = v
        end
        red:set_keepalive(10000, 100)
    end
end

-- $geoip2_data_asn only exists as an nginx variable when nginx_manager.py's
-- DDoS config generator actually emitted the ASN geoip2 {} block
-- (GEOIP2_MODULE_ENABLED=true and the ASN MMDB present) — same pcall-guard
-- reasoning as ml_check.lua's get_geo_country(): an undeclared nginx
-- variable raises a Lua error on access rather than returning nil, so this
-- must stay guarded even though the block is expected to exist in this
-- deployment. Empty string (not nil) when unavailable, same convention as
-- ja4 above — ml_server.py's RequestTelemetry field defaults to "" and
-- treats that as "no ASN", not an error.
local asn = ""
do
    local ok, v = pcall(function() return ngx.var.geoip2_data_asn end)
    if ok and v and v ~= "" then
        asn = v
    end
end

local payload = {
    unique_id = ngx.var.unique_id or ngx.var.request_id or "",
    crs_score = crs_score,
    matched_vars = matched_vars,
    uri = ngx.var.request_uri or "",
    args = ngx.var.args or "",
    method = ngx.req.get_method(),
    body_len = tonumber(headers["Content-Length"]) or 0,
    ct = headers["Content-Type"] or "",
    ua = headers["User-Agent"] or "",
    remote_addr = ngx.var.remote_addr or "",
    ja4 = ja4,
    asn = asn
}

local httpc = http.new()
httpc:set_timeouts(500, 500, 500)

-- CRS-only fallback threshold: if the ML daemon is unavailable, only block
-- requests where the ModSecurity CRS score already indicates a clear
-- attack, so a brief ML outage (e.g. daemon restart during model
-- retraining) doesn't turn into a self-inflicted DoS.
--
-- This was 20.0 — effectively unreachable in this deployment. This script
-- runs in the CONTENT phase, after ModSecurity's own access-phase blocking
-- rule (949110) has already evaluated tx.inbound_anomaly_score_threshold,
-- configured to 5 in rules-override.conf — a request scoring >= 5 is
-- normally blocked there and never reaches this code (a prior audit did
-- record one exception at crs_score=10 out of 108,870 ml_events, most
-- likely a per-rule exclusion overriding that specific match's action
-- while still letting the score accumulate — not something to design
-- around). A threshold of 20 was consequently dead code: real traffic
-- reaching here overwhelmingly scores well under 5, so it could never
-- fire. Set to one point below the configured block threshold instead —
-- the highest-confidence signal actually reachable under normal
-- operation, meaning "CRS was one point from blocking this outright on
-- its own." If tx.inbound_anomaly_score_threshold in rules-override.conf
-- ever changes, update this to match (one less than that value).
local CRS_BLOCK_THRESHOLD = 4.0

local function crs_only_fallback(reason)
    ngx.log(ngx.WARN, "ML-WAF: ", reason, " — falling back to CRS-only mode.")
    if crs_score >= CRS_BLOCK_THRESHOLD then
        ngx.log(ngx.WARN, "ML-WAF CRS fallback: blocking request with CRS score=", crs_score)
        -- WAF-LUA-BLOCK: see ml_check.lua's mTLS check for the full
        -- explanation of this tag — feeds this decision into waf_events
        -- alongside ModSecurity's own audit-log-sourced events.
        ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=crs_fallback code=403 client=", ngx.var.remote_addr or "", " uri=", ngx.var.request_uri or "")
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/html; charset=UTF-8"
        ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (CRS Rule Enforcement)</p>")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    else
        ngx.log(ngx.INFO, "ML-WAF CRS fallback: allowing request (CRS score=", crs_score, " < ", CRS_BLOCK_THRESHOLD, ")")
        return ngx.exec(upstream_location)
    end
end

local ml_host = os.getenv("ML_HOST") or "127.0.0.1"
local ml_port = tonumber(os.getenv("ML_PORT")) or 8003
local ok, err
if string.match(ml_host, "^unix:") then
    ok, err = httpc:connect(ml_host)
else
    ok, err = httpc:connect(ml_host, ml_port)
end

if not ok then
    return crs_only_fallback("ML daemon unreachable: " .. (err or "unknown"))
end

-- Same shared secret the backend uses for waf-ml's admin endpoints (see
-- ml_server.py's verify_internal_key docstring — audit finding P3-04:
-- /predict previously had no auth of its own, relying entirely on Docker
-- network topology). Empty when unset, matching verify_internal_key's own
-- degrade-to-topology-only behavior on that side — never blocks this hot
-- path just because the key hasn't been configured in this environment.
local internal_key = os.getenv("INTERNAL_ALERT_TRIGGER_KEY") or ""

local res, err = httpc:request({
    path = "/predict",
    method = "POST",
    body = json.encode(payload),
    headers = {
        ["Host"] = string.match(ml_host, "^unix:") and "127.0.0.1" or ml_host,
        ["Content-Type"] = "application/json",
        ["X-Internal-Key"] = internal_key,
    }
})

if not res then
    httpc:close()
    return crs_only_fallback("ML daemon request error: " .. (err or "unknown"))
end

httpc:close()

if res.status == 401 then
    -- WAF-LUA-BLOCK: see ml_check.lua's mTLS check for the full
    -- explanation of this tag.
    ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=ml_engine code=403 client=", ngx.var.remote_addr or "", " uri=", ngx.var.request_uri or "")
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (ML Threat Engine)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)

elseif res.status == 429 then
    ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=ml_engine_throttle code=429 client=", ngx.var.remote_addr or "", " uri=", ngx.var.request_uri or "")
    ngx.status = 429
    ngx.header["Retry-After"] = "60"
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>429 Too Many Requests</h1><p>Slow down — rate limited by WAF. Retry after 60s.</p>")
    ngx.exit(429)

elseif res.status == 200 then
    -- Graduated response for moderate-risk traffic (threat_score's "log"
    -- band, 0.40-0.70 — real signal, but not certain enough for the
    -- rate_limit/block bands). Opt-in (default off, see
    -- waf_risk_challenge_enabled): a real browser clears the same
    -- JS-reload interstitial already used for bad-bot UAs in ~600ms; a
    -- scripted client doesn't. Independent of that existing bot-UA gate —
    -- this one triggers off the ML risk score instead.
    if res.headers["X-WAF-Risk-Challenge"] == "1" and ngx.var.waf_risk_challenge_enabled == "1" then
        local red = waf_redis.connect()
        if red then
            bot_challenge.check_risk_triggered(red, ngx.var.remote_addr or "")
            red:set_keepalive(10000, 100)
        end
    end
    return ngx.exec(upstream_location)

else
    ngx.log(ngx.WARN, "ML-WAF: unexpected daemon response status: ", res.status)
    return crs_only_fallback("unexpected daemon response status " .. tostring(res.status))
end
