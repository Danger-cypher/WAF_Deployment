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

if is_admin_request(request_path()) then
    return ngx.exec(upstream_location)
end

-- Read the real ModSecurity anomaly score, exposed by the connector's
-- $modsecurity_anomaly_score variable (backed by CRS v4's
-- TX:BLOCKING_INBOUND_ANOMALY_SCORE via msc_get_tx_variable()) — reliable
-- here because the access phase has fully completed (see header comment).
local headers = ngx.req.get_headers()
local crs_score = tonumber(ngx.var.modsecurity_anomaly_score) or 0.0
local matched_vars = ngx.var.modsec_matched_var_names or ""

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
    remote_addr = ngx.var.remote_addr or ""
}

local httpc = http.new()
httpc:set_timeouts(500, 500, 500)

-- CRS-only fallback threshold: if ML daemon is unavailable, only block requests where
-- the ModSecurity CRS score already indicates a clear attack (score >= 20).
-- This prevents a self-inflicted DoS if the ML daemon restarts during model retraining.
local CRS_BLOCK_THRESHOLD = 20.0

local function crs_only_fallback(reason)
    ngx.log(ngx.WARN, "ML-WAF: ", reason, " — falling back to CRS-only mode.")
    if crs_score >= CRS_BLOCK_THRESHOLD then
        ngx.log(ngx.WARN, "ML-WAF CRS fallback: blocking request with CRS score=", crs_score)
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

local res, err = httpc:request({
    path = "/predict",
    method = "POST",
    body = json.encode(payload),
    headers = {
        ["Host"] = string.match(ml_host, "^unix:") and "127.0.0.1" or ml_host,
        ["Content-Type"] = "application/json",
    }
})

if not res then
    httpc:close()
    return crs_only_fallback("ML daemon request error: " .. (err or "unknown"))
end

httpc:close()

if res.status == 401 then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (ML Threat Engine)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)

elseif res.status == 429 then
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
