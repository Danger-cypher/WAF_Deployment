package.path = "/opt/ml-waf/lualib/?.lua;/opt/ml-waf/?.lua;" .. package.path
local http = require("resty.http")
local json = require("cjson")
local redis = require("resty.redis")
local bit = require("bit")
local bot_challenge = require("bot_challenge")

-- Skip ML evaluation ONLY for:
--   1. Read-only dashboard telemetry endpoints (would cause feedback loops / DB locks)
--   2. Auth endpoints (already rate-limited; ML feedback loop risk)
--   3. Static frontend assets (no security value in scoring static files)
-- NOTE (Gap 3 Fix): State-changing admin API paths (settings save, exclusions write,
--   system actions) are NO LONGER exempt — they now pass through ML scoring.
--   ModSecurity CRS remains active on ALL paths regardless.
local uri = ngx.var.uri or ""
local function is_admin_request(path)
    -- Exact read-only telemetry endpoints that would cause DB/Redis feedback loops
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

    -- Auth routes: already have rate limiting; ML scoring would cause a scoring loop
    -- on the ML event database writes triggered by the login itself.
    if string.match(path, "^/api/auth/") then
        return true
    end

    -- ML engine internal health/predict — never score ourselves
    if string.match(path, "^/api/ml/") then
        return true
    end

    -- Static frontend assets — no threat surface
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

if is_admin_request(uri) then
    return
end


-- IP conversion helpers
local function ip_to_int(ip)
    local o1, o2, o3, o4 = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    if not o1 then return nil end
    return bit.bor(
        bit.lshift(tonumber(o1), 24),
        bit.lshift(tonumber(o2), 16),
        bit.lshift(tonumber(o3), 8),
        tonumber(o4)
    )
end

local function parse_cidr(cidr)
    local ip, mask_bits = cidr:match("([^/]+)/(%d+)")
    if not ip then
        ip = cidr
        mask_bits = 32
    end
    local ip_int = ip_to_int(ip)
    if not ip_int then return nil end
    
    local mask_bits_num = tonumber(mask_bits)
    local mask
    if mask_bits_num == 0 then
        mask = 0
    elseif mask_bits_num == 32 then
        mask = 0xffffffff
    else
        mask = bit.lshift(bit.rshift(0xffffffff, 32 - mask_bits_num), 32 - mask_bits_num)
    end
    return bit.band(ip_int, mask), mask
end

local function match_cidrs(client_ip_int, cidr_list)
    for _, cidr in ipairs(cidr_list) do
        local subnet_int, mask = parse_cidr(cidr)
        if subnet_int and bit.band(client_ip_int, mask) == subnet_int then
            return true
        end
    end
    return false
end

local function check_ip_auth(red, client_ip)
    -- 1. Exact match check (fast O(1))
    local is_white, err = red:sismember("waf:whitelist", client_ip)
    if is_white == 1 then
        return "whitelist"
    end
    local is_black, err = red:sismember("waf:blacklist", client_ip)
    if is_black == 1 then
        return "blacklist"
    end

    -- 2. Fetch CIDR ranges (if any) and check them
    local whitelist_cidrs, err = red:smembers("waf:whitelist:cidrs")
    if whitelist_cidrs and #whitelist_cidrs > 0 then
        local client_ip_int = ip_to_int(client_ip)
        if client_ip_int and match_cidrs(client_ip_int, whitelist_cidrs) then
            return "whitelist"
        end
    end

    local blacklist_cidrs, err = red:smembers("waf:blacklist:cidrs")
    if blacklist_cidrs and #blacklist_cidrs > 0 then
        local client_ip_int = ip_to_int(client_ip)
        if client_ip_int and match_cidrs(client_ip_int, blacklist_cidrs) then
            return "blacklist"
        end
    end

    return "none"
end

-- Dynamic IP Restriction Check via Redis
local red = redis:new()
red:set_timeouts(100, 100, 100) -- 100ms

-- Read Redis password from environment variable first, then fallback to protected secret file
local redis_password = os.getenv("REDIS_PASSWORD")
if not redis_password or redis_password == "" then
    local secret_file = io.open("/etc/cybersentinel/redis.secret", "r")
    if secret_file then
        redis_password = secret_file:read("*l")
        secret_file:close()
        if redis_password then
            redis_password = redis_password:match("^%s*(.-)%s*$") -- trim whitespace
        end
    end
end

local redis_host = os.getenv("REDIS_HOST") or "127.0.0.1"
local ok, err = red:connect(redis_host, 6379)
if ok then
    -- Only authenticate if password was loaded from the secret file
    local auth_ok = true
    if redis_password and redis_password ~= "" then
        local res, auth_err = red:auth(redis_password)
        if not res then
            ngx.log(ngx.ERR, "Redis authentication failed: ", auth_err)
            auth_ok = false
        end
    end

    if auth_ok then
        local client_ip = ngx.var.remote_addr or ""
        local status = check_ip_auth(red, client_ip)
        
        if status == "whitelist" then
            red:set_keepalive(10000, 100)
            return
        elseif status == "blacklist" then
            red:set_keepalive(10000, 100)
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (IP Access Denied)</p>")
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        -- Opt-in JS Challenge bot mitigation (DDoS & Bot Shield settings).
        -- No-ops immediately unless both the feature is enabled AND this
        -- request's UA matched the existing bad-bot signal — reuses the
        -- same connected Redis client, releasing it itself if it serves
        -- the interstitial and exits.
        bot_challenge.check(red, client_ip)
    end
    red:set_keepalive(10000, 100)
end

-- 1. Read the real ModSecurity anomaly score, exposed by the connector's
-- $modsecurity_anomaly_score variable (backed by TX:ANOMALY_SCORE via
-- msc_get_tx_variable()). Populated because ModSecurity's own access-phase
-- handler always runs before this script within the same access phase.
local headers = ngx.req.get_headers()
local crs_score = tonumber(ngx.var.modsecurity_anomaly_score) or 0.0
local matched_vars = ngx.var.modsec_matched_var_names or ""

-- 3. Prepare telemetry payload parameters
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

-- 4. Initiate the HTTP client with timeouts
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
        -- CRS score is below threshold — allow through on ML daemon degraded mode
        ngx.log(ngx.INFO, "ML-WAF CRS fallback: allowing request (CRS score=", crs_score, " < ", CRS_BLOCK_THRESHOLD, ")")
        return
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
    crs_only_fallback("ML daemon unreachable: " .. (err or "unknown"))
    return
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

-- 5. Handle ML daemon failure — use CRS-only fallback instead of blocking all traffic
if not res then
    httpc:close()
    crs_only_fallback("ML daemon request error: " .. (err or "unknown"))
    return
end

-- 6. Parse response from the FastAPI prediction server
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
    return

else
    -- Unexpected daemon response — use CRS fallback instead of blanket block
    ngx.log(ngx.WARN, "ML-WAF: unexpected daemon response status: ", res.status)
    crs_only_fallback("unexpected daemon response status " .. tostring(res.status))
    return
end
