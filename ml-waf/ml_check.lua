package.path = "/opt/ml-waf/lualib/?.lua;/opt/ml-waf/?.lua;" .. package.path
local bit = require("bit")
local bot_challenge = require("bot_challenge")
local schema_validate = require("schema_validate")
local waf_redis = require("waf_redis")

-- This script runs in the ACCESS phase — IP/geo/schema/bot checks only, all
-- of which are safe to decide before ModSecurity has finished its own
-- access-phase evaluation (none of them depend on the CRS score). The CRS
-- score read + ML /predict call + block/challenge decision live in
-- ml_decide.lua instead, run from the CONTENT phase via
-- `content_by_lua_file` on each proxying location. That split exists
-- because of a real, confirmed bug: ngx_http_modsecurity_module is loaded
-- dynamically (`load_module`) while this access_by_lua_file handler is
-- static, and nginx does not guarantee dynamically-loaded modules' phase
-- handlers run before statically-linked ones' within the same phase — so a
-- CRS score read here can see a stale/zero value (confirmed live: a request
-- ModSecurity blocked with a real score of 20 was logged by the old
-- single-script version with crs_score=0). nginx *does* guarantee the
-- entire access phase (every handler in it, static or dynamic) completes
-- before the content phase begins, regardless of order within the access
-- phase — so reading the score in content phase is reliable without
-- touching module load order at all. See ml_decide.lua.

-- Skip ML evaluation ONLY for:
--   1. Read-only dashboard telemetry endpoints (would cause feedback loops / DB locks)
--   2. Auth endpoints (already rate-limited; ML feedback loop risk)
--   3. Static frontend assets (no security value in scoring static files)
-- NOTE (Gap 3 Fix): State-changing admin API paths (settings save, exclusions write,
--   system actions) are NO LONGER exempt — they now pass through ML scoring.
--   ModSecurity CRS remains active on ALL paths regardless.
-- NOTE: also duplicated in ml_decide.lua (content phase) — a location that
-- dispatches to content_by_lua_file must independently skip the ML call for
-- the same exempted paths, since the content phase runs regardless of what
-- this access-phase script decided.
--
-- Deliberately reads $request_uri (the client's original request line,
-- never touched by internal rewrites), not $uri: cybersentinel's own
-- `location /api/` does `rewrite ^/api/(.*) /$1 break;`, and nginx's
-- REWRITE phase runs before both the ACCESS phase (this file) and the
-- CONTENT phase (ml_decide.lua) — so by the time either script runs,
-- $uri for a request to /api/health has already become /health, and every
-- entry in the exemption table below silently stops matching anything
-- routed through that location. Confirmed live: /api/health, /api/top-ips
-- etc. were reaching the ML daemon instead of being skipped. $request_uri
-- includes the query string, so it's stripped below before matching.
local function request_path()
    local full = ngx.var.request_uri or ngx.var.uri or ""
    local qmark = full:find("?", 1, true)
    if qmark then
        return full:sub(1, qmark - 1)
    end
    return full
end
local uri = request_path()
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

    -- 3. External threat-intel feed (Spamhaus DROP/EDROP via
    -- threat_intel_service.py, Settings > Hardening). Kept in its own key
    -- so a scheduled sync can never clobber the admin-managed blacklist
    -- above — checked last, so the manual whitelist (already returned by
    -- this point) always overrides a feed-sourced hit.
    local feed_cidrs, err = red:smembers("waf:blacklist:feed:cidrs")
    if feed_cidrs and #feed_cidrs > 0 then
        local client_ip_int = ip_to_int(client_ip)
        if client_ip_int and match_cidrs(client_ip_int, feed_cidrs) then
            return "blacklist"
        end
    end

    -- 4. Self-learned reputation (auto_reputation_service.py, Settings >
    -- Hardening) — individual TTL'd keys (waf:blacklist:auto:<ip>), not a
    -- CIDR set like the feed tier above, since these are auto-expiring
    -- individual IPs, not admin-curated netblocks. Checked last: the
    -- least-authoritative tier (machine-inferred from this deployment's
    -- own traffic, not admin intent or a curated feed), and the whitelist
    -- check at the top of this function already returned before we ever
    -- get here for a whitelisted IP.
    local is_auto_blocked = red:get("waf:blacklist:auto:" .. client_ip)
    if is_auto_blocked and is_auto_blocked ~= ngx.null then
        return "blacklist"
    end

    return "none"
end

-- $geoip2_data_country_code only exists as an nginx variable when
-- nginx_manager.py's DDoS config generator actually emitted the `geoip2 {}`
-- block (GEOIP2_MODULE_ENABLED=true and the Country MMDB present) — an
-- undeclared nginx variable raises a Lua error on access rather than
-- returning nil, so this must be pcall-guarded to stay safe if that's ever
-- toggled off again.
local function get_geo_country()
    local ok, country = pcall(function() return ngx.var.geoip2_data_country_code end)
    if ok and country and country ~= "" then
        return country
    end
    return nil
end

-- Settings > Hardening's geo-block (nginx_manager.apply_geo_block_settings
-- populates these keys, zero-reload like the IP whitelist/blacklist above).
-- Fails open whenever the mode, country data, or Redis itself is unavailable
-- — a missing GeoIP match must never turn into a lockout.
local function check_geo_block(red)
    local mode = red:get("waf:geo:block_mode")
    if not mode or mode == ngx.null or mode == "disabled" then
        return false
    end
    local country = get_geo_country()
    if not country then
        return false
    end
    local is_member = red:sismember("waf:geo:countries", country)
    if mode == "deny" then
        return is_member == 1
    elseif mode == "allow" then
        return is_member ~= 1
    end
    return false
end

-- Adaptive per-identity throttle (opt-in, DDoS & Bot Shield settings).
-- Layered on top of — never replacing — the native limit_req zones
-- generated by nginx_manager.py, which must keep working even when Redis
-- or the ML daemon are degraded; this is an *additional*, tighter gate
-- for identities that have already shown themselves to be risky, not a
-- substitute for the base volumetric limit. Reputation (rep:{ip}) is
-- written by ml_server.py's increment_reputation()/decay_reputation() on
-- every /predict call — reading it here needs no new signal, just a
-- threshold check against what's already tracked. Deliberately checked
-- here in the ACCESS phase rather than ml_decide.lua's CONTENT phase:
-- this doesn't depend on the CRS score at all (unlike the bug documented
-- at the top of this file), so there's no correctness reason to defer it
-- — and doing it here means an already-throttled IP short-circuits before
-- wasting a /predict call on a request that's about to be rejected anyway.
local ADAPTIVE_THROTTLE_REP_THRESHOLD = 3.0   -- ~3 confirmed ML blocks in the last 24h
local ADAPTIVE_THROTTLE_MAX_REQUESTS = 10     -- once elevated, allow at most this many...
local ADAPTIVE_THROTTLE_WINDOW_SECONDS = 60   -- ...per this rolling window

local function check_adaptive_throttle(red, client_ip)
    if ngx.var.waf_adaptive_throttle_enabled ~= "1" then
        return false
    end
    local rep = red:get("rep:" .. client_ip)
    if rep == ngx.null or not rep then
        return false
    end
    rep = tonumber(rep)
    if not rep or rep < ADAPTIVE_THROTTLE_REP_THRESHOLD then
        return false
    end

    local key = "waf:throttle:" .. client_ip
    local count, err = red:incr(key)
    if not count then
        return false -- fail open on a Redis error, consistent with every other check here
    end
    if count == 1 then
        red:expire(key, ADAPTIVE_THROTTLE_WINDOW_SECONDS)
    end
    return count > ADAPTIVE_THROTTLE_MAX_REQUESTS
end

-- Dynamic IP Restriction Check via Redis
local red = waf_redis.connect()
if red then
    do
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

        if check_geo_block(red) then
            red:set_keepalive(10000, 100)
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (Geo-Restriction)</p>")
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        if check_adaptive_throttle(red, client_ip) then
            red:set_keepalive(10000, 100)
            ngx.status = 429
            ngx.header["Retry-After"] = "60"
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.say("<h1>429 Too Many Requests</h1><p>Slow down — rate limited by WAF. Retry after 60s.</p>")
            ngx.exit(429)
        end

        -- Positive-security API schema check (Settings > per-app "API
        -- Schema"). No-ops unless this host has a schema configured AND the
        -- request matches one of its declared endpoints. Exits internally
        -- (400) in "enforce" mode on a violation; releases its own
        -- keepalive first since it may not return.
        schema_validate.check(red)

        -- Opt-in JS Challenge bot mitigation (DDoS & Bot Shield settings).
        -- No-ops immediately unless both the feature is enabled AND this
        -- request's UA matched the existing bad-bot signal — reuses the
        -- same connected Redis client, releasing it itself if it serves
        -- the interstitial and exits.
        bot_challenge.check(red, client_ip)
    end
    red:set_keepalive(10000, 100)
end

-- CRS score read + ML /predict call + block/challenge decision: see
-- ml_decide.lua (content phase, run per-location via content_by_lua_file).
