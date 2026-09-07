package.path = "/opt/ml-waf/lualib/?.lua;/opt/ml-waf/?.lua;" .. package.path
local bit = require("bit")
local bot_challenge = require("bot_challenge")
local schema_validate = require("schema_validate")
local enum_detect = require("enum_detect")
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

-- True only inside the admin dashboard's own server block, which sets
-- $waf_control_plane (see sites-available/cybersentinel). pcall-guarded
-- because a variable that is never `set` in ANY server block raises a Lua
-- error on read rather than returning nil — same reason check_mtls() and
-- get_geo_country() below are guarded.
local function is_control_plane()
    local ok, v = pcall(function() return ngx.var.waf_control_plane end)
    return ok and v == "1"
end

-- The exemption list above used to short-circuit this ENTIRE script:
--
--     if is_admin_request(uri) then return end
--
-- Everything below it was skipped — mTLS client-cert verification, the
-- manual IP blacklist, the auto-reputation blacklist, the threat-intel feed,
-- the whitelist, JA4 TLS-fingerprint blocking, geo-restriction, good-bot
-- verification, adaptive throttling, schema validation and enumeration
-- detection. And because this file is wired in once at http level
-- (nginx.conf's access_by_lua_file), that applied to protected customer
-- applications too, not just the dashboard it was written for.
--
-- Confirmed live (audit finding P1-03): /probe-plain?x=1 was scored and
-- checked, while /probe-evade.js?x=1, /static/probe-evade?x=1 and
-- /api/auth/probe-evade?x=1 were not — the query string is stripped before
-- matching, so `GET /anything.js?<payload>` cleared every check above. A
-- blacklisted or geo-blocked client reached the origin freely, and mTLS was
-- bypassed on /api/auth/*, precisely the endpoints it exists to protect.
--
-- Two things were conflated. The list's three stated rationales (feedback
-- loops on telemetry reads, auth-endpoint scoring loops, "no security value
-- in scoring static files") are all about SCORING and heuristics. None of
-- them argue for skipping a hard security boundary. So:
--
--   * IP allow/deny, threat-intel feed, JA4, geo-block and mTLS now run on
--     EVERY request, on both planes, with no exemption. These are policy
--     decisions an operator made explicitly; no request shape may dodge them.
--
--   * The behavioural/heuristic checks — adaptive throttle, API-enumeration
--     detection, JS bot challenge, schema validation — remain skippable, but
--     ONLY on the control plane, where they would otherwise fire on the
--     dashboard's own polling. That is the real thing the list was protecting
--     against, and it is what caused the 2026-09-04 self-lockout.
--
-- On the data plane nothing is exempt: a protected application gets every
-- check on every request. That costs an ML round trip on static assets that
-- previously skipped one; correctness before throughput, and it is an
-- explicit operator tuning decision if it ever needs revisiting.
local skip_behavioral_checks = is_control_plane() and is_admin_request(uri)

-- mTLS for API auth (roadmap item), scoped to this app's /api path only.
-- $waf_mtls_mode is a per-server-block `set` (nginx_manager.py), present
-- only for apps that actually have mTLS enabled with a real CA cert file
-- on disk — reading an nginx variable that was never `set` ANYWHERE in
-- the whole config raises a Lua error (the exact reason get_geo_country()
-- below is also pcall-guarded), so this must be too: if zero apps in the
-- whole deployment have mTLS on, $waf_mtls_mode is never declared at all.
-- $ssl_client_verify itself needs no such guard — it's a built-in
-- ngx_http_ssl_module variable, always safe to read (empty string on a
-- connection with no client cert requested).
--
-- Deliberately independent of the Redis-connected block below: mTLS
-- verification is decided entirely by nginx's own TLS-handshake state,
-- so this must keep working even during a Redis outage, same as every
-- other check in this file failing open rather than depending on
-- something unrelated being up.
local function check_mtls(path)
    local ok, mode = pcall(function() return ngx.var.waf_mtls_mode end)
    if not ok or not mode or mode == "" then
        return false -- mTLS not configured for this app
    end
    if not (path == "/api" or path:sub(1, 5) == "/api/") then
        return false -- scoped to /api only, not the whole app
    end

    local verify = ngx.var.ssl_client_verify
    if verify == "SUCCESS" then
        return false -- valid client cert presented
    end

    if mode == "enforce" then
        return true
    end

    -- "log" mode: request+record only, never block — lets an admin
    -- confirm real client certs actually verify before flipping to
    -- enforce.
    ngx.log(ngx.WARN, "mTLS log-mode: client verify=", (verify or "NONE"),
        " for ", ngx.var.host or "?", " ", path, " (not blocking)")
    return false
end

if check_mtls(uri) then
    -- WAF-LUA-BLOCK: the one consistent, greppable tag every non-
    -- ModSecurity blocking decision in this file logs before rejecting a
    -- request. nginx_errorlog_parser.py recognizes this format and feeds
    -- it into the SAME waf_events ClickHouse pipeline ModSecurity's own
    -- audit log already uses — without it, every one of these decisions
    -- (mTLS/blacklist/JA4/geo/adaptive-throttle/API-enum) was completely
    -- invisible to every dashboard metric derived from waf_events, not
    -- just the DDoS page (real gap, found + fixed 2026-09-04).
    ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=mtls code=403 client=", ngx.var.remote_addr or "", " uri=", uri)
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (Client Certificate Required)</p>")
    ngx.exit(ngx.HTTP_FORBIDDEN)
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

-- Known-bad JA4 TLS-client fingerprint blocklist (Settings > Hardening).
-- The fingerprint itself was already computed once per TLS handshake by
-- ja4.lua (ssl_client_hello_by_lua_file, which runs before this
-- access-phase script even starts) and cached in Redis keyed by client
-- IP — the caller reads that cached value back once (see below) and
-- passes it in here; this never recomputes anything. Unlike
-- check_ip_auth()'s whitelist/blacklist/feed/auto tiers, this is a single
-- exact-match set: a fingerprint has no CIDR concept, and no feed/
-- auto-learned source exists yet (admin-curated only, same as
-- nginx_manager.py's apply_hardening_settings comment explains).
-- Fails open exactly like every other check here: ja4 == nil (Redis was
-- down during the handshake, the ClientHello was malformed, or this is
-- HTTP-only traffic with no TLS handshake at all) means "don't block",
-- never "block because unknown".
local function check_ja4_block(red, ja4)
    if not ja4 then
        return false
    end
    return red:sismember("waf:blacklist:ja4", ja4) == 1
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

-- Same pcall-guard reasoning as get_geo_country() above, for the ASN geoip2
-- block instead of the Country one. Used by check_adaptive_throttle() to
-- look up rep:asn:{asn} for the CURRENT request — the value written into
-- that key comes from ml_server.py/redis_features.py via payload.asn
-- (ml_decide.lua reads this same nginx variable independently, since that
-- content-phase script has no access to this access-phase Lua state).
local function get_request_asn()
    local ok, asn = pcall(function() return ngx.var.geoip2_data_asn end)
    if ok and asn and asn ~= "" then
        return asn
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
--
-- Also weighs JA4-keyed reputation (rep:ja4:{fingerprint}), written by
-- the same /predict call via increment_ja4_reputation()/
-- decay_ja4_reputation() whenever ml_decide.lua's payload carried a
-- fingerprint. This is what actually closes the gap plain per-IP
-- reputation has: a botnet client that rotates source IPs but keeps
-- reusing the same TLS stack/library resets its rep:{ip} to zero on every
-- rotation, but rep:ja4:{fingerprint} carries straight through — so the
-- very first request from a "new" IP can already be elevated if that
-- fingerprint has a recent history, rather than needing
-- ADAPTIVE_THROTTLE_MAX_REQUESTS fresh hits to earn it again. The
-- resulting throttle is still counted and applied per-IP (waf:throttle:
-- {ip}) — JA4 only ever decides whether an identity STARTS elevated, it
-- never becomes the throttle key itself, since one fingerprint can
-- legitimately be shared by many unrelated real clients (e.g. the same
-- browser version).
local ADAPTIVE_THROTTLE_REP_THRESHOLD = 3.0   -- ~3 confirmed ML blocks in the last 24h
local ADAPTIVE_THROTTLE_MAX_REQUESTS = 10     -- once elevated, allow at most this many...
local ADAPTIVE_THROTTLE_WINDOW_SECONDS = 60   -- ...per this rolling window

-- Deliberately a much higher bar than the IP/JA4 threshold above. rep:{ip}
-- and rep:ja4:{fingerprint} each identify something close to a single real
-- client; rep:asn:{asn} aggregates every request from an entire autonomous
-- system, which for a big cloud/hosting provider can be thousands of
-- unrelated tenants sharing the same ASN. Reusing the same 3.0 threshold
-- here would mean a handful of unrelated bad actors renting from a large
-- cloud provider could throttle every other legitimate customer on that
-- same provider — a real collateral-damage risk the IP/JA4 threshold
-- doesn't have to worry about. Untuned against real traffic — an admin
-- running this against their own attack patterns may need to adjust it;
-- treat this as a conservative starting point, not a calibrated value.
local ADAPTIVE_THROTTLE_ASN_REP_THRESHOLD = 15.0

-- Bad-bot-UA rate limit (DDoS & Bot Shield > Bot Mitigation Action). Used
-- to be a native nginx limit_req_zone keyed on $binary_remote_addr, 1r/m.
-- Moved here because limit_req_status is a single, shared-per-scope
-- directive, not per-zone: that zone shared a scope with waf_ddos_req (the
-- general rate limit), so whichever status the bot dropdown picked ("Silent
-- Drop" -> 444) silently overrode the status for the general zone too —
-- login attempts, ordinary API rate limiting, every customer app's own
-- zone_app_<id> — none of which have anything to do with bot mitigation
-- (audit finding P2-07). Doing this in Lua instead lets it exit with
-- whichever status $waf_bot_mitigation_status carries (444/429, written by
-- nginx_manager.apply_ddos_settings()) without touching any other zone's
-- status at all.
--
-- Same INCR+EXPIRE shape as check_adaptive_throttle below, deliberately —
-- one bump per request, TTL set only on the first hit in a window. count>1
-- (not >=) matches the old zone's "burst=1, rate=1r/m" semantics: the
-- first request in a 60s window from a bad-bot-tagged client still gets
-- through, only the second one onward within that same window is rejected.
local BAD_BOT_RATE_LIMIT_WINDOW_SECONDS = 60

local function check_bad_bot_rate_limit(red, client_ip)
    if ngx.var.is_bad_bot ~= "1" then
        return false
    end

    local key = "waf:botlimit:" .. client_ip
    local count, err = red:incr(key)
    if not count then
        return false -- fail open on a Redis error, consistent with every other check here
    end
    if count == 1 then
        red:expire(key, BAD_BOT_RATE_LIMIT_WINDOW_SECONDS)
    end
    return count > 1
end

local function check_adaptive_throttle(red, client_ip, ja4, asn)
    if ngx.var.waf_adaptive_throttle_enabled ~= "1" then
        return false
    end

    local rep = red:get("rep:" .. client_ip)
    local ip_rep = (rep ~= ngx.null and rep) and tonumber(rep) or nil

    local ja4_rep = nil
    if ja4 then
        local jrep = red:get("rep:ja4:" .. ja4)
        ja4_rep = (jrep ~= ngx.null and jrep) and tonumber(jrep) or nil
    end

    local asn_rep = nil
    if asn then
        local arep = red:get("rep:asn:" .. asn)
        asn_rep = (arep ~= ngx.null and arep) and tonumber(arep) or nil
    end

    local elevated = (ip_rep and ip_rep >= ADAPTIVE_THROTTLE_REP_THRESHOLD)
        or (ja4_rep and ja4_rep >= ADAPTIVE_THROTTLE_REP_THRESHOLD)
        or (asn_rep and asn_rep >= ADAPTIVE_THROTTLE_ASN_REP_THRESHOLD)
    if not elevated then
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

-- Verified-good-bot allowlist (Settings > Hardening -> good_bot_service.py
-- syncs each crawler's own officially-published IP ranges into Redis).
-- The User-Agent string alone ("Googlebot/2.1") is trivially spoofable by
-- anyone, so it is NEVER sufficient on its own — this only returns true
-- when the UA claims a known crawler AND the request's source IP actually
-- falls inside that specific crawler's own published range. Only ever
-- exempts the adaptive reputation throttle above (a real crawler's fast,
-- referrer-less, sequential crawl pattern is exactly the shape that check
-- is designed to flag) — it never touches check_ip_auth's blacklist tiers,
-- check_ja4_block, check_geo_block, or ModSecurity/CRS's own attack-
-- pattern rules, all of which still apply in full to verified-bot traffic.
local GOOD_BOT_UA_SOURCES = {
    { pattern = "Googlebot", source = "googlebot" },
    { pattern = "bingbot",   source = "bingbot" },
}

local function check_good_bot(red, client_ip, ua)
    -- $waf_good_bot_enabled is written by nginx_manager.apply_ddos_settings()
    -- (the same map block as $waf_adaptive_throttle_enabled) — but unlike
    -- that one, this map didn't exist in any previously-generated config,
    -- so on a fresh deploy it isn't declared anywhere in the live nginx
    -- config until an admin saves DDoS/Bot or Good-Bot settings at least
    -- once. Reading ngx.var.X for a name never referenced anywhere in the
    -- config is documented to raise a Lua runtime error, not return nil —
    -- pcall-guarded so a deploy-before-first-save window fails open
    -- (skip the exemption) instead of 500ing every request.
    local ok, enabled = pcall(function() return ngx.var.waf_good_bot_enabled end)
    if not ok or enabled ~= "1" then
        return false
    end
    if not ua or ua == "" then
        return false
    end
    local client_ip_int = ip_to_int(client_ip)
    if not client_ip_int then
        return false
    end
    for _, entry in ipairs(GOOD_BOT_UA_SOURCES) do
        if string.find(ua, entry.pattern, 1, true) then
            local cidrs, err = red:smembers("waf:goodbot:cidrs:" .. entry.source)
            if cidrs and #cidrs > 0 and match_cidrs(client_ip_int, cidrs) then
                return true
            end
        end
    end
    return false
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
            ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=ip_blacklist code=403 client=", client_ip, " uri=", ngx.var.uri or "")
            red:set_keepalive(10000, 100)
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (IP Access Denied)</p>")
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        -- Fetched once, shared by check_ja4_block() and
        -- check_adaptive_throttle() below, rather than each issuing its
        -- own GET for the same key.
        local ja4 = red:get("ja4:" .. client_ip)
        if ja4 == ngx.null then
            ja4 = nil
        end

        if check_ja4_block(red, ja4) then
            ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=ja4 code=403 client=", client_ip, " uri=", ngx.var.uri or "")
            red:set_keepalive(10000, 100)
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (TLS Fingerprint)</p>")
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        if check_geo_block(red) then
            ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=geo_block code=403 client=", client_ip, " uri=", ngx.var.uri or "")
            red:set_keepalive(10000, 100)
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.say("<h1>403 Forbidden</h1><p>Blocked by WAF (Geo-Restriction)</p>")
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        -- Checked once, ahead of the throttle it exempts from — a verified
        -- crawler's own request shape (fast, sequential, no referrer) is
        -- exactly what that throttle is designed to catch, so skip it
        -- entirely for one rather than let it accrue toward the same
        -- per-IP counter as anyone else.
        local is_good_bot = check_good_bot(red, client_ip, ngx.var.http_user_agent)

        -- Everything from here down is behavioural/heuristic rather than an
        -- explicit operator policy, so it is the only part the control-plane
        -- exemption list may skip (see skip_behavioral_checks above). The
        -- policy checks that ran before this point — IP allow/deny, feed,
        -- JA4, geo, and mTLS further up — are never skipped on either plane.
        if not skip_behavioral_checks then

        if not is_good_bot and check_adaptive_throttle(red, client_ip, ja4, get_request_asn()) then
            -- See the WAF-LUA-BLOCK comment on the mTLS check above for
            -- what this tag is for. ddos_analytics.py additionally parses
            -- this same format for the DDoS & Bot Shield page's own
            -- figures, filtered to the reasons its settings control
            -- (rate_limit/adaptive_throttle/api_enum) — without this line,
            -- an admin enabling adaptive throttle would never see any
            -- evidence it did anything on the very page that controls it
            -- (real gap, found 2026-09-04).
            ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=adaptive_throttle code=429 client=", client_ip, " uri=", ngx.var.uri or "")
            red:set_keepalive(10000, 100)
            ngx.status = 429
            ngx.header["Retry-After"] = "60"
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.say("<h1>429 Too Many Requests</h1><p>Slow down — rate limited by WAF. Retry after 60s.</p>")
            ngx.exit(429)
        end

        -- Bad-bot-UA rate limit (DDoS & Bot Shield > Bot Mitigation
        -- Action). $waf_bot_mitigation_status is written by
        -- nginx_manager.apply_ddos_settings() ("map $host", same trick as
        -- $waf_adaptive_throttle_enabled above) — pcall-guarded the same
        -- way $waf_good_bot_enabled is above, since it won't exist until an
        -- admin has saved DDoS & Bot Shield settings at least once. 0 means
        -- JS Challenge mode (or any future off-state): bot_challenge.lua
        -- handles bad-bot UAs itself in that mode, so this must not also
        -- reject the same request.
        local status_ok, bot_status = pcall(function()
            return tonumber(ngx.var.waf_bot_mitigation_status)
        end)
        if status_ok and bot_status and bot_status > 0 and check_bad_bot_rate_limit(red, client_ip) then
            -- See the WAF-LUA-BLOCK comment on the mTLS check above for
            -- what this tag is for; ddos_analytics.py and
            -- nginx_errorlog_parser.py both recognize reason=bot_ua_limit.
            ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=bot_ua_limit code=", bot_status, " client=", client_ip, " uri=", ngx.var.uri or "")
            red:set_keepalive(10000, 100)
            if bot_status == 429 then
                ngx.status = 429
                ngx.header["Retry-After"] = "60"
                ngx.header.content_type = "text/html; charset=UTF-8"
                ngx.say("<h1>429 Too Many Requests</h1><p>Slow down — rate limited by WAF. Retry after 60s.</p>")
            end
            -- 444 (Silent Drop) sends no headers/body at all — that's the
            -- whole point of the code, same as nginx's native handling.
            ngx.exit(bot_status)
        end

        -- Positive-security API schema check (Settings > per-app "API
        -- Schema"). No-ops unless this host has a schema configured AND the
        -- request matches one of its declared endpoints. Exits internally
        -- (400) in "enforce" mode on a violation; releases its own
        -- keepalive first since it may not return.
        schema_validate.check(red)

        -- Sequential API-ID enumeration detection (DDoS & Bot Shield
        -- settings). Skipped for a verified good bot, same reasoning as
        -- check_adaptive_throttle above — a real crawler sequentially
        -- walking numbered resource pages (e.g. a sitemap crawl) is
        -- legitimate traffic shaped exactly like the pattern this check
        -- looks for.
        if not is_good_bot then
            enum_detect.check(red, client_ip)
        end

        -- Opt-in JS Challenge bot mitigation (DDoS & Bot Shield settings).
        -- No-ops immediately unless both the feature is enabled AND this
        -- request's UA matched the existing bad-bot signal — reuses the
        -- same connected Redis client, releasing it itself if it serves
        -- the interstitial and exits.
        bot_challenge.check(red, client_ip)

        end -- if not skip_behavioral_checks
    end
    red:set_keepalive(10000, 100)
end

-- CRS score read + ML /predict call + block/challenge decision: see
-- ml_decide.lua (content phase, run per-location via content_by_lua_file).
