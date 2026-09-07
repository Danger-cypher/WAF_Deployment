-- Real-time sequential API-ID enumeration detection (Settings > DDoS & Bot
-- Shield -> api_enum_protection_enabled). Classic OWASP API1:2023 (Broken
-- Object Level Authorization) scanning pattern: hitting the same endpoint
-- template with monotonically stepping numeric IDs (/api/users/1,
-- /api/users/2, ...) from one client. Nothing else in this WAF looks at
-- request SEQUENCE across a client's own history — CRS/ModSecurity and the
-- ML engine both score one request at a time in isolation, so a scan that
-- never trips a single-request signature or anomaly score sails through.
--
-- Scoped deliberately narrow: only a URI that literally ENDS in a numeric
-- segment (the overwhelmingly common REST shape for "act on resource {id}")
-- is tracked at all — a numeric segment in the middle of the path (e.g.
-- /api/orgs/5/users) is left alone rather than guessed at.
--
-- Soft-throttles (429), not a hard block — this is untested against real
-- traffic (no reference data to tune it against, same caveat as the ASN
-- reputation threshold), so a false positive — a legitimate client
-- iterating its own paginated IDs, say — gets slowed down and can retry,
-- not locked out outright.
local _M = {}

local ENUM_STEP_MAX = 5           -- IDs within this delta of the last one count as "stepping"
local ENUM_STREAK_THRESHOLD = 8   -- this many consecutive stepping requests before flagging
local ENUM_KEY_TTL_SECONDS = 300  -- 5 min of inactivity resets the streak

function _M.check(red, client_ip)
    if ngx.var.waf_api_enum_enabled ~= "1" then
        return
    end

    local uri = ngx.var.uri or ""
    local id_str = uri:match("(%d+)$")
    if not id_str then
        return
    end
    local id_num = tonumber(id_str)
    if not id_num then
        return
    end

    -- Endpoint template: the same path with every numeric segment
    -- generalized, so /api/users/1 and /api/users/2 land on the same
    -- tracking key. Hashed (not stored verbatim) to keep the Redis key
    -- short and avoid any odd-character edge cases in the raw path.
    local template = uri:gsub("%d+", "{n}")
    local key = "waf:enum:" .. client_ip .. ":" .. ngx.md5(template)

    local vals, err = red:hmget(key, "last_id", "streak")
    if not vals then
        return -- fail open on a Redis error, consistent with every other check here
    end
    local prev = (vals[1] and vals[1] ~= ngx.null) and tonumber(vals[1]) or nil
    local streak = (vals[2] and vals[2] ~= ngx.null) and tonumber(vals[2]) or 0

    local new_streak
    if prev and prev ~= id_num and math.abs(id_num - prev) <= ENUM_STEP_MAX then
        new_streak = streak + 1
    else
        new_streak = 1
    end

    red:hset(key, "last_id", id_num)
    red:hset(key, "streak", new_streak)
    red:expire(key, ENUM_KEY_TTL_SECONDS)

    if new_streak < ENUM_STREAK_THRESHOLD then
        return
    end

    -- WAF-LUA-BLOCK: same consistent tag ml_check.lua's blocking checks
    -- log (see the mTLS check's comment there for the full explanation).
    -- ddos_analytics.py additionally greps this exact format for the
    -- DDoS & Bot Shield page's own figures.
    ngx.log(ngx.WARN, "WAF-LUA-BLOCK reason=api_enum code=429 client=", client_ip,
        " uri=", uri, " streak=", new_streak, " last_id=", id_num)

    -- Same convention as bot_challenge.check()/schema_validate.check():
    -- release the shared connection ourselves before an exit the caller's
    -- own set_keepalive() further down will never reach.
    red:set_keepalive(10000, 100)
    ngx.status = 429
    ngx.header["Retry-After"] = "30"
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.say("<h1>429 Too Many Requests</h1><p>Sequential access pattern detected — slow down.</p>")
    ngx.exit(429)
end

return _M
