-- waf_redis.lua — CyberSentinel WAF
-- ============================================================================
-- Shared Redis connect+auth helper, used by both ml_check.lua (access phase:
-- IP/geo/schema/bot checks) and ml_decide.lua (content phase: CRS/ML
-- decision + risk-triggered challenge). Extracted so both phases open
-- connections the same way without duplicating the password/secret-file
-- fallback logic.
-- ============================================================================

local redis = require("resty.redis")

local M = {}

-- Rate-limits the degraded-mode log line via the shared dict declared in
-- nginx.conf (lua_shared_dict waf_state) — shared across all worker
-- processes, so this caps total log volume during an outage regardless of
-- how many workers are handling traffic, not just per-worker. Without
-- this, a sustained Redis outage under real traffic would log once per
-- request — this codebase's IP/geo/bot/schema checks all go through this
-- same connect(), so that's every single request.
--
-- Read by backend/app/services/redis_degraded_monitor.py, which tails
-- nginx's error log (already readable from the backend container — see
-- docker-compose.yml, the same volume log_ingestor reads ModSecurity
-- entries from) looking for this exact marker string, and feeds it into
-- the existing heartbeat_registry/alerting pipeline. heartbeat_registry
-- itself only covers tasks inside the backend process — this Lua-side log
-- line plus that Python-side tailer together are the bridge across the
-- container boundary, since Redis being down rules out using Redis itself
-- as that bridge.
local DEGRADED_LOG_MARKER = "ML-WAF-REDIS-DEGRADED"
local DEGRADED_LOG_RATE_LIMIT_SECONDS = 30

local function log_degraded(reason)
    local dict = ngx.shared.waf_state
    if dict then
        local last_logged = dict:get("redis_degraded_last_logged")
        local now = ngx.now()
        if last_logged and (now - last_logged) < DEGRADED_LOG_RATE_LIMIT_SECONDS then
            return
        end
        dict:set("redis_degraded_last_logged", now)
    end
    ngx.log(ngx.ERR, DEGRADED_LOG_MARKER, ": ", reason,
            " — IP/geo/bot/schema checks are failing open until Redis recovers.")
end

-- Opens and authenticates a new Redis client. Returns the connected+
-- authenticated client, or nil on failure (caller fails open).
function M.connect()
    local client = redis:new()
    client:set_timeouts(100, 100, 100) -- 100ms

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
    local ok, err = client:connect(redis_host, 6379)
    if not ok then
        log_degraded("Redis connect failed: " .. (err or "unknown"))
        return nil
    end
    if redis_password and redis_password ~= "" then
        local res, auth_err = client:auth(redis_password)
        if not res then
            log_degraded("Redis authentication failed: " .. (auth_err or "unknown"))
            return nil
        end
    end
    return client
end

return M
