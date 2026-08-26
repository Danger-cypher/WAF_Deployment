-- Per-app positive-security API schema enforcement (roadmap item: API
-- schema validation). Declares known-good endpoints (method/path + required/
-- allowed JSON body fields) per protected app; everything else in this WAF
-- is negative-security (CRS signatures, ML anomaly scoring) — this is the
-- one layer that says "reject anything that isn't shaped like what we
-- expect" instead of "reject anything that looks like a known attack".
--
-- Config source of truth is routes/apps.py's PUT /apps/{app_id}/schema,
-- pushed to Redis by nginx_manager.apply_api_schema_settings() keyed by
-- domain (waf:schema:<host>) — no app_id lookup needed here, $host is
-- already cheap to read. Absence of a key for the current host is the
-- overwhelmingly common case (dashboard traffic, any app with no schema
-- configured) and must be a fast no-op.
--
-- Only requests matching a DECLARED endpoint (exact method+path) are
-- checked at all — an unlisted endpoint passes through untouched, same
-- "absence never means deny-all" convention as Positive Security
-- (nginx_manager.apply_positive_security_settings).
local cjson = require("cjson")

local _M = {}

local function find_endpoint(endpoints, method, uri)
    for _, ep in ipairs(endpoints) do
        if ep.method == method and ep.path == uri then
            return ep
        end
    end
    return nil
end

function _M.check(red)
    local host = ngx.var.host or ""
    if host == "" then
        return
    end

    local raw = red:get("waf:schema:" .. host)
    if not raw or raw == ngx.null then
        return
    end

    local decode_ok, schema = pcall(cjson.decode, raw)
    if not decode_ok or type(schema) ~= "table" or type(schema.endpoints) ~= "table" then
        return
    end

    local method = ngx.req.get_method()
    local uri = ngx.var.uri or ""
    local endpoint = find_endpoint(schema.endpoints, method, uri)
    if not endpoint then
        return
    end

    -- Field-level checks only make sense for a JSON body — anything else
    -- (form-encoded, multipart, no body) isn't in scope for this check.
    local content_type = ngx.var.content_type or ""
    if not content_type:find("application/json", 1, true) then
        return
    end

    ngx.req.read_body()
    local body_data = ngx.req.get_body_data()
    if not body_data then
        return
    end

    local body_ok, body = pcall(cjson.decode, body_data)
    if not body_ok or type(body) ~= "table" then
        -- Malformed JSON is CRS/ModSecurity's job to flag, not this check's.
        return
    end

    local violations = {}

    for _, field in ipairs(endpoint.required_fields or {}) do
        if body[field] == nil then
            table.insert(violations, "missing required field: " .. field)
        end
    end

    local allowed_fields = endpoint.allowed_fields or {}
    if #allowed_fields > 0 then
        local allowed = {}
        for _, f in ipairs(allowed_fields) do
            allowed[f] = true
        end
        for k, _ in pairs(body) do
            if not allowed[k] then
                table.insert(violations, "unexpected field: " .. k)
            end
        end
    end

    -- Type/enum/length checks — presence and allowlist membership alone
    -- let a field declared as "expects a number" accept a SQL fragment.
    -- Only runs for fields the endpoint actually declares a field_types
    -- entry for; every other field keeps today's presence/allowlist-only
    -- behavior. A field that's absent here is the required-fields check's
    -- job above, not this one's — skip fields not present in body.
    local field_types = endpoint.field_types or {}
    for field, spec in pairs(field_types) do
        local value = body[field]
        if value ~= nil then
            local lua_type = type(value)
            -- cjson decodes a JSON null to the cjson.null sentinel
            -- (lightuserdata) — that's neither a string, number, nor
            -- boolean, so it naturally fails any declared type below
            -- rather than needing special-cased handling.
            if spec.type == "string" and lua_type ~= "string" then
                table.insert(violations, "field '" .. field .. "' must be a string")
            elseif spec.type == "number" and lua_type ~= "number" then
                table.insert(violations, "field '" .. field .. "' must be a number")
            elseif spec.type == "boolean" and lua_type ~= "boolean" then
                table.insert(violations, "field '" .. field .. "' must be a boolean")
            elseif spec.type == "enum" and spec.enum then
                local matched = false
                for _, allowed_value in ipairs(spec.enum) do
                    if allowed_value == value then
                        matched = true
                        break
                    end
                end
                if not matched then
                    table.insert(violations, "field '" .. field .. "' is not one of the allowed values")
                end
            end

            if lua_type == "string" then
                if spec.max_length and #value > spec.max_length then
                    table.insert(violations, "field '" .. field .. "' exceeds max length " .. spec.max_length)
                end
                if spec.pattern and spec.pattern ~= "" then
                    local match_ok, matched_or_err = pcall(ngx.re.match, value, spec.pattern, "jo")
                    if not match_ok or not matched_or_err then
                        table.insert(violations, "field '" .. field .. "' does not match the required pattern")
                    end
                end
            end
        end
    end

    if #violations == 0 then
        return
    end

    if schema.mode == "enforce" then
        ngx.log(ngx.WARN, "API schema violation (enforced) for ", host, " ", method, " ", uri,
            ": ", table.concat(violations, "; "))
        -- Same convention as bot_challenge.check(): release the shared
        -- connection back to the keepalive pool ourselves before an exit
        -- the caller's own set_keepalive() further down will never reach.
        red:set_keepalive(10000, 100)
        ngx.status = 400
        ngx.header.content_type = "application/json; charset=UTF-8"
        ngx.say(cjson.encode({
            error = "Request does not match the declared API schema.",
            violations = violations,
        }))
        ngx.exit(400)
    else
        ngx.log(ngx.WARN, "API schema violation (log-only) for ", host, " ", method, " ", uri,
            ": ", table.concat(violations, "; "))
    end
end

return _M
