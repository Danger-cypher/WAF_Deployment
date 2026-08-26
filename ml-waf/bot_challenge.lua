-- bot_challenge.lua — CyberSentinel WAF
-- ============================================================================
-- Opt-in "JS Challenge" bot mitigation mode (DDoS & Bot Shield > Mitigation
-- Action). Serves an interstitial to traffic matching the existing bad-bot
-- User-Agent signal ($is_bad_bot, defined in the generated waf_ddos.conf)
-- instead of an outright reject:
--
--   1. First hit from a client with no "passed" marker -> served this page.
--      The page's own JS reloads itself once, appending ?waf_challenge_ack=1.
--   2. A real browser executes that JS automatically (~600ms) and reloads;
--      this module sees the ack param, marks the IP as passed in Redis
--      (1 hour TTL), and lets the (now-reloaded) request through normally.
--   3. A scripted client (curl, sqlmap, python-requests, etc.) has no JS
--      engine, never sends the reload, and never gets past this page — no
--      403/429 is ever returned, so it can't tell which control caught it.
--
-- Required because of a real interaction with the EXISTING bad-bot rate
-- limit: waf_ddos.conf's waf_bot_req zone allows only 1 request/minute per
-- bad-bot-matching client, which would reject the JS-triggered reload
-- (request #2) before this module ever saw it. nginx_manager.py's
-- apply_ddos_settings() skips applying that zone whenever this mode is
-- selected, making this module the sole gate for that traffic instead.
--
-- Called from ml_check.lua, reusing its already-connected/authenticated
-- Redis client — this module does not open its own connection.
-- ============================================================================

local M = {}

local PASSED_TTL_SECONDS = 3600 -- 1 hour

local CHALLENGE_HTML = [[<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<title>Just a moment...</title>
</head>
<body style="background:#0b0f19;color:#e5e7eb;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
<div style="text-align:center;">
<div style="font-size:15px;">Verifying your browser...</div>
</div>
<script>
setTimeout(function () {
    var u = new URL(window.location.href);
    u.searchParams.set('waf_challenge_ack', '1');
    window.location.replace(u.toString());
}, 600);
</script>
</body>
</html>]]

local function serve_challenge_page(red)
    -- Release the connection back to the pool before exiting — mirrors
    -- every other ngx.exit() path in ml_check.lua (e.g. its blacklist
    -- branch). Only done on THIS path; the plain `return` paths below
    -- leave the connection alone since the caller (ml_check.lua) still
    -- has its own work left to do with it.
    red:set_keepalive(10000, 100)
    ngx.status = ngx.HTTP_OK
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say(CHALLENGE_HTML)
    ngx.exit(ngx.HTTP_OK)
end

-- red: an already-connected, already-authenticated resty.redis instance.
--      Ownership: a plain `return` from this function leaves the
--      connection alone for the caller to keep using/release; the
--      serve_challenge_page() exit path releases it itself (see above).
-- client_ip: ngx.var.remote_addr, already resolved by the caller.
function M.check(red, client_ip)
    if ngx.var.waf_bot_challenge_enabled ~= "1" then
        return -- feature disabled globally
    end
    if ngx.var.is_bad_bot ~= "1" then
        return -- only applies to the existing bad-bot UA signal
    end

    local passed_key = "waf:challenge_passed:" .. client_ip

    -- Request #2: the challenge page's own self-triggered reload. Mark this
    -- IP as passed and let the request through as-is — the extra query
    -- param rides along to the upstream app harmlessly (a clean redirect to
    -- strip it would cost an extra round trip for no real benefit here).
    if ngx.var.arg_waf_challenge_ack then
        local ok, err = red:setex(passed_key, PASSED_TTL_SECONDS, "1")
        if not ok then
            ngx.log(ngx.WARN, "bot_challenge: failed to record pass for ", client_ip, ": ", err)
        end
        return
    end

    -- Already passed within the TTL window — skip straight through.
    local passed, err = red:get(passed_key)
    if passed and passed ~= ngx.null then
        return
    end

    serve_challenge_page(red)
end

-- Second, independent trigger for the same interstitial mechanics: a
-- moderate-but-not-certain ML risk score (threat_score.py's "log" band)
-- instead of the bad-bot UA signal M.check() above gates on. Deliberately
-- NOT sharing M.check()'s body — this is a second, unrelated caller
-- (ml_check.lua, after its /predict call, on its own fresh Redis
-- connection) and duplicating the ~15 lines here keeps that addition from
-- being able to affect the already-proven bad-bot path at all.
--
-- Own enabled-check (waf_risk_challenge_enabled) and own pass-tracking key
-- namespace (waf:risk_challenge_passed:*, not waf:challenge_passed:*) — a
-- client that already cleared the bad-bot challenge doesn't automatically
-- skip this one, and vice versa; they're answering different questions.
function M.check_risk_triggered(red, client_ip)
    if ngx.var.waf_risk_challenge_enabled ~= "1" then
        return
    end

    local passed_key = "waf:risk_challenge_passed:" .. client_ip

    if ngx.var.arg_waf_challenge_ack then
        local ok, err = red:setex(passed_key, PASSED_TTL_SECONDS, "1")
        if not ok then
            ngx.log(ngx.WARN, "bot_challenge (risk-triggered): failed to record pass for ", client_ip, ": ", err)
        end
        return
    end

    local passed, err = red:get(passed_key)
    if passed and passed ~= ngx.null then
        return
    end

    serve_challenge_page(red)
end

return M
