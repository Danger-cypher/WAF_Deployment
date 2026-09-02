-- ja4.lua — CyberSentinel WAF
-- ============================================================================
-- Computes a JA4 TLS-client fingerprint (FoxIO spec) from the live
-- ClientHello via OpenResty's official ngx.ssl.clienthello API — no custom
-- C module, no OpenSSL patch, no OpenResty upgrade: this API has shipped
-- since OpenResty 1.21.4.1 (May 2022), and this deployment runs 1.25.3.2.
--
-- Must be called from `ssl_client_hello_by_lua_block` — the only phase
-- ngx.ssl.clienthello's functions work in, since that's before OpenSSL has
-- finished processing the ClientHello into a normal SSL session.
--
-- Phase 1, capture only: this module computes and stores a fingerprint per
-- connection. Nothing reads it yet — no blocking, challenging, or scoring
-- decision is wired to it. That's deliberate: unlike bot_challenge.lua's
-- waf_bot_challenge_enabled or ml_check.lua's
-- waf_adaptive_throttle_enabled, there's no settings-driven enable/disable
-- toggle here, because there's no user-visible behavior to gate — this
-- never blocks, delays, or challenges a real connection, only writes a
-- Redis key. The enforcement side (what to actually DO with a fingerprint
-- — known-bad JA4 blocklist, anomaring diversity-per-IP, etc.) is
-- unbuilt and scoped separately; add a real toggle when that lands, the
-- same way every other opt-in mechanism in this codebase has one.
--
-- The whole computation is pcall-wrapped: this runs on every TLS
-- handshake, and an uncaught Lua error here would fail the handshake for
-- every client, not just log a warning — the one failure mode worse than
-- "no fingerprint captured" for a WAF.
--
-- See ja4_core.lua for the actual JA4 algorithm (verified against FoxIO's
-- published test vector — see test_ja4_core.lua) and its header comment
-- for the one accepted simplification (no legacy_version fallback path).
--
-- package.path is set by ja4_entry.lua (this module's sole caller), not
-- here — matching bot_challenge.lua/schema_validate.lua/waf_redis.lua,
-- which are required modules and don't repeat it either.

local ja4_core = require("ja4_core")
local waf_redis = require("waf_redis")
local ssl_clt = require("ngx.ssl.clienthello")
local resty_sha256 = require("resty.sha256")
local resty_str = require("resty.string")

local M = {}

local EXT_SNI = 0
local EXT_ALPN = 16
local EXT_SIGALGS = 13

-- Redis key TTL for a captured fingerprint — long enough to outlive one
-- HTTP request on the connection it was captured for (ml_check.lua reads
-- it back per-request via the same client IP key), short enough that a
-- stale/reused IP eventually falls back to "no fingerprint" rather than
-- serving an old client's data indefinitely. Matches the scale of this
-- codebase's other short-lived per-IP Redis state (e.g.
-- bot_challenge.lua's 1-hour PASSED_TTL_SECONDS is longer because that's
-- a deliberate grace period, not a freshness bound).
local FINGERPRINT_TTL_SECONDS = 300

local byte = string.byte

-- ALPN extension payload: 2-byte protocol_name_list length, then repeated
-- (1-byte name length + name bytes) entries. Only the first entry is
-- needed for JA4's "first ALPN value" field.
local function first_alpn_name(raw)
  if not raw or #raw < 3 then return nil end
  local name_len = byte(raw, 3)
  if not name_len or name_len == 0 then return nil end
  if 3 + name_len > #raw then return nil end -- truncated/malformed — fail safe, not fail loud
  return raw:sub(4, 3 + name_len)
end

-- signature_algorithms extension payload: 2-byte list length (in bytes),
-- then that many bytes as 2-byte SignatureScheme values, in the order the
-- client sent them (JA4 keeps this list unsorted, unlike ciphers/extensions).
local function sig_algs_list(raw)
  if not raw or #raw < 2 then return {} end
  local list_len = byte(raw, 1) * 256 + byte(raw, 2)
  local out = {}
  local i = 3
  while i + 1 <= 2 + list_len and i + 1 <= #raw do
    local v = byte(raw, i) * 256 + byte(raw, i + 1)
    if not ja4_core.is_grease(v) then
      out[#out + 1] = v
    end
    i = i + 2
  end
  return out
end

local function sha256_12(input_str)
  local sha = resty_sha256:new()
  sha:update(input_str)
  local digest = sha:final()
  return resty_str.to_hex(digest):sub(1, 12)
end

local function compute()
  local ciphers = ssl_clt.get_client_hello_ciphers()
  local exts = ssl_clt.get_client_hello_ext_present()
  if not ciphers or not exts then
    return nil, "get_client_hello_ciphers/ext_present returned nothing"
  end

  local sni = ssl_clt.get_client_hello_server_name()
  local versions = ssl_clt.get_supported_versions()

  local has_alpn, has_sigalgs = false, false
  for _, e in ipairs(exts) do
    if e == EXT_ALPN then has_alpn = true end
    if e == EXT_SIGALGS then has_sigalgs = true end
  end

  local first_alpn = nil
  if has_alpn then
    first_alpn = first_alpn_name(ssl_clt.get_client_hello_ext(EXT_ALPN))
  end

  local sigalgs = {}
  if has_sigalgs then
    sigalgs = sig_algs_list(ssl_clt.get_client_hello_ext(EXT_SIGALGS))
  end

  local exts_filtered = {}
  for _, e in ipairs(exts) do
    if e ~= EXT_SNI and e ~= EXT_ALPN then
      exts_filtered[#exts_filtered + 1] = e
    end
  end

  local part_a = ja4_core.part_a({
    protocol = "t", -- this WAF terminates TLS over TCP only — no QUIC/DTLS listener exists
    version_list = versions,
    has_sni = sni ~= nil,
    cipher_count = #ciphers,
    ext_count = #exts, -- unfiltered count — SNI/ALPN are included in the count, excluded only from part C's hash
    first_alpn = first_alpn,
  })

  local b_input = ja4_core.part_b_input(ciphers)
  local part_b = b_input and sha256_12(b_input) or "000000000000"

  local c_input = ja4_core.part_c_input(exts_filtered, sigalgs)
  local part_c = c_input and sha256_12(c_input) or "000000000000"

  return part_a .. "_" .. part_b .. "_" .. part_c
end

-- Call from ssl_client_hello_by_lua_block. Stores the fingerprint in
-- Redis keyed by client IP; does nothing else. Never raises — any failure
-- (malformed ClientHello, Redis unavailable, an unexpected nil somewhere)
-- is logged and swallowed, exactly like every other check in
-- ml_check.lua/bot_challenge.lua fails open rather than fails the
-- connection.
function M.capture()
  local ok, result = pcall(compute)
  if not ok then
    ngx.log(ngx.WARN, "ja4.capture: computation error, skipping: ", tostring(result))
    return
  end
  if not result then
    return -- compute() itself returned nil (malformed/incomplete ClientHello) — nothing to store
  end

  local client_ip = ngx.var.remote_addr
  if not client_ip then
    return
  end

  local red = waf_redis.connect()
  if not red then
    return -- waf_redis.connect() already logs the degraded-mode marker
  end
  local set_ok, set_err = red:setex("ja4:" .. client_ip, FINGERPRINT_TTL_SECONDS, result)
  if not set_ok then
    ngx.log(ngx.WARN, "ja4.capture: failed to store fingerprint in Redis: ", tostring(set_err))
  end
  red:set_keepalive(10000, 100)
end

return M
