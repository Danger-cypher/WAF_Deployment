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
-- This module computes and stores a fingerprint per connection; it never
-- blocks, delays, or challenges anything itself, only writes a Redis key.
-- There's deliberately no settings-driven enable/disable toggle here
-- (unlike bot_challenge.lua's waf_bot_challenge_enabled or ml_check.lua's
-- waf_adaptive_throttle_enabled) because capture itself has no
-- user-visible behavior to gate.
--
-- First consumer: ml_check.lua's check_ja4_block() reads this cached
-- fingerprint back and blocks it if it's in the admin-curated
-- waf:blacklist:ja4 set (Settings > Hardening). That's an exact-match
-- known-bad list only — reputation/diversity-based enforcement on top of
-- the fingerprint is unbuilt and scoped separately.
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

-- Capability probe, evaluated once per worker rather than per handshake.
--
-- The header comment above asserts that everything this module needs is part
-- of OpenResty's official ngx.ssl.clienthello API "since 1.21.4.1". That is
-- true of get_client_hello_server_name(), get_client_hello_ext(),
-- get_client_hello_ext_present() and get_supported_versions() — but NOT of
-- get_client_hello_ciphers(), which upstream lua-resty-core does not ship at
-- all. This image is stock openresty:1.25.3.2 plus two ModSecurity patches
-- (openresty/patches/), neither of which touches lua-resty-core.
--
-- So compute() called a nil field on every single TLS handshake. Because the
-- call is pcall-wrapped it never broke a connection — it just logged
-- "attempt to call field 'get_client_hello_ciphers' (a nil value)" and
-- returned no fingerprint, forever. Measured on the running deployment:
-- 956 handshakes, 956 errors, 0 fingerprints ever stored. Every downstream
-- consumer therefore degraded silently — ml_check.lua's check_ja4_block()
-- never had a fingerprint to match against the waf:blacklist:ja4 set, and
-- ml_decide.lua always sent ja4="" to the ML engine (audit finding P1-07).
--
-- The cipher list is not recoverable from the rest of the API: it lives in
-- the ClientHello body, not in an extension, so get_client_hello_ext() cannot
-- reach it. And JA4 needs it twice over — part B hashes it, and part A
-- encodes its length — so there is no reduced-but-still-JA4 fallback either.
-- Genuine JA4 support requires exposing the cipher list from the connector,
-- i.e. a third entry in openresty/patches/ and an image rebuild.
--
-- Until that exists, fail honestly: detect the missing capability once, say
-- so once at a severity an operator will actually see, and then no-op. A
-- security control that cannot work must announce that it is off, not
-- emit an error per request and let the dashboard imply it is running.
local _capability = nil -- nil = unprobed, true = usable, false = unavailable

local function ja4_supported()
  if _capability ~= nil then
    return _capability
  end
  if type(ssl_clt.get_client_hello_ciphers) ~= "function"
     or type(ssl_clt.get_client_hello_ext_present) ~= "function" then
    _capability = false
    ngx.log(ngx.CRIT,
      "ja4: DISABLED — this OpenResty build's ngx.ssl.clienthello does not expose ",
      "get_client_hello_ciphers(); the cipher list is required for JA4 parts A and B ",
      "and cannot be derived from the rest of the API. No TLS fingerprints will be ",
      "captured, so JA4 blocklisting (Settings > Hardening) will never match and the ",
      "ML engine will score every request with an empty ja4 feature. Fix: add a ",
      "lua-resty-core patch exposing the ClientHello cipher list under ",
      "openresty/patches/ and rebuild the openresty image. Logged once per worker.")
    return false
  end
  _capability = true
  return true
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
  -- Cheap boolean after the first handshake in each worker; keeps a build
  -- without cipher-list support from logging a stack trace per connection.
  if not ja4_supported() then
    return
  end

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
