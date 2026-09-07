-- ja4_core.lua — CyberSentinel WAF
-- ============================================================================
-- Pure JA4 (TLS client fingerprint, FoxIO spec) string construction —
-- deliberately decoupled from ngx.ssl.clienthello and resty.sha256 so it
-- can be unit-tested with plain luajit, no nginx/SSL runtime required.
-- ja4.lua (the nginx-integration layer, calling ngx.ssl.clienthello.* on a
-- live ClientHello) is a thin adapter around this module, not a second
-- copy of the logic — one place the actual algorithm lives.
--
-- JA4 was chosen over the older JA3 deliberately: JA3 hashes fields in the
-- exact order the client sent them, which Chrome/Firefox's GREASE
-- mechanism (RFC 8701 — randomized fake values, standard since 2020)
-- breaks by design, making JA3 an unreliable, spoofable signal today. JA4
-- sorts before hashing specifically to resist that.
--
-- Verified against FoxIO's own published worked example
-- (github.com/FoxIO-LLC/ja4, technical_details/JA4.md): the exact input
-- field values from that example, run through this module, reproduce
-- their published output "t13d1516h2_8daaf6152771_e5627efa2ab1" byte for
-- byte — see ml-waf/test_ja4_core.lua.
--
-- Known, accepted simplification: JA4's spec falls back to the ClientHello
-- legacy_version field when the supported_versions (0x002b) extension is
-- absent. ngx.ssl.clienthello exposes per-extension access but no raw
-- whole-message accessor for that legacy field, so that fallback path
-- isn't implemented — version_code() returns "00" (unknown) in that case
-- instead. In practice this only affects clients old enough to predate
-- TLS 1.3's extension (pre-2018), not the modern evasive-bot traffic this
-- feature targets.

local M = {}

-- The 16 fixed GREASE values (RFC 8701) — Google's client-extensibility
-- probe values, always excluded from every JA4 field per spec.
local GREASE = {}
for _, v in ipairs({0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,
                     0x8a8a,0x9a9a,0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa}) do
  GREASE[v] = true
end
M.GREASE = GREASE

local function is_grease(v) return GREASE[v] == true end
M.is_grease = is_grease

local function hex4(n) return string.format("%04x", n) end

local VERSION_MAP = {
  [0x0304] = "13", [0x0303] = "12", [0x0302] = "11", [0x0301] = "10",
  [0x0300] = "s3", [0x0002] = "s2",
  [0xfeff] = "d1", [0xfefd] = "d2", [0xfefc] = "d3",
}

-- version_list: plain array of decimal version values, as returned by
-- ngx.ssl.clienthello's get_supported_versions() — GREASE is NOT
-- documented as pre-excluded by that function (unlike the cipher/extension
-- getters, which explicitly say they strip it), so it's filtered
-- defensively here rather than assumed clean.
function M.version_code(version_list)
  if not version_list or #version_list == 0 then return "00" end
  local max_v = nil
  for _, v in ipairs(version_list) do
    if not is_grease(v) and (not max_v or v > max_v) then max_v = v end
  end
  if not max_v then return "00" end
  return VERSION_MAP[max_v] or "00"
end

local function alpn_char(c)
  local b = string.byte(c)
  if (b >= 48 and b <= 57) or (b >= 97 and b <= 122) or (b >= 65 and b <= 90) then
    return c:lower()
  end
  return string.format("%02x", b)
end

-- first_alpn: the raw first ALPN protocol-name string (already extracted
-- from the raw extension bytes by ja4.lua). "00" for absent/empty per
-- spec; a 1-character value uses that same char as both first and last.
function M.alpn_code(first_alpn)
  if not first_alpn or #first_alpn == 0 then return "00" end
  local first = alpn_char(first_alpn:sub(1, 1))
  local last = alpn_char(first_alpn:sub(-1))
  return first .. last
end

-- opts.cipher_count / opts.ext_count: raw counts, already GREASE-excluded
-- by the ngx.ssl.clienthello functions that produced them. ext_count
-- INCLUDES SNI/ALPN per spec — only part_c_input's hash excludes them,
-- not the count here.
function M.part_a(opts)
  local proto = opts.protocol or "t"
  local ver = M.version_code(opts.version_list)
  local sni = opts.has_sni and "d" or "i"
  local cc = math.min(opts.cipher_count or 0, 99)
  local ec = math.min(opts.ext_count or 0, 99)
  local alpn = M.alpn_code(opts.first_alpn)
  return string.format("%s%s%s%02d%02d%s", proto, ver, sni, cc, ec, alpn)
end

-- Ascending-sorted, 4-char lowercase hex, comma-joined — part B's cipher
-- list and part C's extension list both use this same shape.
local function sorted_hex_join(dec_list)
  local copy = {}
  for i, v in ipairs(dec_list) do copy[i] = v end
  table.sort(copy)
  local hexed = {}
  for i, v in ipairs(copy) do hexed[i] = hex4(v) end
  return table.concat(hexed, ",")
end
M.sorted_hex_join = sorted_hex_join

-- Hex-joined in GIVEN (not sorted) order — part C's signature-algorithms
-- tail, which JA4 deliberately keeps in client-sent order.
local function original_hex_join(dec_list)
  local hexed = {}
  for i, v in ipairs(dec_list) do hexed[i] = hex4(v) end
  return table.concat(hexed, ",")
end
M.original_hex_join = original_hex_join

-- Pre-hash string for part B. sha256+truncate-12 is applied by ja4.lua
-- via resty.sha256, not here, so this module needs no OpenResty runtime.
-- Returns nil if there are no ciphers — caller uses the spec's
-- "000000000000" literal in that case.
function M.part_b_input(ciphers_dec)
  if not ciphers_dec or #ciphers_dec == 0 then return nil end
  return sorted_hex_join(ciphers_dec)
end

-- exts_dec_filtered must already have SNI(0)/ALPN(16) removed by the
-- caller — kept as the caller's job since ja4.lua also needs the
-- unfiltered list (for part A's extension count) and re-filtering twice
-- here would just be extra surface for the two counts to drift apart.
function M.part_c_input(exts_dec_filtered, sigalgs_dec)
  if not exts_dec_filtered or #exts_dec_filtered == 0 then return nil end
  local ext_part = sorted_hex_join(exts_dec_filtered)
  if sigalgs_dec and #sigalgs_dec > 0 then
    return ext_part .. "_" .. original_hex_join(sigalgs_dec)
  end
  return ext_part -- spec: omit the trailing underscore when there are no sig algos
end

return M
