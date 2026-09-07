-- test_ja4_core.lua — plain luajit test, no OpenResty/nginx runtime
-- needed. Run with: luajit test_ja4_core.lua
--
-- Validates ja4_core.lua against FoxIO's own published worked example
-- (github.com/FoxIO-LLC/ja4, technical_details/JA4.md) — the hex field
-- values from that doc, converted to the decimal form ngx.ssl.clienthello
-- actually returns, must reproduce their published fingerprint
-- "t13d1516h2_8daaf6152771_e5627efa2ab1" exactly (part_a string-for-string,
-- and the two hash INPUT strings — sha256+truncate of those inputs is
-- verified separately in Python since resty.sha256 needs OpenResty's
-- runtime; SHA256 itself is standard and not re-verified here).

package.path = package.path .. ";./?.lua"
local ja4 = require("ja4_core")

local ciphers = {4865,4866,4867,49195,49199,49196,49200,52393,52392,49171,49172,156,157,47,53}
local exts_with_sni_alpn = {27,0,51,16,17513,23,45,13,5,35,18,43,65281,11,10,21}
local sigalgs = {1027,2052,1025,1283,2053,1281,2054,1537}
local version_list = {0x0304}
local first_alpn = "h2"

local exts_filtered = {}
for _, v in ipairs(exts_with_sni_alpn) do
  if v ~= 0 and v ~= 16 then table.insert(exts_filtered, v) end
end

local part_a = ja4.part_a({
  protocol = "t", version_list = version_list, has_sni = true,
  cipher_count = #ciphers, ext_count = #exts_with_sni_alpn, first_alpn = first_alpn,
})
local part_b_input = ja4.part_b_input(ciphers)
local part_c_input = ja4.part_c_input(exts_filtered, sigalgs)

local EXPECTED_A = "t13d1516h2"
local EXPECTED_B_INPUT = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
local EXPECTED_C_INPUT = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"

local failures = 0
local function check(name, got, want)
  if got ~= want then
    failures = failures + 1
    print(string.format("FAIL %s:\n  got:  %s\n  want: %s", name, tostring(got), tostring(want)))
  end
end

check("part_a", part_a, EXPECTED_A)
check("part_b_input", part_b_input, EXPECTED_B_INPUT)
check("part_c_input", part_c_input, EXPECTED_C_INPUT)

-- Edge cases
local function assert_eq(name, got, want)
  if got ~= want then
    failures = failures + 1
    print(string.format("FAIL %s: got %s want %s", name, tostring(got), tostring(want)))
  end
end
assert_eq("alpn nil", ja4.alpn_code(nil), "00")
assert_eq("alpn empty", ja4.alpn_code(""), "00")
assert_eq("alpn h2", ja4.alpn_code("h2"), "h2")
assert_eq("version nil list", ja4.version_code(nil), "00")
assert_eq("version all-GREASE", ja4.version_code({0x0a0a}), "00")
assert_eq("version GREASE excluded", ja4.version_code({0x0a0a, 0x0303}), "12")
assert_eq("grease detected", ja4.is_grease(0xaaaa), true)
assert_eq("non-grease not flagged", ja4.is_grease(0x1301), false)
assert_eq("empty ciphers -> nil", ja4.part_b_input({}), nil)
assert_eq("empty exts -> nil", ja4.part_c_input({}, {1,2}), nil)
assert_eq("no sigalgs omits trailing underscore",
  ja4.part_c_input({5, 10}, {}), "0005,000a")

if failures == 0 then
  print("ALL CHECKS PASSED (" .. "ja4_core.lua matches FoxIO's published JA4 test vector)")
  os.exit(0)
else
  print(failures .. " CHECK(S) FAILED")
  os.exit(1)
end
