-- ja4_entry.lua — CyberSentinel WAF
-- ============================================================================
-- ssl_client_hello_by_lua_file's entry point. Kept as a thin top-level
-- script (matching how ml_check.lua/ml_decide.lua are the entry points for
-- their own phases) rather than making ja4.lua itself do double duty as
-- both an entry point and a require()-able module — bot_challenge.lua,
-- schema_validate.lua, and waf_redis.lua are all required BY an entry
-- script the same way, this follows that same shape.
-- ============================================================================
package.path = "/opt/ml-waf/lualib/?.lua;/opt/ml-waf/?.lua;" .. package.path
require("ja4").capture()
