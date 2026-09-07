"""
Regression tests for audit finding P1-04: the DDoS & Bot Shield's rate-limit
zones were configured but never evaluated a single request.

Two independent defects, both asserted here.

1. WRONG SCOPE. nginx does not merge limit_req across configuration levels —
   a location containing any limit_req directive REPLACES every inherited one
   rather than adding to it. apply_ddos_settings() emitted its limit_req lines
   at http level only, while every proxying location in the product declares
   its own zone (zone_app_<id> in generated app vhosts, api_limit/login_limit
   in the console vhost). So the whole page configured zones that applied to
   no traffic. Confirmed live before the fix: four consecutive requests with
   User-Agent "Wget/1.21" against a 1r/m zone all returned 200; after the fix
   the third was dropped.

   The fix emits the same directives a second time into
   DDOS_LIMITS_INCLUDE_PATH, which each generated location `include`s so they
   apply alongside its own zone.

2. WRONG KEY. The bad-bot zone was keyed on the constant string
   "bad_bot_key" — identical for every client on the internet — so
   limit_req_zone hashed all bad-bot traffic worldwide into ONE shared 1r/m
   bucket. A single attacker could exhaust it for everybody, and every
   legitimate client matching the bad-bot UA list was collectively capped at
   one request per minute across the entire deployment.

   Fixing defect 2 by keying limit_req_zone on $binary_remote_addr (instead
   of the constant string) surfaced a THIRD, worse defect covered by
   test_p2_07_bot_status.py's neighbor tests and touched on here only where
   it affects what this generator still emits: limit_req_status/
   limit_conn_status are single, shared-per-scope directives, not per-zone,
   so the bad-bot zone sharing a scope with waf_ddos_req meant the
   bot_mitigation_action dropdown ("Silent Drop" -> 444) was silently
   overriding the status code for every OTHER rate limit in the product too
   — login, API, per-app zones, all of it (audit finding P2-07). The bad-bot
   zone was removed from nginx entirely as part of that fix; see
   GENERAL_RATE_LIMIT_STATUS and bot_mitigation_status_code in
   nginx_manager.py, and ml_check.lua's check_bad_bot_rate_limit().
"""
import pytest

from app.services import nginx_manager


BASE_SETTINGS = {
    "rate_limit_rps": 50,
    "burst_tolerance": 100,
    "trusted_ips": [],
    "bot_mitigation_action": "Silent Drop",
    "advanced_rules": [],
}


def _generate(monkeypatch, settings=None):
    """Runs apply_ddos_settings() against a fake writer and returns every
    file it tried to write, keyed by path."""
    captured = {}

    def fake_write_and_apply(file_contents):
        captured.update(file_contents)
        return True, ""

    monkeypatch.setattr(nginx_manager, "write_and_apply_configs", fake_write_and_apply)
    ok, msg = nginx_manager.apply_ddos_settings(settings or dict(BASE_SETTINGS))
    assert ok, msg
    return captured


# --------------------------------------------------------------------------
# Defect 2 (historical) — the bad-bot zone this once tested no longer
# exists in nginx at all; see test_p2_07_bot_status.py for its replacement,
# ml_check.lua's check_bad_bot_rate_limit(), which keys on client_ip
# directly (never a shared constant — there's nothing here to key wrong).
# --------------------------------------------------------------------------

def test_bot_zone_never_uses_a_shared_constant_key(monkeypatch):
    conf = _generate(monkeypatch)[nginx_manager.DDOS_CONF_PATH]
    # The original bug, verbatim. A constant here would mean every bad bot
    # on the internet shares one bucket — confirms no trace of it survived
    # the later move to Lua either.
    assert "bad_bot_key" not in conf


# --------------------------------------------------------------------------
# Defect 1 — the limits must also be emitted for location scope
# --------------------------------------------------------------------------

def test_location_include_file_is_always_written(monkeypatch):
    # Generated vhosts include this path unconditionally; a missing include
    # file is a hard nginx startup failure, so it must exist even when the
    # bot zone is skipped or no advanced rules are configured.
    written = _generate(monkeypatch)
    assert nginx_manager.DDOS_LIMITS_INCLUDE_PATH in written
    assert written[nginx_manager.DDOS_LIMITS_INCLUDE_PATH].strip()


def test_location_include_carries_the_ddos_zone(monkeypatch):
    inc = _generate(monkeypatch)[nginx_manager.DDOS_LIMITS_INCLUDE_PATH]
    assert "limit_req zone=waf_ddos_req burst=100 nodelay;" in inc
    # Bad-bot traffic is handled in Lua now (see test_p2_07_bot_status.py),
    # not via a second limit_req zone spliced into every location.
    assert "waf_bot_req" not in inc


def test_location_include_is_not_picked_up_as_http_level_conf(monkeypatch):
    # nginx.conf does `include /etc/nginx/conf.d/*.conf` at http level. These
    # directives are only valid inside a location, so the file must not match
    # that glob or nginx refuses to start.
    assert not nginx_manager.DDOS_LIMITS_INCLUDE_PATH.endswith(".conf")
    assert nginx_manager.DDOS_LIMITS_INCLUDE_PATH.endswith(".inc")


def test_advanced_rule_zones_reach_location_scope_too(monkeypatch):
    # An admin's custom per-country/per-ISP/per-header rule was overridden at
    # http level for exactly the same reason as the two built-in zones.
    settings = dict(BASE_SETTINGS)
    # "URI", not "Country": Country rules are skipped entirely unless the
    # geoip2 module is enabled and the Country MMDB is present, which is an
    # environment dependency this test has no reason to take on.
    settings["advanced_rules"] = [
        {
            "id": "rule_uri_1",
            "name": "Throttle one path",
            "parameter_type": "URI",
            "parameter_value": "/expensive-endpoint",
            "rate_limit_rps": 5,
            "burst": 3,
            "enabled": True,
        }
    ]
    written = _generate(monkeypatch, settings)
    inc = written[nginx_manager.DDOS_LIMITS_INCLUDE_PATH]
    conf = written[nginx_manager.DDOS_CONF_PATH]
    # Zone declared at http level (limit_req_zone is only valid there)...
    assert "zone=zone_rule_uri_1:10m" in conf
    # ...but applied at location level as well.
    assert "limit_req zone=zone_rule_uri_1" in inc


def test_disabled_advanced_rule_is_not_applied(monkeypatch):
    settings = dict(BASE_SETTINGS)
    settings["advanced_rules"] = [
        {
            "id": "rule_off",
            "name": "Disabled rule",
            "parameter_type": "URI",
            "parameter_value": "/whatever",
            "rate_limit_rps": 5,
            "burst": 3,
            "enabled": False,
        }
    ]
    inc = _generate(monkeypatch, settings)[nginx_manager.DDOS_LIMITS_INCLUDE_PATH]
    assert "zone_rule_off" not in inc


def test_js_challenge_mode_disables_the_lua_bot_check(monkeypatch):
    # JS Challenge needs at least two requests from the same client in quick
    # succession (initial hit + the JS-triggered reload). check_bad_bot_rate_
    # limit()'s 1r/m equivalent would reject the reload before
    # bot_challenge.lua ever sees it, so this mode must disable that check
    # entirely — see test_p2_07_bot_status.py for the 0-means-off contract.
    settings = dict(BASE_SETTINGS)
    settings["bot_mitigation_action"] = "JS Challenge"
    written = _generate(monkeypatch, settings)
    conf = written[nginx_manager.DDOS_CONF_PATH]
    assert "map $host $waf_bot_mitigation_status {\n    default 0;\n}" in conf
    # The volumetric zone still applies in this mode.
    assert "limit_req zone=waf_ddos_req" in written[nginx_manager.DDOS_LIMITS_INCLUDE_PATH]


def test_http_level_fallback_is_retained(monkeypatch):
    # The http-level directives stay as a safety net for any location that
    # declares no limit_req of its own (removing them would silently drop
    # protection for those). The include is what makes them effective in the
    # locations that do.
    conf = _generate(monkeypatch)[nginx_manager.DDOS_CONF_PATH]
    assert "limit_req zone=waf_ddos_req burst=100 nodelay;" in conf


@pytest.mark.parametrize("rps,burst", [(10, 20), (200, 400)])
def test_configured_rate_and_burst_reach_the_include(monkeypatch, rps, burst):
    settings = dict(BASE_SETTINGS)
    settings["rate_limit_rps"] = rps
    settings["burst_tolerance"] = burst
    written = _generate(monkeypatch, settings)
    assert f"rate={rps}r/s" in written[nginx_manager.DDOS_CONF_PATH]
    assert f"burst={burst} nodelay;" in written[nginx_manager.DDOS_LIMITS_INCLUDE_PATH]
