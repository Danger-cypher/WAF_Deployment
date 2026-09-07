"""
Regression tests for the protected-app `name` field as an nginx config
injection vector (audit finding P1-05).

`name` is interpolated into the generated gateway config as a comment line
("# --- Upstream App {id}: {name} ({domain}) ---"). It carried no character
validation, so a newline in it terminated the comment and let the remainder
of the value be parsed as live nginx directives — `content_by_lua_block`
included, i.e. code execution in the OpenResty container.

That matters more than a normal admin-only footgun because
PUT /apps/{app_id} is gated by require_app_write_access, which deliberately
accepts the app-scoped 'app_admin' role. So the injection was an escalation
path from one tenant's app administrator to root on the gateway serving
every tenant.

Two layers are asserted here, because either alone would leave a gap:
  1. the pydantic validator on ProtectedAppBase.name, which rejects the
     request outright; and
  2. nginx_manager._sanitize_config_comment(), which also neutralises rows
     already stored before the validator existed.
"""
import pytest
from pydantic import ValidationError

from app.routes.apps import ProtectedAppCreate
from app.services.nginx_manager import _sanitize_config_comment


def _app(**overrides):
    base = {
        "name": "Safe App",
        "domain": "app.example.com",
        "upstream_host": "backend.internal",
        "upstream_port": 8080,
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------
# Layer 1 — the request never reaches the generator
# --------------------------------------------------------------------------

INJECTION_NAMES = [
    # The real exploit shape: close the comment, open a server block that runs
    # arbitrary Lua, then re-open a comment so the rest of the file still parses.
    'MyApp\n}\nserver { listen 9999; location / { content_by_lua_block { os.execute("id") } } }\n#',
    # Minimal newline break-out.
    "MyApp\ninjected_directive on;",
    # Carriage return — nginx treats it as a line terminator too.
    "MyApp\rinjected_directive on;",
    # Directive terminator / block syntax without a newline, in case the value
    # is ever interpolated somewhere that is not a comment.
    "MyApp; injected_directive on",
    "MyApp { }",
    # A '#' would let a value comment out the remainder of a generated line.
    "MyApp # trailing",
    # NUL and other control characters.
    "MyApp\x00evil",
    "MyApp\x7fevil",
]


@pytest.mark.parametrize("bad_name", INJECTION_NAMES)
def test_name_with_injection_payload_is_rejected(bad_name):
    with pytest.raises(ValidationError):
        ProtectedAppCreate(**_app(name=bad_name))


def test_empty_and_whitespace_only_names_are_rejected():
    for bad in ("", "   ", "\t\n"):
        with pytest.raises(ValidationError):
            ProtectedAppCreate(**_app(name=bad))


def test_overlong_name_is_rejected():
    with pytest.raises(ValidationError):
        ProtectedAppCreate(**_app(name="A" * 65))


@pytest.mark.parametrize(
    "good_name",
    [
        "MSSP",
        "Customer Portal",
        "api-gateway",
        "Store (EU)",
        "App_7.prod",
        "Café Ordering",  # non-ASCII is fine; it is not nginx syntax
    ],
)
def test_ordinary_names_still_accepted(good_name):
    app = ProtectedAppCreate(**_app(name=good_name))
    assert app.name == good_name.strip()


def test_name_is_stripped_not_mangled():
    assert ProtectedAppCreate(**_app(name="  Customer Portal  ")).name == "Customer Portal"


# --------------------------------------------------------------------------
# Layer 2 — the generator neutralises anything already stored
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad_name", INJECTION_NAMES)
def test_sanitizer_output_cannot_break_out_of_a_comment(bad_name):
    out = _sanitize_config_comment(bad_name)
    # Nothing that can end the comment line...
    assert "\n" not in out
    assert "\r" not in out
    # ...and nothing that reads as nginx block/statement syntax.
    for ch in "{};#\\":
        assert ch not in out
    assert all(ord(c) >= 0x20 and ord(c) != 0x7F for c in out)


def test_sanitized_name_still_renders_a_wellformed_comment():
    evil = 'MyApp\n}\nserver { listen 9999; }\n#'
    line = f"# --- Upstream App 7: {_sanitize_config_comment(evil)} (app.example.com) ---"
    assert line.count("\n") == 0
    assert line.startswith("# --- Upstream App 7: ")


def test_sanitizer_never_returns_empty():
    # An all-control-character name must not collapse the generated comment
    # into "# --- Upstream App 7:  () ---".
    assert _sanitize_config_comment("\n\r\t") == "unnamed"
    assert _sanitize_config_comment("") == "unnamed"
    assert _sanitize_config_comment(None) == "unnamed"


def test_sanitizer_leaves_ordinary_names_untouched():
    for good in ("MSSP", "Customer Portal", "api-gateway", "Store (EU)"):
        assert _sanitize_config_comment(good) == good
