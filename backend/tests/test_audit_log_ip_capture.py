"""
Regression tests for audit finding P2-13: every row in the audit_log table
had an empty ip_address, no matter which admin performed the action.

Root cause: app.utils.audit.log_admin_action() has always supported an
optional `request` parameter and forwards get_client_ip(request) to the
ClickHouse writer — but not one of the 54 call sites across apps.py,
api_keys.py, false_positives.py, rules.py, users.py, virtual_patches.py,
system.py and settings.py ever passed it, so `ip_address` defaulted to "" on
every write. Wiring it through revealed a second, sharper bug: three of
those functions (false_positives.py's mark_log_as_false_positive,
update_status, update_note) already declared a parameter literally named
`request` — the Pydantic request *body*, not fastapi.Request — so a
mechanical "just pass request=request" pass would have silently forwarded
the wrong object into get_client_ip(), which expects a `.headers` mapping.
rules.py's save_custom_rules had the identical shadowing bug. All four were
fixed by renaming the body parameter to `payload` and introducing a real
`request: Request`.

This file guards both bugs: that log_admin_action's `request` argument
really reaches get_client_ip(), and that no route module reintroduces a
`request` parameter typed as anything other than fastapi.Request.
"""
import ast
import inspect
from pathlib import Path
from unittest.mock import MagicMock

from app.utils.audit import log_admin_action


ROUTES_DIR = Path(__file__).parent.parent / "app" / "routes"

# Every route module this fix touched — each has at least one
# log_admin_action() call site.
TOUCHED_MODULES = [
    "apps.py",
    "api_keys.py",
    "false_positives.py",
    "rules.py",
    "users.py",
    "virtual_patches.py",
    "system.py",
    "settings.py",
]


def _fake_token_data(username="admin"):
    td = MagicMock()
    td.username = username
    return td


def test_request_is_forwarded_to_get_client_ip(monkeypatch):
    captured = {}

    def fake_insert_audit_log(**kwargs):
        captured.update(kwargs)
        return True

    monkeypatch.setattr(
        "app.utils.audit.clickhouse_service.insert_audit_log", fake_insert_audit_log
    )
    monkeypatch.setattr(
        "app.utils.audit.get_client_ip", lambda request: "203.0.113.7"
    )

    fake_request = MagicMock()
    log_admin_action(
        "user", "10", "update", _fake_token_data(), details={"enabled": False},
        request=fake_request,
    )

    assert captured["ip_address"] == "203.0.113.7"


def test_get_client_ip_is_not_called_without_a_request(monkeypatch):
    # No request object available (a call site that genuinely has none) must
    # not crash and must fall back to the empty string, not raise.
    called = {"n": 0}

    def fake_get_client_ip(request):
        called["n"] += 1
        return "should-not-be-used"

    captured = {}
    monkeypatch.setattr(
        "app.utils.audit.clickhouse_service.insert_audit_log",
        lambda **kw: captured.update(kw) or True,
    )
    monkeypatch.setattr("app.utils.audit.get_client_ip", fake_get_client_ip)

    log_admin_action("user", "10", "update", _fake_token_data())

    assert called["n"] == 0
    assert captured["ip_address"] == ""


def test_log_admin_action_never_raises_on_a_broken_writer(monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("clickhouse unreachable")

    monkeypatch.setattr("app.utils.audit.clickhouse_service.insert_audit_log", boom)
    # Must not raise — the admin action itself already succeeded.
    log_admin_action(
        "user", "10", "update", _fake_token_data(), request=MagicMock()
    )


# --------------------------------------------------------------------------
# Static guard: every function that calls log_admin_action() must accept a
# genuine fastapi.Request, never a same-named Pydantic body (the exact bug
# that shipped in false_positives.py and rules.py).
# --------------------------------------------------------------------------

def _functions_calling_log_admin_action(path):
    tree = ast.parse(path.read_text())
    results = []

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            self.check(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node):
            self.check(node)
            self.generic_visit(node)

        def check(self, node):
            calls = [
                n for n in ast.walk(node)
                if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "log_admin_action"
            ]
            if calls:
                results.append(node)

    V().visit(tree)
    return results


def test_no_route_shadows_the_request_parameter():
    offenders = []
    for filename in TOUCHED_MODULES:
        path = ROUTES_DIR / filename
        for node in _functions_calling_log_admin_action(path):
            for arg in node.args.args + node.args.kwonlyargs:
                if arg.arg != "request":
                    continue
                annotation = arg.annotation
                type_name = getattr(annotation, "id", None)
                if type_name != "Request":
                    offenders.append(f"{filename}:{node.name} (request: {ast.dump(annotation)})")

    assert offenders == [], (
        "These functions declare a `request` parameter that is not "
        "fastapi.Request, which would silently break audit-log IP capture "
        "and/or crash get_client_ip(): " + ", ".join(offenders)
    )


def test_every_log_admin_action_call_site_passes_request():
    missing = []
    for filename in TOUCHED_MODULES:
        path = ROUTES_DIR / filename
        for node in _functions_calling_log_admin_action(path):
            calls = [
                n for n in ast.walk(node)
                if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "log_admin_action"
            ]
            for c in calls:
                if not any(kw.arg == "request" for kw in c.keywords):
                    missing.append(f"{filename}:{node.name}:{c.lineno}")

    assert missing == [], (
        "These log_admin_action() calls don't forward request=request, so "
        "their audit rows will have an empty ip_address again: " + ", ".join(missing)
    )
