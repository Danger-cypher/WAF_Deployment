"""
Covers P1-5: CVE-aware virtual-patch templates — deploying/undeploying/
mode-switching entries from the curated library (app/data/cve_templates.py)
into custom-rules.conf's own marker-delimited section, and the routes on
top of it.

Isolates the real filesystem (custom-rules.conf) and the real nginx-
touching pipeline the same way test_rule_canary.py isolates ClickHouse:
monkeypatch virtual_patch_service.CUSTOM_RULES_FILE to a tmp_path file,
and nginx_manager.write_and_apply_configs (imported LAZILY inside
deploy()/undeploy() — a call-time import, so patching the source module's
attribute is picked up automatically, same pattern used for
session_service/api_key_service elsewhere in this suite) to a fake that
performs the same write-the-file effect a real success would, without
touching Docker/nginx.
"""
import pytest
from fastapi.testclient import TestClient

from app.services import virtual_patch_service
from app.services import nginx_manager
from app.services import clickhouse_service
from app.data.cve_templates import CVE_TEMPLATES
from app.main import app as fastapi_app

KNOWN_CVE = CVE_TEMPLATES[0]["cve_id"]  # CVE-2021-44228
OTHER_CVE = CVE_TEMPLATES[1]["cve_id"]  # CVE-2022-22965


def _fake_write_success(file_contents):
    for path, content in file_contents.items():
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    return True, ""


def _fake_write_failure(file_contents):
    return False, "nginx config test failed (simulated)"


@pytest.fixture
def isolated_vp_file(tmp_path, monkeypatch):
    rules_file = tmp_path / "custom-rules.conf"
    monkeypatch.setattr(virtual_patch_service, "CUSTOM_RULES_FILE", str(rules_file))
    monkeypatch.setattr(nginx_manager, "write_and_apply_configs", _fake_write_success)
    return rules_file


# ---------------------------------------------------------------------------
# rule_id_for / get_template / get_library — pure logic, no I/O
# ---------------------------------------------------------------------------

def test_rule_id_is_deterministic_and_in_reserved_band():
    id1 = virtual_patch_service.rule_id_for(KNOWN_CVE)
    id2 = virtual_patch_service.rule_id_for(KNOWN_CVE)
    assert id1 == id2
    assert 6_000_000 <= id1 < 6_900_000


def test_rule_ids_unique_across_whole_library():
    ids = [virtual_patch_service.rule_id_for(t["cve_id"]) for t in CVE_TEMPLATES]
    assert len(ids) == len(set(ids))


def test_get_template_unknown_cve_returns_none():
    assert virtual_patch_service.get_template("CVE-9999-99999") is None


def test_get_template_known_cve_returns_dict():
    t = virtual_patch_service.get_template(KNOWN_CVE)
    assert t is not None
    assert t["cve_id"] == KNOWN_CVE
    assert "__ID__" in t["rule_body"] and "__MODE__" in t["rule_body"]


def test_get_library_shape_when_nothing_deployed(isolated_vp_file):
    library = virtual_patch_service.get_library()
    assert len(library) == len(CVE_TEMPLATES)
    for entry in library:
        assert entry["deployed_mode"] is None
        assert entry["rule_id"] == virtual_patch_service.rule_id_for(entry["cve_id"])


# ---------------------------------------------------------------------------
# deploy / undeploy / mode switch — the actual file-writing logic
# ---------------------------------------------------------------------------

def test_deploy_detect_mode_writes_pass_action(isolated_vp_file):
    ok, err = virtual_patch_service.deploy(KNOWN_CVE, "detect")
    assert ok, err

    content = isolated_vp_file.read_text()
    assert f"id:{virtual_patch_service.rule_id_for(KNOWN_CVE)}" in content
    assert ",pass," in content or "\n    pass,\\\n" in content
    assert "block" not in content.split("msg:")[0]  # the action list, not the msg text
    assert virtual_patch_service.list_deployed() == {KNOWN_CVE: "detect"}


def test_deploy_block_mode_writes_block_action(isolated_vp_file):
    ok, err = virtual_patch_service.deploy(KNOWN_CVE, "block")
    assert ok, err

    content = isolated_vp_file.read_text()
    assert virtual_patch_service.list_deployed() == {KNOWN_CVE: "block"}
    assert "block,\\\n    log," in content


def test_redeploy_switches_mode_without_duplicating_block(isolated_vp_file):
    virtual_patch_service.deploy(KNOWN_CVE, "detect")
    virtual_patch_service.deploy(KNOWN_CVE, "block")

    content = isolated_vp_file.read_text()
    assert content.count(f"# virtual-patch: {KNOWN_CVE}") == 1  # not duplicated
    assert virtual_patch_service.list_deployed() == {KNOWN_CVE: "block"}


def test_deploy_unknown_cve_fails_cleanly(isolated_vp_file):
    ok, err = virtual_patch_service.deploy("CVE-9999-99999", "detect")
    assert ok is False
    assert "Unknown CVE template" in err


def test_deploy_invalid_mode_fails_cleanly(isolated_vp_file):
    ok, err = virtual_patch_service.deploy(KNOWN_CVE, "shadow")
    assert ok is False
    assert "mode" in err


def test_two_different_cves_coexist(isolated_vp_file):
    virtual_patch_service.deploy(KNOWN_CVE, "detect")
    virtual_patch_service.deploy(OTHER_CVE, "block")

    deployed = virtual_patch_service.list_deployed()
    assert deployed == {KNOWN_CVE: "detect", OTHER_CVE: "block"}


def test_undeploy_removes_only_the_target_cve(isolated_vp_file):
    virtual_patch_service.deploy(KNOWN_CVE, "detect")
    virtual_patch_service.deploy(OTHER_CVE, "block")

    ok, err = virtual_patch_service.undeploy(KNOWN_CVE)
    assert ok, err
    assert virtual_patch_service.list_deployed() == {OTHER_CVE: "block"}


def test_undeploy_never_deployed_cve_is_a_noop_success(isolated_vp_file):
    ok, err = virtual_patch_service.undeploy(KNOWN_CVE)
    assert ok is True
    assert "Not currently deployed" in err


def test_deploy_preserves_admins_own_hand_written_rules(isolated_vp_file):
    """The whole point of the marker-block approach: an admin's own
    Virtual Patching content outside the auto-generated section survives
    a deploy untouched."""
    isolated_vp_file.write_text('SecRule REQUEST_URI "@contains /admin-secret" "id:1234567,phase:1,deny,status:403"\n')

    virtual_patch_service.deploy(KNOWN_CVE, "detect")

    content = isolated_vp_file.read_text()
    assert "/admin-secret" in content
    assert "id:1234567" in content
    assert virtual_patch_service.list_deployed() == {KNOWN_CVE: "detect"}


def test_deploy_failure_propagates_error_message(tmp_path, monkeypatch):
    rules_file = tmp_path / "custom-rules.conf"
    monkeypatch.setattr(virtual_patch_service, "CUSTOM_RULES_FILE", str(rules_file))
    monkeypatch.setattr(nginx_manager, "write_and_apply_configs", _fake_write_failure)

    ok, err = virtual_patch_service.deploy(KNOWN_CVE, "detect")
    assert ok is False
    assert "nginx config test failed" in err


# ---------------------------------------------------------------------------
# Route-level tests
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_client(isolated_user_service, isolated_vp_file):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


def test_analyst_can_read_library(isolated_client, make_user):
    client = isolated_client
    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.get("/virtual-patches")
    assert r.status_code == 200
    assert len(r.json()) == len(CVE_TEMPLATES)


def test_analyst_forbidden_from_deploy(isolated_client, make_user):
    client = isolated_client
    analyst = make_user(role="analyst")
    csrf = _login(client, analyst["username"], analyst["password"])

    r = client.post(f"/virtual-patches/{KNOWN_CVE}/deploy", headers={"X-XSRF-TOKEN": csrf}, json={"mode": "detect"})
    assert r.status_code == 403


def test_admin_deploy_then_appears_in_library(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(f"/virtual-patches/{KNOWN_CVE}/deploy", headers={"X-XSRF-TOKEN": csrf}, json={"mode": "detect"})
    assert r.status_code == 200, r.text

    library = client.get("/virtual-patches").json()
    entry = next(e for e in library if e["cve_id"] == KNOWN_CVE)
    assert entry["deployed_mode"] == "detect"


def test_deploy_unknown_cve_404s(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post("/virtual-patches/CVE-9999-99999/deploy", headers={"X-XSRF-TOKEN": csrf}, json={"mode": "detect"})
    assert r.status_code == 404


def test_deploy_invalid_mode_422s(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(f"/virtual-patches/{KNOWN_CVE}/deploy", headers={"X-XSRF-TOKEN": csrf}, json={"mode": "shadow"})
    assert r.status_code == 422


def test_admin_undeploy(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    client.post(f"/virtual-patches/{KNOWN_CVE}/deploy", headers={"X-XSRF-TOKEN": csrf}, json={"mode": "block"})
    r = client.post(f"/virtual-patches/{KNOWN_CVE}/undeploy", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200

    library = client.get("/virtual-patches").json()
    entry = next(e for e in library if e["cve_id"] == KNOWN_CVE)
    assert entry["deployed_mode"] is None


def test_undeploy_unknown_cve_404s(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post("/virtual-patches/CVE-9999-99999/undeploy", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 404


def test_deploy_logs_admin_action(isolated_client, make_user, monkeypatch):
    import app.routes.virtual_patches as vp_routes

    calls = []
    monkeypatch.setattr(vp_routes, "log_admin_action", lambda *a, **k: calls.append((a, k)))

    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])
    client.post(f"/virtual-patches/{KNOWN_CVE}/deploy", headers={"X-XSRF-TOKEN": csrf}, json={"mode": "detect"})

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0] == "virtual_patch"
    assert args[1] == KNOWN_CVE
    assert args[2] == "deploy"


# ---------------------------------------------------------------------------
# Hit-count route — reuses clickhouse_service.get_rule_canary_report
# ---------------------------------------------------------------------------

class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClient:
    def __init__(self, rows):
        self._rows = rows
        self.queries = []
        self.params = []

    def query(self, sql, *args, parameters=None, **kwargs):
        self.queries.append(sql)
        self.params.append(parameters)
        return _FakeResult(self._rows)


def test_hits_route_returns_canary_report_shape(isolated_client, make_user, monkeypatch):
    fake = _FakeClient(rows=[(5, 2, 3)])
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    client = isolated_client
    admin = make_user(role="admin")
    _login(client, admin["username"], admin["password"])

    r = client.get(f"/virtual-patches/{KNOWN_CVE}/hits")
    assert r.status_code == 200
    assert r.json() == {"total_matches": 5, "sole_match_count": 2, "co_matched_count": 3}
    # The rule id used against ClickHouse is this CVE's own deterministic id.
    assert fake.params[0] == {"rule_id": str(virtual_patch_service.rule_id_for(KNOWN_CVE))}


def test_hits_route_unknown_cve_404s(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    _login(client, admin["username"], admin["password"])

    r = client.get("/virtual-patches/CVE-9999-99999/hits")
    assert r.status_code == 404
