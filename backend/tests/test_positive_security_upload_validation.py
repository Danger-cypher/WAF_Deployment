"""
Covers apply_positive_security_settings() — no existing tests for this
function at all before this. Focus: the restricted-extensions fix (P0-3).
The pre-existing rule only ever matched REQUEST_FILENAME (the URL path,
e.g. GET /malware.exe) — a multipart file upload to an allowed path (POST
/upload with a part literally named shell.php) sailed straight through,
since the uploaded file's own name was never checked. This adds a
companion FILES_NAMES rule at phase:2 (request body/multipart parsing
phase) alongside the original phase:1 REQUEST_FILENAME rule.
"""
from app.services import nginx_manager

BASE_SETTINGS = {
    "enabled": True,
    "allowed_methods": [],
    "allowed_content_types": [],
    "restricted_extensions": [],
}


def _capture_generated_config(monkeypatch, settings):
    captured = {}

    def fake_write_and_apply(file_contents):
        captured.update(file_contents)
        return True, ""

    monkeypatch.setattr(nginx_manager, "write_and_apply_configs", fake_write_and_apply)
    ok, msg = nginx_manager.apply_positive_security_settings(settings)
    assert ok, msg
    return captured[nginx_manager.POSITIVE_SECURITY_CONF_PATH]


def test_disabled_produces_comment_only_policy(monkeypatch):
    config = _capture_generated_config(monkeypatch, {**BASE_SETTINGS, "enabled": False})
    assert "SecRule" not in config


def test_no_restricted_extensions_generates_neither_rule(monkeypatch):
    config = _capture_generated_config(monkeypatch, BASE_SETTINGS)
    assert "REQUEST_FILENAME" not in config
    assert "FILES_NAMES" not in config


def test_restricted_extensions_generates_both_request_filename_and_files_names_rules(monkeypatch):
    settings = {**BASE_SETTINGS, "restricted_extensions": ["php", "exe", ".sh"]}
    config = _capture_generated_config(monkeypatch, settings)

    # Original URL-path check still present, unchanged rule ID.
    assert 'SecRule REQUEST_FILENAME "@rx \\.(php|exe|sh)$"' in config
    assert "id:5900004,phase:1" in config

    # New: the actual uploaded-file-name check.
    assert 'SecRule FILES_NAMES "@rx \\.(php|exe|sh)$"' in config
    assert "id:5900005,phase:2" in config
    assert "t:lowercase" in config


def test_files_names_rule_uses_same_extension_set_as_request_filename(monkeypatch):
    settings = {**BASE_SETTINGS, "restricted_extensions": ["PHP", "ASPX"]}
    config = _capture_generated_config(monkeypatch, settings)

    # Extensions normalized to lowercase, leading dots stripped, same
    # pattern used for both rules (single source of truth, not two
    # independently-typed lists that could drift apart).
    assert config.count(r"\.(php|aspx)$") == 2


def test_files_names_rule_has_distinct_id_from_request_filename_rule(monkeypatch):
    settings = {**BASE_SETTINGS, "restricted_extensions": ["php"]}
    config = _capture_generated_config(monkeypatch, settings)
    assert "id:5900004" in config
    assert "id:5900005" in config
    assert "id:5900004" != "id:5900005"


def test_allowed_methods_and_content_types_unaffected_by_upload_fix(monkeypatch):
    settings = {
        **BASE_SETTINGS,
        "allowed_methods": ["GET", "POST"],
        "allowed_content_types": ["application/json"],
        "restricted_extensions": ["php"],
    }
    config = _capture_generated_config(monkeypatch, settings)
    assert "REQUEST_METHOD" in config
    assert "id:5900002" in config
    assert "id:5900003" in config
    assert "id:5900004" in config
    assert "id:5900005" in config
