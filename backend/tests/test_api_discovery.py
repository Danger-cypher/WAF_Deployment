"""
Tests for API Protection's trustworthy-scoring inputs.

has_https/content_encoding used to be fabricated (has_https hardcoded true,
content_encoding guessed from the status code). These tests pin down the
tri-state sentinel scheme (2/"unknown" = not yet measured) that replaced it:
the three-tier log-format regex fallback in api_discovery.py, the
prefer-known-over-unknown merge logic, and calculate_endpoint_score's
deductions only firing on confirmed-bad values, never on "unknown".
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from app.services import api_discovery
from app.routes.api_protection import calculate_endpoint_score


# ---------------------------------------------------------------------------
# Regex tiers
# ---------------------------------------------------------------------------

FULL_LINE = (
    '203.0.113.5 - - [08/Jun/2026:10:35:51 +0530] '
    '"GET /api/v1/orders HTTP/1.1" 200 154 "-" "Mozilla/5.0" '
    '0.012 0.010 https "gzip"'
)
FULL_LINE_HTTP_NO_ENCODING = (
    '203.0.113.5 - - [08/Jun/2026:10:35:51 +0530] '
    '"GET /api/v1/orders HTTP/1.1" 200 154 "-" "Mozilla/5.0" '
    '0.012 0.010 http ""'
)
TIMING_ONLY_LINE = (
    '203.0.113.5 - - [08/Jun/2026:10:35:51 +0530] '
    '"GET /api/v1/orders HTTP/1.1" 200 154 "-" "Mozilla/5.0" '
    '0.012 0.010'
)
LEGACY_LINE = (
    '203.0.113.5 - - [08/Jun/2026:10:35:51 +0530] '
    '"GET /api/v1/orders HTTP/1.1" 200 154 "-" "Mozilla/5.0"'
)


def test_full_tier_captures_scheme_and_encoding():
    m = api_discovery.ACCESS_LINE_RE.match(FULL_LINE)
    assert m is not None
    assert m.group("scheme") == "https"
    assert m.group("encoding") == "gzip"


def test_full_tier_handles_empty_encoding():
    m = api_discovery.ACCESS_LINE_RE.match(FULL_LINE_HTTP_NO_ENCODING)
    assert m is not None
    assert m.group("scheme") == "http"
    assert m.group("encoding") == ""


def test_full_tier_does_not_match_timing_only_line():
    assert api_discovery.ACCESS_LINE_RE.match(TIMING_ONLY_LINE) is None


def test_timing_only_tier_matches():
    m = api_discovery.ACCESS_LINE_RE_TIMING_ONLY.match(TIMING_ONLY_LINE)
    assert m is not None
    assert m.group("request_time") == "0.012"


def test_legacy_tier_matches_oldest_format():
    m = api_discovery.ACCESS_LINE_RE_LEGACY.match(LEGACY_LINE)
    assert m is not None
    assert m.group("status") == "200"


# ---------------------------------------------------------------------------
# is_internal_ip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ("127.0.0.1", True),
    ("10.0.5.2", True),
    ("172.17.0.3", True),
    ("192.168.1.10", True),
    ("169.254.1.1", True),
    ("::1", True),
    ("8.8.8.8", False),
    ("203.0.113.5", False),
    ("not-an-ip", False),
])
def test_is_internal_ip(ip, expected):
    assert api_discovery.is_internal_ip(ip) is expected


# ---------------------------------------------------------------------------
# run_api_discovery — end-to-end parsing + merge logic
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_access_log(tmp_path, monkeypatch):
    """Points api_discovery at a throwaway log file and resets its
    module-level read-position/lock state so tests don't leak into
    each other or the real /var/log/nginx/access.log."""
    log_path = tmp_path / "access.log"
    log_path.write_text("")
    monkeypatch.setattr(api_discovery, "NGINX_ACCESS_LOG", str(log_path))
    monkeypatch.setattr(api_discovery, "_last_position", 0)

    captured = {}

    def _fake_upsert(endpoints_data):
        captured.update(endpoints_data)

    monkeypatch.setattr(api_discovery.db_service, "bulk_upsert_discovered_endpoints", _fake_upsert)
    return log_path, captured


def test_run_api_discovery_captures_real_https_and_encoding(fake_access_log):
    log_path, captured = fake_access_log
    log_path.write_text(FULL_LINE + "\n")

    api_discovery.run_api_discovery()

    ep = captured[("/api/v1/orders", "GET")]
    assert ep["has_https"] == 1
    assert ep["content_encoding"] == "gzip"


def test_run_api_discovery_confirmed_http_deducts_no_guessing(fake_access_log):
    log_path, captured = fake_access_log
    log_path.write_text(FULL_LINE_HTTP_NO_ENCODING + "\n")

    api_discovery.run_api_discovery()

    ep = captured[("/api/v1/orders", "GET")]
    assert ep["has_https"] == 0
    assert ep["content_encoding"] == ""


def test_run_api_discovery_legacy_line_uses_unknown_sentinel(fake_access_log):
    log_path, captured = fake_access_log
    log_path.write_text(LEGACY_LINE + "\n")

    api_discovery.run_api_discovery()

    ep = captured[("/api/v1/orders", "GET")]
    assert ep["has_https"] == api_discovery.HTTPS_UNKNOWN
    assert ep["content_encoding"] == api_discovery.ENCODING_UNKNOWN


def test_run_api_discovery_merges_insecure_hit_wins_over_secure(fake_access_log):
    """A confirmed-insecure hit is a real finding and must not be papered
    over by a later confirmed-secure hit for the same endpoint."""
    log_path, captured = fake_access_log
    log_path.write_text(FULL_LINE + "\n" + FULL_LINE_HTTP_NO_ENCODING + "\n")

    api_discovery.run_api_discovery()

    ep = captured[("/api/v1/orders", "GET")]
    assert ep["has_https"] == 0
    assert ep["hit_count"] == 2


def test_run_api_discovery_merges_known_encoding_over_unknown(fake_access_log):
    """A legacy (unknown-encoding) hit followed by a measured hit should
    keep the real measurement, not fall back to the sentinel."""
    log_path, captured = fake_access_log
    log_path.write_text(LEGACY_LINE + "\n" + FULL_LINE + "\n")

    api_discovery.run_api_discovery()

    ep = captured[("/api/v1/orders", "GET")]
    assert ep["content_encoding"] == "gzip"
    # has_https: legacy=unknown(2), full=https(1) -> min() keeps the known value
    assert ep["has_https"] == 1


def test_run_api_discovery_tags_internal_ips_without_polluting_score_metrics(fake_access_log):
    """Internal/RFC1918 traffic is tagged (so the endpoint isn't invisible
    and Traffic Source classification works) but must not touch any
    score-driving metric — hit_count, error/malicious/suspicious counts,
    latency, or the https/encoding measurements all stay at their
    untouched defaults."""
    log_path, captured = fake_access_log
    internal_line = FULL_LINE.replace("203.0.113.5", "192.168.1.5")
    log_path.write_text(internal_line + "\n")

    api_discovery.run_api_discovery()

    ep = captured[("/api/v1/orders", "GET")]
    assert ep["internal_hit_count"] == 1
    assert ep["external_hit_count"] == 0
    assert ep["hit_count"] == 0
    assert ep["error_count"] == 0
    assert ep["malicious_count"] == 0
    assert ep["suspicious_count"] == 0
    assert ep["response_time_ms_sum"] == 0.0
    assert ep["has_https"] == api_discovery.HTTPS_UNKNOWN
    assert ep["content_encoding"] == api_discovery.ENCODING_UNKNOWN


# ---------------------------------------------------------------------------
# calculate_endpoint_score — tri-state deductions
# ---------------------------------------------------------------------------

def _base_endpoint(**overrides):
    ep = {
        "hit_count": 100,
        "error_count": 0,
        "malicious_count": 0,
        "suspicious_count": 0,
        "avg_response_time_ms": 50.0,
        "has_https": api_discovery.HTTPS_UNKNOWN,
        "has_versioning": 1,
        "content_encoding": api_discovery.ENCODING_UNKNOWN,
        "external_hit_count": 100,
        "internal_hit_count": 0,
    }
    ep.update(overrides)
    return ep


def test_confirmed_http_deducts_20():
    scored = calculate_endpoint_score(_base_endpoint(has_https=0))
    assert scored["score"] == 80


def test_confirmed_https_deducts_nothing():
    scored = calculate_endpoint_score(_base_endpoint(has_https=1))
    assert scored["score"] == 100


def test_unknown_https_deducts_nothing_not_guilty_until_measured():
    scored = calculate_endpoint_score(_base_endpoint(has_https=api_discovery.HTTPS_UNKNOWN))
    assert scored["score"] == 100


def test_confirmed_no_compression_deducts_5():
    scored = calculate_endpoint_score(_base_endpoint(content_encoding=""))
    assert scored["score"] == 95


def test_known_compression_deducts_nothing():
    scored = calculate_endpoint_score(_base_endpoint(content_encoding="gzip"))
    assert scored["score"] == 100


def test_unknown_compression_deducts_nothing():
    scored = calculate_endpoint_score(_base_endpoint(content_encoding=api_discovery.ENCODING_UNKNOWN))
    assert scored["score"] == 100


def test_worst_case_confirmed_values_stack():
    scored = calculate_endpoint_score(_base_endpoint(has_https=0, content_encoding=""))
    assert scored["score"] == 75
    assert scored["grade"] == "C"
