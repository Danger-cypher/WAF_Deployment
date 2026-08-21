"""
Regression guard for the "blocked request" status-code drift bug: multiple
ClickHouse queries in clickhouse_service.py each independently decided what
counts as a "blocked" request, and one of them (get_stats' total_blocked)
had silently fallen behind — it checked bare http_code = '403' while every
other panel (severity distribution, attack types, top IPs, endpoint threat
counts) correctly included require-auth/positive-security/rate-limit codes
too. That's now centralized into one BLOCKED_HTTP_CODES constant.

This test doesn't hit a real ClickHouse — it substitutes a fake client that
records the exact SQL text each function sends, then asserts every one of
them references the *same* shared SQL fragment. A future change that
hardcodes a status-code tuple in just one function instead of importing the
constant will fail this test immediately, rather than silently drifting
until a user notices mismatched numbers on the dashboard.
"""
import pytest

from app.services import clickhouse_service


class _FakeResult:
    """Minimal stand-in for clickhouse_connect's QueryResult — every query
    in this test returns zero rows, which is enough: none of the target
    functions crash on an empty result (all handle it as "no data yet")."""
    result_rows = []


class _FakeClient:
    """Records every SQL string sent to .query(), answers with empty rows."""

    def __init__(self):
        self.queries = []

    def ping(self):
        return True

    def query(self, sql, *args, **kwargs):
        self.queries.append(sql)
        return _FakeResult()


@pytest.fixture
def fake_ch_client(monkeypatch):
    client = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: client)
    return client


def test_blocked_http_codes_constant_is_the_full_set():
    """Basic sanity check that nobody silently trims the tuple later —
    catches require-auth (401), CRS/positive-security-extension (403),
    positive-security method/content-type (405/415), and bot/DDoS
    rate-limiting (429/444). 406 is kept for backward compatibility with
    already-ingested rows even though nothing currently generates it."""
    assert set(clickhouse_service.BLOCKED_HTTP_CODES) == {
        "401", "403", "405", "406", "415", "429", "444",
    }


def test_get_stats_uses_shared_blocked_codes(fake_ch_client):
    clickhouse_service.get_stats()
    assert len(fake_ch_client.queries) == 1
    # Referenced 4 times — total_blocked, unique_ips, recent_threats,
    # top_attack. A plain "in" check would miss a partial reversion (e.g.
    # just total_blocked hardcoded back to '403') since the other 3 would
    # still contain the fragment — count() is what actually catches that.
    assert fake_ch_client.queries[0].count(clickhouse_service._BLOCKED_HTTP_CODES_SQL) == 4


def test_get_severity_distribution_uses_shared_blocked_codes(fake_ch_client):
    clickhouse_service.get_severity_distribution()
    assert len(fake_ch_client.queries) == 1
    assert fake_ch_client.queries[0].count(clickhouse_service._BLOCKED_HTTP_CODES_SQL) == 1


def test_get_attack_types_uses_shared_blocked_codes(fake_ch_client):
    clickhouse_service.get_attack_types()
    assert len(fake_ch_client.queries) == 1
    assert fake_ch_client.queries[0].count(clickhouse_service._BLOCKED_HTTP_CODES_SQL) == 1


def test_get_top_ips_uses_shared_blocked_codes(fake_ch_client):
    clickhouse_service.get_top_ips()
    assert len(fake_ch_client.queries) == 1
    assert fake_ch_client.queries[0].count(clickhouse_service._BLOCKED_HTTP_CODES_SQL) == 1


def test_get_endpoint_threat_counts_uses_shared_blocked_codes(fake_ch_client):
    clickhouse_service.get_endpoint_threat_counts()
    assert len(fake_ch_client.queries) == 1
    # Referenced twice — once for malicious_count (IN), once for
    # suspicious_count (NOT IN) — both must use the same fragment.
    assert fake_ch_client.queries[0].count(clickhouse_service._BLOCKED_HTTP_CODES_SQL) == 2
