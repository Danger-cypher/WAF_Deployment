"""
Coverage for the Overview KPI trend badges (P0 of the WAAP console teardown
roadmap — pairs every tile with an up/down delta against the prior period,
matching AWS WAF's pattern of trend arrows on every dashboard tile).

Two things need checking: that get_stats' new offset_hours parameter builds
the right ClickHouse WHERE clause (the "previous window" must be the
equal-sized period immediately before the current one, not overlapping it
and not shifted by the wrong amount), and that calculate_stats_trend wires
current/previous together correctly and degrades safely when ClickHouse is
unavailable.
"""
import pytest

from app.services import clickhouse_service, stats_calculator


class _FakeResult:
    result_rows = [(5, 1, 2, 3, 0, "SQL Injection")]


class _FakeClient:
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


def test_offset_zero_matches_plain_time_filter():
    """offset_hours=0 must be byte-identical to the pre-existing behavior —
    every other caller of _time_filter_clause must see no change."""
    assert clickhouse_service._offset_time_filter_clause(24, 0) == clickhouse_service._time_filter_clause(24)


def test_offset_window_is_the_equal_sized_period_immediately_before():
    clause = clickhouse_service._offset_time_filter_clause(24, 24)
    assert "INTERVAL 48 HOUR" in clause  # window start: 24 (this window) + 24 (offset) hours ago
    assert "INTERVAL 24 HOUR" in clause  # window end: 24 hours ago (exclusive)
    assert clause.count("timestamp") == 2  # both a lower and an upper bound


def test_get_stats_offset_hours_requires_bounded_hours(fake_ch_client):
    with pytest.raises(ValueError):
        clickhouse_service.get_stats(hours=None, offset_hours=24)


def test_get_stats_offset_hours_reaches_the_query(fake_ch_client):
    clickhouse_service.get_stats(24, offset_hours=24)
    assert "INTERVAL 48 HOUR" in fake_ch_client.queries[0]


def test_calculate_stats_trend_returns_current_and_previous(fake_ch_client, monkeypatch):
    # Redis unreachable in the test env, so _cache_get/_cache_set are already
    # real no-ops — no need to mock them.
    result = stats_calculator.calculate_stats_trend(window_hours=24)
    assert result["current"] is not None
    assert result["previous"] is not None
    assert result["current"]["total_blocked"] == 5
    # Two independent get_stats calls — one per window.
    assert len(fake_ch_client.queries) == 2
    assert "INTERVAL 24 HOUR" in fake_ch_client.queries[0] and "INTERVAL 48 HOUR" not in fake_ch_client.queries[0]
    assert "INTERVAL 48 HOUR" in fake_ch_client.queries[1]


def test_calculate_stats_trend_degrades_safely_when_clickhouse_unavailable(monkeypatch):
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: None)
    result = stats_calculator.calculate_stats_trend(window_hours=24)
    assert result == {"current": None, "previous": None}
