"""
Regression coverage for the clickhouse_service.py SQL-parameterization
migration (~20 call sites moved off f-string interpolation + ad-hoc
quote-stripping onto clickhouse-connect's real %(name)s parameter binding).

The highest-risk part of this migration isn't the escaping itself
(clickhouse-connect's finalize_query already does that correctly, proven
directly below) — it's a subtler pitfall: finalize_query applies Python's
`%`-string-formatting to the ENTIRE query text whenever a non-empty
parameters dict is passed. Any bare '%' left in the template outside a
%(name)s token (e.g. a hardcoded `LIKE '4%'`) raises ValueError the moment
it's combined with ANY other parameter — exactly the case here, since
_build_waf_events_where_clause's blocked_only branch has three such literal
'%' patterns and gets combined with user filters like severity/rule_id in
the same query. This suite exercises that combination specifically, using
the real finalize_query (not a hand-rolled simulation) so a regression here
would fail loudly instead of only surfacing against a live ClickHouse.
"""
from clickhouse_connect.driver.binding import finalize_query

from app.services import clickhouse_service


class _FakeResult:
    result_rows = []


class _FakeClient:
    """Records every (sql, parameters) pair sent to .query()/.command()."""

    def __init__(self):
        self.calls = []

    def ping(self):
        return True

    def query(self, sql, *args, parameters=None, **kwargs):
        self.calls.append((sql, parameters))
        return _FakeResult()

    def command(self, sql, *args, parameters=None, **kwargs):
        self.calls.append((sql, parameters))
        return _FakeResult()


def test_where_clause_returns_sql_and_params_tuple():
    sql, params = clickhouse_service._build_waf_events_where_clause(severity="critical")
    assert isinstance(sql, str)
    assert isinstance(params, dict)
    assert params["severity"] == "critical"
    assert "%(severity)s" in sql
    assert "critical" not in sql


def test_blocked_only_plus_other_filter_survives_finalize_query_without_raising():
    """
    The exact dangerous combination: blocked_only's static '4%'/'5%' LIKE
    patterns coexisting with a real user-supplied parameter in the same
    query. If either static pattern were left as literal '%' text instead
    of a bound parameter, this would raise ValueError here — the same way
    it would against a real ClickHouse server.
    """
    sql, params = clickhouse_service._build_waf_events_where_clause(
        blocked_only=True, severity="high", rule_id="942100",
    )
    final = finalize_query(sql, params)
    assert "942100" in final
    assert "'high'" in final
    assert "LIKE '4%'" in final
    assert "LIKE '5%'" in final


def test_search_filter_injection_payload_is_escaped_not_executed():
    payload = "x' OR '1'='1"
    sql, params = clickhouse_service._build_waf_events_where_clause(search=payload)
    final = finalize_query(sql, params)
    # The literal unescaped breakout must never appear in the final SQL
    assert "%x' OR '1'='1%" not in final
    assert "\\' OR \\'1\\'=\\'1" in final


def test_uri_type_api_filter_uses_parameter_not_literal_percent():
    sql, params = clickhouse_service._build_waf_events_where_clause(uri_type="api")
    assert params["uri_prefix"] == "/api%"
    final = finalize_query(sql, params)
    assert "uri LIKE '/api%'" in final


def test_query_waf_events_passes_parameters_to_every_query_call(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    clickhouse_service.query_waf_events(rule_id="942100' OR '1'='1", blocked_only=True)

    assert len(fake.calls) == 2  # count query + rows query
    for sql, params in fake.calls:
        assert params is not None
        assert "942100' OR '1'='1" not in sql
        finalize_query(sql, params)  # must not raise


def test_query_waf_events_grouped_passes_parameters_to_every_query_call(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    clickhouse_service.query_waf_events_grouped(search="'; DROP TABLE waf_events; --", blocked_only=True)

    assert len(fake.calls) == 2
    for sql, params in fake.calls:
        assert params is not None
        assert "DROP TABLE" not in sql
        finalize_query(sql, params)


def test_get_ml_events_parameterizes_decision(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    clickhouse_service.get_ml_events(decision="block' OR '1'='1")

    assert len(fake.calls) == 2
    for sql, params in fake.calls:
        assert "block' OR '1'='1" not in sql
        finalize_query(sql, params)


def test_get_all_false_positives_parameterizes_all_filters(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    clickhouse_service.get_all_false_positives(
        status="Open' OR '1'='1", severity="high", rule_id="942100", search="foo' bar",
    )

    sql, params = fake.calls[0]
    assert "Open' OR '1'='1" not in sql
    assert params["status"] == "Open' OR '1'='1"
    finalize_query(sql, params)


def test_get_audit_log_parameterizes_entity_type(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    clickhouse_service.get_audit_log(entity_type="app' OR '1'='1")

    assert len(fake.calls) == 2
    for sql, params in fake.calls:
        assert "app' OR '1'='1" not in sql
        finalize_query(sql, params)


def test_query_alert_history_parameterizes_filters(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    clickhouse_service.query_alert_history(event_type="rule_disabled' OR '1'='1", severity="critical", status="new")

    sql, params = fake.calls[0]
    assert "rule_disabled' OR '1'='1" not in sql
    finalize_query(sql, params)


def test_acknowledge_alert_parameterizes_acknowledged_by(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    clickhouse_service.acknowledge_alert(1, "alice' OR '1'='1")

    sql, params = fake.calls[0]
    assert "alice' OR '1'='1" not in sql
    assert params["acknowledged_by"] == "alice' OR '1'='1"
    finalize_query(sql, params)


def test_acknowledge_alert_forces_synchronous_mutation(monkeypatch):
    """Regression guard for a real, empirically-confirmed bug: ClickHouse's
    ALTER TABLE ... UPDATE is an async background mutation by default —
    without SETTINGS mutations_sync = 1, a route handler (or
    NotificationBell.jsx's immediate re-fetch right after acknowledging)
    reading the row back right after this call can still see the OLD,
    unacknowledged status. Confirmed directly against a live ClickHouse
    instance during development: the exact same UPDATE without this
    setting left the row's status as 'sent' on an immediate re-read; with
    it, the re-read correctly showed 'acknowledged'."""
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    clickhouse_service.acknowledge_alert(1, "alice")

    sql, _ = fake.calls[0]
    assert "mutations_sync" in sql and "= 1" in sql


def test_get_waf_event_by_id_parameterizes_log_id(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    clickhouse_service.get_waf_event_by_id("abc' OR '1'='1")

    # The second call is the by-id lookup this function makes directly
    # (its first call comes from the internal query_waf_events(...) it
    # also fires, unrelated to this test).
    sql, params = fake.calls[-1]
    assert "abc' OR '1'='1" not in sql
    finalize_query(sql, params)
