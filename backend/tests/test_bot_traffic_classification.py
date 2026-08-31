"""
Coverage for User-Agent traffic classification (P1 item 5 of the WAAP
console teardown roadmap — DDoS & Bot Shield's "traffic composition" view).

The classification SQL itself (_bot_category_case_expr) was hand-verified
against the live ClickHouse instance during development — this file guards
the two things that could silently regress afterward: category-ordering
(a specific bot name must win over the generic "bot" substring catch-all)
and the shared-fragment discipline the rest of clickhouse_service.py
already follows (both queries must classify identically).
"""
import pytest

from app.services import clickhouse_service


class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClient:
    def __init__(self, rows=None):
        self.queries = []
        self._rows = rows or []

    def ping(self):
        return True

    def query(self, sql, *args, **kwargs):
        self.queries.append(sql)
        return _FakeResult(self._rows)


@pytest.fixture
def fake_ch_client(monkeypatch):
    client = _FakeClient()
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: client)
    return client


def test_named_ai_crawler_beats_the_generic_bot_catch_all():
    """'GPTBot' must classify as 'AI Crawler', not fall through to the
    generic 'Generic Bot/Spider' bucket just because it also contains the
    substring 'bot' — this only holds if AI Crawler's branch is ordered
    before the generic catch-all in the multiIf."""
    expr = clickhouse_service._bot_category_case_expr("'Mozilla/5.0 GPTBot/1.0'")
    ai_crawler_pos = expr.index("'AI Crawler'")
    generic_pos = expr.index("'Generic Bot/Spider'")
    assert ai_crawler_pos < generic_pos


def test_scripted_client_is_ordered_before_generic_catch_all():
    """curl/wget etc. must not fall into 'Generic Bot/Spider' — none of
    them contain 'bot'/'spider'/'crawl'/'scraper' as substrings, but this
    pins the ordering contract so a future keyword addition can't change
    that by accident."""
    expr = clickhouse_service._bot_category_case_expr()
    assert expr.index("'Scripted Client'") < expr.index("'Generic Bot/Spider'")


def test_get_bot_traffic_breakdown_uses_shared_blocked_codes(fake_ch_client):
    clickhouse_service.get_bot_traffic_breakdown()
    assert len(fake_ch_client.queries) == 1
    assert fake_ch_client.queries[0].count(clickhouse_service._BLOCKED_HTTP_CODES_SQL) == 1


def test_breakdown_and_identities_classify_with_the_identical_expression(fake_ch_client):
    """Both queries build their category column from the exact same
    _bot_category_case_expr() call — if one call site drifts (e.g. someone
    hand-edits one copy instead of both), the two views would silently
    disagree on where a request lands. This diffs the two actual SQL
    strings' classification sub-expression instead of just trusting they
    were written the same way."""
    clickhouse_service.get_bot_traffic_breakdown()
    breakdown_sql = fake_ch_client.queries[-1]
    fake_ch_client.queries.clear()
    clickhouse_service.get_top_bot_identities()
    identities_sql = fake_ch_client.queries[-1]

    category_expr = clickhouse_service._bot_category_case_expr()
    assert category_expr in breakdown_sql
    assert category_expr in identities_sql


def test_top_bot_identities_excludes_human_and_no_user_agent_buckets(fake_ch_client):
    clickhouse_service.get_top_bot_identities()
    sql = fake_ch_client.queries[0]
    assert "'Browser (Human)'" in sql and "'No User-Agent'" in sql
    assert "NOT IN" in sql
