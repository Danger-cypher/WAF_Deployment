"""
Covers AlertManager.trigger_event()'s throttle-bypass split for syslog
channels (P1-12): a syslog channel gets every matching event
unconditionally, while every other channel type keeps the exact
pre-existing throttle/dedup behavior. This refactor touches
alert_aggregations/alert_history directly and had zero test coverage
before this — uses a real, isolated SQLite AlertDatabaseService (tmp_path)
rather than mocking the DB layer, since the throttle timing correctness
(syslog firing must NOT reset the other channels' throttle clock) is
exactly the kind of thing a mock would paper over.

trigger_event is async but this project has no pytest-asyncio configured
— run it via a bare asyncio.run() in an otherwise-synchronous test
function instead of adding a new test-only dependency.
"""
import asyncio

import pytest

from app.services import alert_manager as alert_manager_module
from app.services import clickhouse_service
from app.services.alert_db_service import AlertDatabaseService


@pytest.fixture
def db(tmp_path, monkeypatch):
    # create_alert_history/get_alert_history both prefer real ClickHouse
    # when reachable — this sandbox has live network access to the real
    # ClickHouse instance, so without this, these tests would write test
    # rows into (and read mixed real+test data from) production
    # alert_history. alert_db_service imports the clickhouse_service
    # MODULE (not the function directly), so patching it here is visible
    # there too. Force the SQLite-only path for full isolation.
    monkeypatch.setattr(clickhouse_service, "is_available", lambda: False)
    return AlertDatabaseService(db_path=str(tmp_path / "alerts_test.db"))


@pytest.fixture
def manager(db, monkeypatch):
    mgr = alert_manager_module.AlertManager()
    monkeypatch.setattr(mgr, "db", db)
    return mgr


class _RecordedCalls(list):
    """A list (so `== [...]` assertions read naturally) that can also
    carry a mutable `fail_for` set for per-test failure injection."""
    def __init__(self):
        super().__init__()
        self.fail_for = set()


@pytest.fixture
def dispatch_calls(monkeypatch):
    """Replaces the real network-hitting dispatcher with one that records
    which channels it was asked to notify and reports success for all of
    them, unless overridden per-test via calls.fail_for."""
    calls = _RecordedCalls()

    def _dispatch(channels_list, severity, event_type, message, event_data):
        calls.append(sorted(c["name"] for c in channels_list))
        return [
            {"channel_name": c["name"], "success": c["name"] not in calls.fail_for, "error": ("boom" if c["name"] in calls.fail_for else None)}
            for c in channels_list
        ]

    monkeypatch.setattr(alert_manager_module.notification_dispatcher, "dispatch", _dispatch)
    return calls


def _make_rule(db, channel_specs, throttle_minutes=5, event_type="attack_detected"):
    channel_ids = [
        db.create_channel(name=name, channel_type=ctype, config={"dummy": True})
        for name, ctype in channel_specs
    ]
    rule_id = db.create_rule(
        name=f"rule-{event_type}", event_type=event_type, severity="high",
        conditions={}, channels=channel_ids, throttle_minutes=throttle_minutes,
    )
    return rule_id


def _event(**overrides):
    base = {"remote_addr": "10.0.0.1", "uri": "/login", "message": "test"}
    base.update(overrides)
    return base


def _trigger(manager, event_type, event_data):
    asyncio.run(manager.trigger_event(event_type, event_data))


# ---------------------------------------------------------------------------
# Baseline: pre-existing throttle behavior, unchanged (no syslog channel)
# ---------------------------------------------------------------------------

def test_non_syslog_channel_fires_on_first_event(manager, db, dispatch_calls):
    _make_rule(db, [("slack-1", "slack")])
    _trigger(manager, "attack_detected", _event())

    assert dispatch_calls == [["slack-1"]]
    history = db.get_alert_history()
    assert history[0]["status"] == "sent"


def test_non_syslog_channel_throttled_on_second_event_within_window(manager, db, dispatch_calls):
    _make_rule(db, [("slack-1", "slack")], throttle_minutes=5)
    _trigger(manager, "attack_detected", _event())
    _trigger(manager, "attack_detected", _event())

    # Only the first call actually dispatched — same (rule, ip, uri)
    # signature within the throttle window skips the second.
    assert dispatch_calls == [["slack-1"]]
    history = db.get_alert_history()
    statuses = sorted(h["status"] for h in history)
    assert statuses == ["sent", "throttled"]


def test_different_uri_is_a_different_signature_not_throttled(manager, db, dispatch_calls):
    _make_rule(db, [("slack-1", "slack")], throttle_minutes=5)
    _trigger(manager, "attack_detected", _event(uri="/login"))
    _trigger(manager, "attack_detected", _event(uri="/admin"))

    assert dispatch_calls == [["slack-1"], ["slack-1"]]


# ---------------------------------------------------------------------------
# Syslog bypass — the new behavior
# ---------------------------------------------------------------------------

def test_syslog_only_rule_fires_on_every_event_never_throttled(manager, db, dispatch_calls):
    _make_rule(db, [("siem-1", "syslog")], throttle_minutes=5)
    for _ in range(3):
        _trigger(manager, "attack_detected", _event())

    assert dispatch_calls == [["siem-1"]] * 3
    history = db.get_alert_history()
    assert all(h["status"] == "sent" for h in history)
    assert len(history) == 3


def test_syslog_fires_while_sibling_slack_channel_is_throttled(manager, db, dispatch_calls):
    _make_rule(db, [("slack-1", "slack"), ("siem-1", "syslog")], throttle_minutes=5)
    _trigger(manager, "attack_detected", _event())  # both fire (first occurrence)
    dispatch_calls.clear()

    _trigger(manager, "attack_detected", _event())  # slack throttled, syslog still fires

    # syslog dispatched alone in its own call; slack did NOT get a second dispatch call
    assert dispatch_calls == [["siem-1"]]


def test_syslog_firing_does_not_reset_sibling_channel_throttle_clock(manager, db, dispatch_calls):
    """The core correctness risk of this refactor: syslog's own dispatch
    must never touch alert_aggregations, or it would incorrectly keep the
    throttle window alive for the OTHER channel on the same rule forever
    (every syslog firing bumping last_notified_at) instead of that
    channel's own last real notification."""
    _make_rule(db, [("slack-1", "slack"), ("siem-1", "syslog")], throttle_minutes=5)

    _trigger(manager, "attack_detected", _event())  # slack fires (1st), syslog fires (1st)
    dispatch_calls.clear()

    # Many more events within the throttle window — syslog keeps firing
    # every time, slack must stay throttled every time (not un-throttled
    # by syslog's repeated activity).
    for _ in range(5):
        _trigger(manager, "attack_detected", _event())

    # Only ever syslog in these subsequent dispatch calls — slack never
    # appears again, proving it stayed throttled throughout.
    assert dispatch_calls == [["siem-1"]] * 5


def test_syslog_history_entry_is_independent_of_throttled_entry(manager, db, dispatch_calls):
    _make_rule(db, [("slack-1", "slack"), ("siem-1", "syslog")], throttle_minutes=5)
    _trigger(manager, "attack_detected", _event())
    _trigger(manager, "attack_detected", _event())  # slack throttled, syslog sent

    # Syslog and the throttle-gated group are always dispatched (and
    # recorded) as two independent calls, even on the very first,
    # not-yet-throttled trigger — not merged into one combined entry.
    # trigger 1: syslog "sent" + slack "sent" = 2 entries.
    # trigger 2: syslog "sent" again + slack "throttled" = 2 more entries.
    history = db.get_alert_history()
    assert len(history) == 4
    throttled = [h for h in history if h["status"] == "throttled"]
    assert len(throttled) == 1
    assert throttled[0]["channels_notified"] == ["slack-1"]
    sent_syslog_entries = [h for h in history if h["status"] == "sent" and h["channels_notified"] == ["siem-1"]]
    assert len(sent_syslog_entries) == 2


def test_syslog_dispatch_failure_reported_as_failed_status(manager, db, dispatch_calls):
    dispatch_calls.fail_for.add("siem-1")
    _make_rule(db, [("siem-1", "syslog")])
    _trigger(manager, "attack_detected", _event())

    history = db.get_alert_history()
    assert history[0]["status"] == "failed"


def test_multiple_syslog_channels_on_one_rule_all_fire(manager, db, dispatch_calls):
    _make_rule(db, [("siem-1", "syslog"), ("siem-2", "syslog")])
    _trigger(manager, "attack_detected", _event())

    assert dispatch_calls == [["siem-1", "siem-2"]]


def test_rule_with_no_channels_at_all_still_records_history(manager, db, dispatch_calls):
    db.create_rule(
        name="no-channels-rule", event_type="attack_detected", severity="high",
        conditions={}, channels=[],
    )
    _trigger(manager, "attack_detected", _event())

    assert dispatch_calls == []
    history = db.get_alert_history()
    assert history[0]["status"] == "sent"
    assert "No active notification channels" in (history[0]["error_message"] or "")
