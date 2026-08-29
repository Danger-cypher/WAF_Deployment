"""
Covers per-channel delivery health (P2-17): AlertDispatcher.dispatch()
always computed a per-channel {channel_name, success, error} result, but
alert_manager.py used to collapse it into one shared status/error string
before persisting, discarding exactly the data this feature needs.
create_alert_history/get_channel_delivery_health now carry it through end
to end — exercised here via a real AlertManager.trigger_event() call (same
isolated-SQLite fixture pattern as test_alert_syslog_throttle_bypass.py),
not a hand-built alert_history row, so a regression in how alert_manager
builds channel_results would actually be caught.
"""
import asyncio

import pytest

from app.services import alert_manager as alert_manager_module
from app.services import clickhouse_service
from app.services.alert_db_service import AlertDatabaseService


@pytest.fixture
def db(tmp_path, monkeypatch):
    # See test_alert_syslog_throttle_bypass.py's identical fixture for why:
    # this sandbox has live network access to the real ClickHouse instance,
    # so without forcing the SQLite-only path these tests would read/write
    # production alert_history.
    monkeypatch.setattr(clickhouse_service, "is_available", lambda: False)
    return AlertDatabaseService(db_path=str(tmp_path / "alerts_test.db"))


@pytest.fixture
def manager(db, monkeypatch):
    mgr = alert_manager_module.AlertManager()
    monkeypatch.setattr(mgr, "db", db)
    return mgr


class _RecordedCalls(list):
    def __init__(self):
        super().__init__()
        self.fail_for = set()


@pytest.fixture
def dispatch_calls(monkeypatch):
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


def test_success_and_failure_recorded_per_channel(manager, db, dispatch_calls):
    _make_rule(db, [("slack-1", "slack"), ("pd-1", "pagerduty")])
    dispatch_calls.fail_for.add("pd-1")

    _trigger(manager, "attack_detected", _event())

    health = {h["channel_name"]: h for h in db.get_channel_delivery_health()}
    assert health["slack-1"]["attempts"] == 1
    assert health["slack-1"]["successes"] == 1
    assert health["slack-1"]["last_success"] is True
    assert health["slack-1"]["last_error"] is None

    assert health["pd-1"]["attempts"] == 1
    assert health["pd-1"]["successes"] == 0
    assert health["pd-1"]["last_success"] is False
    assert health["pd-1"]["last_error"] == "boom"


def test_attempts_accumulate_and_last_attempt_is_most_recent(manager, db, dispatch_calls):
    # Distinct URIs so the throttle's event-signature dedup doesn't collapse
    # these into one aggregated notification — each must actually dispatch.
    _make_rule(db, [("slack-1", "slack")], throttle_minutes=0)

    _trigger(manager, "attack_detected", _event(uri="/a"))
    dispatch_calls.fail_for.add("slack-1")
    _trigger(manager, "attack_detected", _event(uri="/b"))

    health = {h["channel_name"]: h for h in db.get_channel_delivery_health()}
    assert health["slack-1"]["attempts"] == 2
    assert health["slack-1"]["successes"] == 1
    # Most recent attempt (the second, failing one) wins for "last_*".
    assert health["slack-1"]["last_success"] is False
    assert health["slack-1"]["last_error"] == "boom"


def test_channel_never_dispatched_to_does_not_appear(manager, db, dispatch_calls):
    _make_rule(db, [("slack-1", "slack")])
    _trigger(manager, "attack_detected", _event())

    names = {h["channel_name"] for h in db.get_channel_delivery_health()}
    assert names == {"slack-1"}


def test_rows_written_before_channel_results_existed_are_skipped_not_crashed(db):
    # A pre-migration row: channels_notified/error_message still work the
    # old way, channel_results defaults to '[]' via the schema DEFAULT —
    # get_channel_delivery_health must not error out on it.
    db.create_alert_history(
        rule_id=1, rule_name="legacy", event_type="attack_detected", severity="high",
        channels_notified=["slack-1"], event_data={}, message="m", status="sent",
        error_message=None,
    )
    assert db.get_channel_delivery_health() == []
