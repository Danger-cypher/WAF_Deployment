"""
Unit tests for CyberSentinel WAF Compliance & Executive Report Service (Phase 4).
Tests report compilation, multi-vector metrics aggregation, schedule CRUD, and dispatch endpoints.
"""
try:
    import pytest
except ImportError:
    class MockPytest:
        class mark:
            @staticmethod
            def asyncio(fn):
                return fn
        @staticmethod
        def raises(expected_exception):
            class Context:
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc_val, exc_tb):
                    if exc_type is None:
                        raise AssertionError(f"Expected {expected_exception} but no exception was raised")
                    self.value = exc_val
                    return issubclass(exc_type, expected_exception)
            return Context()
    pytest = MockPytest()

from app.services import report_service
from app.routes.reports import (
    SchedulePayload,
    DispatchNowPayload,
    get_executive_summary_report,
    get_schedules,
    save_schedule,
    delete_schedule,
    get_report_history,
    dispatch_report_now,
)
from app.services.auth import TokenData
from fastapi import HTTPException


def test_compile_executive_report_aggregates_all_vectors():
    report = report_service.compile_executive_report(hours=24, timeframe_label="24h")
    assert "report_id" in report
    assert report["report_id"].startswith("CSR-")
    assert "risk_level" in report
    assert report["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert "traffic_metrics" in report
    assert "api_posture" in report
    assert "ml_posture" in report
    assert "ddos_posture" in report
    assert "compliance" in report
    assert "narrative" in report

    # Verify API posture structure
    api_p = report["api_posture"]
    assert "discovered_endpoints" in api_p
    assert "shadow_endpoints" in api_p

    # Verify ML posture structure
    ml_p = report["ml_posture"]
    assert "sensitivity_preset" in ml_p
    assert "drift_status" in ml_p

    # Verify DDoS posture structure
    ddos_p = report["ddos_posture"]
    assert "challenge_mode" in ddos_p
    assert "jailed_ips_count" in ddos_p

    # Verify Compliance structure
    comp = report["compliance"]
    assert "engine_enforcement" in comp
    assert "tls_hardening" in comp


def test_generate_html_and_csv_reports():
    report = report_service.compile_executive_report(hours=24, timeframe_label="24h")
    html = report_service.generate_html_report(report)
    assert "<!DOCTYPE html>" in html
    assert "CyberSentinel WAF" in html
    assert report["report_id"] in html
    assert report["risk_level"] in html

    csv_text = report_service.generate_csv_report(report)
    assert "Category,Metric,Value" in csv_text
    assert "Total Requests" in csv_text
    assert "Discovered Endpoints" in csv_text


def test_report_schedule_crud():
    # 1. Create schedule
    sched_data = {
        "name": "Weekly Monday SOC Brief",
        "template": "executive",
        "frequency": "weekly",
        "time_utc": "08:30",
        "day_of_week": 1,
        "recipients_email": "soc@company.com, security@company.com",
        "webhook_url": "https://hooks.slack.com/services/T00/B00/X00",
        "is_active": True,
    }
    sched_id = report_service.create_or_update_report_schedule(sched_data)
    assert sched_id > 0

    # 2. Retrieve schedules
    schedules = report_service.get_report_schedules()
    matching = [s for s in schedules if s["id"] == sched_id]
    assert len(matching) == 1
    assert matching[0]["name"] == "Weekly Monday SOC Brief"
    assert matching[0]["time_utc"] == "08:30"
    assert "soc@company.com" in matching[0]["recipients_email"]

    # 3. Update schedule
    sched_data["id"] = sched_id
    sched_data["name"] = "Weekly Monday SOC Brief (Updated)"
    updated_id = report_service.create_or_update_report_schedule(sched_data)
    assert updated_id == sched_id

    schedules_updated = report_service.get_report_schedules()
    updated = [s for s in schedules_updated if s["id"] == sched_id][0]
    assert updated["name"] == "Weekly Monday SOC Brief (Updated)"

    # 4. Delete schedule
    deleted = report_service.delete_report_schedule(sched_id)
    assert deleted is True

    schedules_after = report_service.get_report_schedules()
    assert not any(s["id"] == sched_id for s in schedules_after)


def test_delivery_history_recording():
    report_service.record_delivery(
        schedule_id=None,
        schedule_name="Manual Test",
        template="compliance",
        status="success",
        destinations="email: soc@company.com",
        error_message=None
    )

    history = report_service.get_delivery_history(limit=5)
    assert len(history) > 0
    latest = history[0]
    assert latest["schedule_name"] == "Manual Test"
    assert latest["status"] == "success"
    assert "soc@company.com" in latest["destinations"]


def test_report_routes():
    admin_user = TokenData(username="admin", role="admin")
    analyst_user = TokenData(username="analyst", role="analyst")

    # GET /reports/executive-summary
    summary = get_executive_summary_report(hours=24, timeframe="24h", current_user=analyst_user)
    assert summary["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    # POST /reports/schedules
    payload = SchedulePayload(
        name="Daily Midnight Check",
        template="compliance",
        frequency="daily",
        time_utc="00:00",
        recipients_email="compliance@company.com",
    )
    save_res = save_schedule(payload, current_user=admin_user)
    assert save_res["status"] == "success"
    sched_id = save_res["id"]

    # GET /reports/schedules
    list_res = get_schedules(current_user=analyst_user)
    assert any(s["id"] == sched_id for s in list_res["data"])

    # DELETE /reports/schedules/{id}
    del_res = delete_schedule(sched_id, current_user=admin_user)
    assert del_res["status"] == "success"

    # GET /reports/history
    hist_res = get_report_history(limit=10, current_user=analyst_user)
    assert isinstance(hist_res["data"], list)


def test_dispatch_now_rejects_empty_destinations():
    admin_user = TokenData(username="admin", role="admin")
    payload = DispatchNowPayload(
        template="executive",
        timeframe="24h",
        recipients_email="",
        webhook_url="",
    )
    with pytest.raises(HTTPException) as exc:
        dispatch_report_now(payload, current_user=admin_user)
    assert exc.value.status_code == 400
    assert "Must provide at least one recipient" in exc.value.detail


if __name__ == "__main__":
    tests = [
        test_compile_executive_report_aggregates_all_vectors,
        test_generate_html_and_csv_reports,
        test_report_schedule_crud,
        test_delivery_history_recording,
        test_report_routes,
        test_dispatch_now_rejects_empty_destinations,
    ]
    for t in tests:
        print(f"Running {t.__name__}...")
        t()
        print(f"  -> PASSED")
    print(f"\nALL {len(tests)} SECURITY REPORT BACKEND TESTS PASSED SUCCESSFULLY!")

