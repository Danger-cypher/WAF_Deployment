"""
CyberSentinel WAF - Unified Compliance & Executive Report Service
Generates multi-vector security reports (WAF, CRS, ML Behavioral Drift, API Protection, DDoS Posture)
and provides automated scheduled delivery via Email (SMTP) and Webhooks (Slack/Teams/SIEM).
"""
import os
import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.services.db_service import get_connection
from app.services.settings_manager import settings_manager

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_META_PATH = os.path.join(BASE_DIR, "..", "ml-waf", "models", "model_metadata.json")
ML_DB_PATH = os.environ.get(
    "ML_DB_PATH",
    os.path.abspath(os.path.join(BASE_DIR, "data", "ml_events.db"))
)


def init_report_tables():
    """Initializes tables for scheduled report configurations and delivery history."""
    try:
        with get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS report_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    template TEXT NOT NULL DEFAULT 'executive',
                    frequency TEXT NOT NULL DEFAULT 'weekly',
                    time_utc TEXT NOT NULL DEFAULT '08:00',
                    day_of_week INTEGER DEFAULT 1,
                    day_of_month INTEGER DEFAULT 1,
                    recipients_email TEXT,
                    webhook_url TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    last_sent_at TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS report_delivery_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    schedule_id INTEGER,
                    schedule_name TEXT,
                    template TEXT NOT NULL,
                    delivered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    status TEXT NOT NULL,
                    destinations TEXT,
                    error_message TEXT
                )
            """)
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to initialize report tables: {e}")


def get_report_schedules() -> List[Dict[str, Any]]:
    init_report_tables()
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM report_schedules ORDER BY id ASC")
        return [dict(r) for r in cursor.fetchall()]


def create_or_update_report_schedule(data: Dict[str, Any]) -> int:
    init_report_tables()
    schedule_id = data.get("id")
    name = data.get("name", "Executive Security Summary")
    template = data.get("template", "executive")
    frequency = data.get("frequency", "weekly")
    time_utc = data.get("time_utc", "08:00")
    day_of_week = int(data.get("day_of_week", 1))
    day_of_month = int(data.get("day_of_month", 1))
    recipients_email = data.get("recipients_email", "")
    webhook_url = data.get("webhook_url", "")
    is_active = 1 if data.get("is_active", True) else 0

    with get_connection() as conn:
        cursor = conn.cursor()
        if schedule_id:
            cursor.execute("""
                UPDATE report_schedules
                SET name = ?, template = ?, frequency = ?, time_utc = ?, day_of_week = ?,
                    day_of_month = ?, recipients_email = ?, webhook_url = ?, is_active = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (name, template, frequency, time_utc, day_of_week, day_of_month,
                  recipients_email, webhook_url, is_active, schedule_id))
            conn.commit()
            return schedule_id
        else:
            cursor.execute("""
                INSERT INTO report_schedules
                    (name, template, frequency, time_utc, day_of_week, day_of_month,
                     recipients_email, webhook_url, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, template, frequency, time_utc, day_of_week, day_of_month,
                  recipients_email, webhook_url, is_active))
            conn.commit()
            return cursor.lastrowid


def delete_report_schedule(schedule_id: int) -> bool:
    init_report_tables()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM report_schedules WHERE id = ?", (schedule_id,))
        conn.commit()
        return cursor.rowcount > 0


def get_delivery_history(limit: int = 50) -> List[Dict[str, Any]]:
    init_report_tables()
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM report_delivery_history ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cursor.fetchall()]


def record_delivery(schedule_id: Optional[int], schedule_name: str, template: str,
                    status: str, destinations: str, error_message: Optional[str] = None):
    try:
        init_report_tables()
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO report_delivery_history
                    (schedule_id, schedule_name, template, status, destinations, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (schedule_id, schedule_name, template, status, destinations, error_message))
            if schedule_id:
                cursor.execute("""
                    UPDATE report_schedules
                    SET last_sent_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (schedule_id,))
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to record report delivery: {e}")


def _get_ml_meta_safe() -> Dict[str, Any]:
    meta_path = os.path.abspath(ML_META_PATH)
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _get_latest_ml_drift() -> Dict[str, Any]:
    if not os.path.exists(ML_DB_PATH):
        return {"drift_detected": False, "status": "nominal", "reasons": []}
    try:
        conn = sqlite3.connect(ML_DB_PATH, timeout=5.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM drift_reports ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        if not row:
            return {"drift_detected": False, "status": "nominal", "reasons": []}
        d = dict(row)
        reasons = []
        if d.get("reasons"):
            try:
                reasons = json.loads(d["reasons"])
            except Exception:
                reasons = []
        status = "breached" if d.get("drift_detected") else "nominal"
        return {
            "drift_detected": bool(d.get("drift_detected")),
            "status": status,
            "avg_threat_score": d.get("avg_threat_score", 0.0),
            "reasons": reasons,
            "timestamp": d.get("timestamp"),
        }
    except Exception as e:
        logger.warning(f"Error querying drift report: {e}")
        return {"drift_detected": False, "status": "nominal", "reasons": []}


def _get_redis_safe():
    try:
        from app.utils.redis_client import get_global_redis_client
        return get_global_redis_client()
    except Exception:
        return None


def _get_jailed_ips_count() -> int:
    r = _get_redis_safe()
    if not r:
        return 0
    try:
        keys = r.keys("waf:jail:*") or []
        keys += r.keys("waf:ddos:jail:*") or []
        return len(set(keys))
    except Exception:
        return 0


def compile_executive_report(hours: int = 24, timeframe_label: str = "24h") -> Dict[str, Any]:
    """Compiles a unified multi-vector security report covering WAF, CRS, ML, API, and DDoS."""
    from app.services.stats_calculator import calculate_stats, get_top_ips, get_attack_types_distribution
    from app.services.db_service import get_all_discovered_endpoints, get_api_spec, get_all_protected_apps
    from app.services import api_spec

    # 1. Core traffic stats
    stats = calculate_stats(hours)
    attack_types = get_attack_types_distribution(hours)
    top_ips = get_top_ips(hours)

    total_requests = stats.get("total_requests", 0)
    total_blocked = stats.get("total_blocked", 0)
    block_rate = (total_blocked / total_requests * 100) if total_requests > 0 else 0.0

    # 2. API Security Posture (Phase 1)
    discovered_endpoints = get_all_discovered_endpoints() or []
    spec_record = get_api_spec()
    shadow_endpoints_count = 0
    spec_endpoints_count = 0
    if spec_record:
        try:
            parsed = api_spec.parse_spec(spec_record["raw_content"])
            drift = api_spec.compute_drift(parsed["endpoints"], discovered_endpoints)
            shadow_endpoints_count = len(drift.get("shadow_endpoints", []))
            spec_endpoints_count = len(parsed.get("endpoints", []))
        except Exception as e:
            logger.warning(f"Error computing API drift for report: {e}")

    # 3. ML Behavioral Anomaly Posture (Phase 3)
    ml_tuning = settings_manager.get_ml_tuning()
    ml_meta = _get_ml_meta_safe()
    ml_drift = _get_latest_ml_drift()

    # 4. DDoS & Bot Mitigation Posture (Phase 2)
    ddos_cfg = settings_manager.get_ddos_bot_mitigation()
    threat_intel = settings_manager.get_threat_intel()
    jailed_ips_count = _get_jailed_ips_count()
    blocked_asns = threat_intel.get("blocked_asns", [])

    # 5. Compliance & Health Posture
    waf_settings = settings_manager.get_waf_settings()
    hardening = settings_manager.get_hardening()
    log_settings = settings_manager.get_log_settings()
    anti_defacement = settings_manager.get_anti_defacement()
    protected_apps = get_all_protected_apps() or []

    # Risk level determination
    blocked_per_day = total_blocked / (hours / 24.0)
    risk_level = "LOW"
    risk_color = "var(--success-color)"
    if blocked_per_day > 1000 or block_rate > 10.0 or ml_drift.get("drift_detected"):
        risk_level = "CRITICAL"
        risk_color = "var(--danger-color)"
    elif blocked_per_day > 200 or block_rate > 3.0 or shadow_endpoints_count > 10:
        risk_level = "HIGH"
        risk_color = "var(--sev-high)"
    elif blocked_per_day > 20 or block_rate > 0.5:
        risk_level = "MEDIUM"
        risk_color = "var(--warning-color)"

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = f"CSR-{int(time.time()):X}-{timeframe_label.upper()}"

    # Executive narrative
    narrative = [
        f"Over the monitored {timeframe_label} timeframe, the CyberSentinel WAF Engine inspected {total_requests:,} total HTTP requests, blocking {total_blocked:,} malicious attempts ({block_rate:.2f}% block rate).",
        f"API Security Inventory identified {len(discovered_endpoints)} total endpoints, with {shadow_endpoints_count} uncataloged shadow endpoints detected outside active OpenAPI specifications." if spec_record else f"API Security Inventory tracks {len(discovered_endpoints)} discovered endpoints across protected hosts.",
        f"Behavioral Anomaly Engine operates under the '{ml_tuning.get('sensitivity_preset', 'balanced').capitalize()}' sensitivity preset, with active telemetry evaluated as {ml_drift.get('status', 'nominal').upper()} drift.",
        f"DDoS and Bot mitigation enforced '{ddos_cfg.get('challenge_mode', 'Turnstile/Native').upper()}' challenge mode with {jailed_ips_count} active dynamic IP auto-jails and {len(blocked_asns)} blocked autonomous system networks (ASNs).",
        f"Overall operational risk is rated as {risk_level} based on active multi-vector threat indicators."
    ]

    return {
        "report_id": report_id,
        "timeframe": timeframe_label,
        "hours": hours,
        "generated_at": generated_at,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "narrative": " ".join(narrative),
        "traffic_metrics": {
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "block_rate": round(block_rate, 2),
            "clean_requests": max(0, total_requests - total_blocked),
            "unique_ips": stats.get("unique_ips", len(top_ips)),
            "sqli_count": stats.get("sqli_count", 0),
            "xss_count": stats.get("xss_count", 0),
            "top_attack_type": stats.get("top_attack_type", "None"),
        },
        "attack_distribution": attack_types,
        "top_ips": top_ips[:10],
        "api_posture": {
            "discovered_endpoints": len(discovered_endpoints),
            "documented_endpoints": spec_endpoints_count,
            "shadow_endpoints": shadow_endpoints_count,
            "spec_loaded": bool(spec_record),
        },
        "ml_posture": {
            "sensitivity_preset": ml_tuning.get("sensitivity_preset", "balanced"),
            "xgboost_version": ml_meta.get("xgboost", {}).get("version", "production"),
            "xgboost_accuracy": ml_meta.get("xgboost", {}).get("accuracy", 1.0),
            "isolation_forest_version": ml_meta.get("isolation_forest", {}).get("version", "production"),
            "drift_status": ml_drift.get("status", "nominal"),
            "drift_breached": ml_drift.get("drift_detected", False),
            "drift_reasons": ml_drift.get("reasons", []),
        },
        "ddos_posture": {
            "challenge_mode": ddos_cfg.get("challenge_mode", "turnstile"),
            "jailed_ips_count": jailed_ips_count,
            "blocked_asns_count": len(blocked_asns),
            "rate_limit_rpm": ddos_cfg.get("rate_limit_rpm", 120),
        },
        "compliance": {
            "engine_enforcement": waf_settings.get("secRuleEngine", "On"),
            "tls_hardening": bool(hardening.get("hsts_enabled", True)),
            "anti_defacement": anti_defacement.get("status", "ACTIVE") if isinstance(anti_defacement, dict) else "ACTIVE",
            "audit_logging": bool(log_settings.get("auditEnabled", True)),
            "api_inventory_control": "ENFORCED" if spec_record else "MONITORED",
            "ml_anomaly_monitoring": "ACTIVE",
            "active_hosts": len([a for a in protected_apps if a.get("is_active", True)]),
            "total_hosts": len(protected_apps),
        }
    }


def generate_html_report(data: Dict[str, Any]) -> str:
    """Generates an executive-ready HTML document for email dispatch and PDF printouts."""
    tm = data["traffic_metrics"]
    ml = data["ml_posture"]
    api_p = data["api_posture"]
    ddos = data["ddos_posture"]
    comp = data["compliance"]

    rows_attacks = ""
    for a in data.get("attack_distribution", [])[:6]:
        rows_attacks += f"<tr><td>{a.get('attack_type', 'Unknown')}</td><td style='text-align:right;'>{a.get('count', 0):,}</td></tr>"

    rows_ips = ""
    for ip in data.get("top_ips", [])[:5]:
        rows_ips += f"<tr><td><code>{ip.get('ip', 'Unknown')}</code></td><td>{ip.get('country', 'N/A')}</td><td style='text-align:right;'>{ip.get('count', 0):,}</td></tr>"

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>CyberSentinel WAF Executive Security Report - {data['report_id']}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #f3f4f6; margin: 0; padding: 24px; }}
    .container {{ max-width: 800px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 32px; }}
    .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #374151; padding-bottom: 20px; }}
    .logo {{ font-size: 20px; font-weight: 800; color: #00ff9d; letter-spacing: 0.5px; }}
    .badge {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }}
    .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid #eab308; }}
    .badge-low {{ background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }}
    .narrative {{ background: #1f2937; border-left: 4px solid #00ff9d; padding: 16px; border-radius: 4px; margin: 24px 0; font-size: 14px; line-height: 1.6; color: #d1d5db; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 24px 0; }}
    .stat-card {{ background: #1f2937; padding: 16px; border-radius: 8px; border: 1px solid #374151; }}
    .stat-label {{ font-size: 12px; color: #9ca3af; text-transform: uppercase; font-weight: 600; }}
    .stat-value {{ font-size: 26px; font-weight: 800; color: #fff; margin-top: 4px; }}
    .section-title {{ font-size: 16px; font-weight: 700; margin: 24px 0 12px 0; color: #00ff9d; border-bottom: 1px solid #374151; padding-bottom: 8px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 20px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #374151; }}
    th {{ background: #1f2937; color: #9ca3af; font-weight: 600; }}
    code {{ background: #374151; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
    .footer {{ font-size: 11px; color: #6b7280; text-align: center; border-top: 1px solid #374151; padding-top: 16px; margin-top: 32px; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <div class="logo">🛡️ CYBERSENTINEL WAF</div>
            <div style="font-size: 18px; font-weight: 700; color: #fff; margin-top: 6px;">Executive Security Summary</div>
            <div style="font-size: 12px; color: #9ca3af; margin-top: 4px;">Report ID: {data['report_id']} | Timeframe: {data['timeframe']}</div>
        </div>
        <div style="text-align: right;">
            <div class="badge badge-{data['risk_level'].lower()}">{data['risk_level']} RISK</div>
            <div style="font-size: 11px; color: #9ca3af; margin-top: 6px;">Generated: {data['generated_at']}</div>
        </div>
    </div>

    <div class="narrative">
        <strong>Executive Overview:</strong> {data['narrative']}
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Total Requests</div>
            <div class="stat-value">{tm['total_requests']:,}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Blocked Violations</div>
            <div class="stat-value" style="color: #ef4444;">{tm['total_blocked']:,}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Block Rate</div>
            <div class="stat-value" style="color: #f97316;">{tm['block_rate']}%</div>
        </div>
    </div>

    <div class="section-title">Posture Breakdown Across Security Layers</div>
    <table>
        <tr><th>Protection Vector</th><th>Key Metric / Status</th><th>Standard Citation</th></tr>
        <tr><td>Core Ruleset Enforcement</td><td>{comp['engine_enforcement']} ({comp['active_hosts']}/{comp['total_hosts']} Hosts)</td><td>PCI-DSS v4.0 Req 6.4.2</td></tr>
        <tr><td>API Inventory & Shadow Endpoints</td><td>{api_p['discovered_endpoints']} Discovered / {api_p['shadow_endpoints']} Shadow</td><td>OWASP API9:2023 Inventory Management</td></tr>
        <tr><td>AI Behavioral Anomaly Ensemble</td><td>Preset: {ml['sensitivity_preset'].capitalize()} (Drift: {ml['drift_status'].upper()})</td><td>NIST SP 800-53 SI-4 Monitoring</td></tr>
        <tr><td>DDoS & Datacenter Mitigation</td><td>Challenge: {ddos['challenge_mode'].upper()} ({ddos['jailed_ips_count']} Jailed IPs)</td><td>PCI-DSS v4.0 Automated Defense</td></tr>
        <tr><td>TLS / HSTS Dynamic Hardening</td><td>{'ENABLED' if comp['tls_hardening'] else 'DISABLED'}</td><td>PCI-DSS v4.0 Req 4.2.1 / OWASP A02</td></tr>
    </table>

    <div class="section-title">Top Detected Attack Categories</div>
    <table>
        <tr><th>Violation Type</th><th style="text-align:right;">Detections</th></tr>
        {rows_attacks if rows_attacks else '<tr><td colspan="2" style="text-align:center; color:#9ca3af;">No threat detections recorded.</td></tr>'}
    </table>

    <div class="section-title">Top Attacking Source Originators</div>
    <table>
        <tr><th>Source IP Address</th><th>Country</th><th style="text-align:right;">Hits</th></tr>
        {rows_ips if rows_ips else '<tr><td colspan="3" style="text-align:center; color:#9ca3af;">No attacking IP originators recorded.</td></tr>'}
    </table>

    <div class="footer">
        Generated automatically by CyberSentinel WAF Enterprise Security Engine. Confidential SOC Distribution.
    </div>
</div>
</body>
</html>
"""


def generate_csv_report(data: Dict[str, Any]) -> str:
    """Generates a plain-text CSV export of the compiled report."""
    lines = [
        "Category,Metric,Value",
        f"General,Report ID,{data.get('report_id')}",
        f"General,Generated At,{data.get('generated_at')}",
        f"General,Timeframe,{data.get('timeframe')}",
        f"General,Risk Level,{data.get('risk_level')}",
        f"Traffic,Total Requests,{data['traffic_metrics']['total_requests']}",
        f"Traffic,Total Blocked,{data['traffic_metrics']['total_blocked']}",
        f"Traffic,Block Rate,{data['traffic_metrics']['block_rate']}%",
        f"Traffic,Unique IPs,{data['traffic_metrics']['unique_ips']}",
        f"API Security,Discovered Endpoints,{data['api_posture']['discovered_endpoints']}",
        f"API Security,Documented Endpoints,{data['api_posture']['documented_endpoints']}",
        f"API Security,Shadow Endpoints,{data['api_posture']['shadow_endpoints']}",
        f"ML Ensemble,Sensitivity Preset,{data['ml_posture']['sensitivity_preset']}",
        f"ML Ensemble,Drift Status,{data['ml_posture']['drift_status']}",
        f"DDoS,Challenge Mode,{data['ddos_posture']['challenge_mode']}",
        f"DDoS,Jailed IPs,{data['ddos_posture']['jailed_ips_count']}",
        f"Compliance,WAF Enforcement,{data['compliance']['engine_enforcement']}",
        f"Compliance,TLS Hardening,{data['compliance']['tls_hardening']}",
        f"Compliance,Active Hosts,{data['compliance']['active_hosts']}",
    ]
    lines.append("\nAttack Category Breakdown:")
    lines.append("Attack Type,Count")
    for a in data.get("attack_distribution", []):
        lines.append(f'"{a.get("attack_type", "Unknown")}",{a.get("count", 0)}')

    lines.append("\nTop Threat Originators:")
    lines.append("IP,Country,Count")
    for ip in data.get("top_ips", []):
        lines.append(f'"{ip.get("ip", "Unknown")}","{ip.get("country", "")}",{ip.get("count", 0)}')

    return "\n".join(lines)


def dispatch_report(
    report_data: Dict[str, Any],
    emails: Optional[List[str]] = None,
    webhook_url: Optional[str] = None,
    schedule_id: Optional[int] = None,
    schedule_name: str = "Manual Dispatch"
) -> Tuple[bool, str]:
    """Dispatches executive report to email list and webhook URL."""
    from app.services.alert_db_service import alert_db_service
    from app.services.alert_dispatcher import EmailNotificationChannel, WebhookNotificationChannel

    emails = emails or []
    destinations = []
    if emails:
        destinations.append(f"email: {', '.join(emails)}")
    if webhook_url:
        destinations.append(f"webhook: {webhook_url}")

    dest_str = " | ".join(destinations) or "None"
    errors = []

    html_content = generate_html_report(report_data)

    # 1. Send via Email
    if emails:
        # Check if an existing email channel is configured in alert channels
        channels = alert_db_service.get_channels(enabled_only=True)
        email_channel = next((c for c in channels if c.get("channel_type") == "email"), None)

        if email_channel and email_channel.get("config"):
            cfg = dict(email_channel["config"])
            cfg["to_addrs"] = emails
            sender = EmailNotificationChannel()
            # Send email
            ok, err = sender.send(
                config=cfg,
                severity=report_data.get("risk_level", "INFO"),
                event_type="Executive Security Report",
                message=report_data.get("narrative", ""),
                event_data=report_data.get("traffic_metrics", {})
            )
            if not ok:
                errors.append(f"Email delivery error: {err}")
        else:
            errors.append("No active SMTP Email channel configured in Alerts & Integrations.")

    # 2. Send via Webhook
    if webhook_url:
        sender = WebhookNotificationChannel()
        cfg = {"url": webhook_url, "method": "POST", "headers": {"Content-Type": "application/json"}}
        ok, err = sender.send(
            config=cfg,
            severity=report_data.get("risk_level", "INFO"),
            event_type="Executive Security Report",
            message=report_data.get("narrative", ""),
            event_data={
                "report_id": report_data.get("report_id"),
                "risk_level": report_data.get("risk_level"),
                "timeframe": report_data.get("timeframe"),
                "traffic_metrics": report_data.get("traffic_metrics"),
                "api_posture": report_data.get("api_posture"),
                "ml_posture": report_data.get("ml_posture"),
                "ddos_posture": report_data.get("ddos_posture"),
            }
        )
        if not ok:
            errors.append(f"Webhook delivery error: {err}")

    status_str = "failed" if (errors and len(errors) == len(destinations)) else "partial" if errors else "success"
    err_str = "; ".join(errors) if errors else None
    record_delivery(
        schedule_id=schedule_id,
        schedule_name=schedule_name,
        template=report_data.get("template", "executive"),
        status=status_str,
        destinations=dest_str,
        error_message=err_str
    )

    if status_str == "failed":
        return False, err_str or "Dispatch failed"
    return True, "Dispatch completed successfully" if not errors else f"Partial dispatch: {err_str}"


# ──────────────────────────────────────────────────────────────
#  Scheduled Report Dispatcher Background Loop
# ──────────────────────────────────────────────────────────────
_scheduler_started = False
_scheduler_lock = threading.Lock()


def _report_scheduler_loop():
    logger.info("Report delivery scheduler worker started.")
    while True:
        try:
            now_utc = datetime.now(timezone.utc)
            cur_time_str = now_utc.strftime("%H:%M")
            cur_dow = now_utc.weekday() + 1  # 1 = Monday, 7 = Sunday
            cur_dom = now_utc.day

            schedules = get_report_schedules()
            for s in schedules:
                if not s.get("is_active"):
                    continue

                sched_time = s.get("time_utc", "08:00")
                if sched_time != cur_time_str:
                    continue

                freq = s.get("frequency", "weekly")
                due = False

                if freq == "daily":
                    due = True
                elif freq == "weekly" and s.get("day_of_week") == cur_dow:
                    due = True
                elif freq == "monthly" and s.get("day_of_month") == cur_dom:
                    due = True

                # Check if already sent in the last 2 hours to avoid repeat triggers
                last_sent = s.get("last_sent_at")
                if last_sent:
                    try:
                        last_dt = datetime.fromisoformat(last_sent.replace("Z", "+00:00"))
                        if (now_utc - last_dt).total_seconds() < 7200:
                            due = False
                    except Exception:
                        pass

                if due:
                    logger.info(f"Triggering scheduled report dispatch for: {s.get('name')}")
                    timeframe_hours = 24 if freq == "daily" else 168 if freq == "weekly" else 720
                    report_data = compile_executive_report(hours=timeframe_hours, timeframe_label=freq)
                    report_data["template"] = s.get("template", "executive")

                    emails = [e.strip() for e in (s.get("recipients_email") or "").split(",") if e.strip()]
                    webhook = s.get("webhook_url") or None

                    dispatch_report(
                        report_data=report_data,
                        emails=emails,
                        webhook_url=webhook,
                        schedule_id=s.get("id"),
                        schedule_name=s.get("name")
                    )

        except Exception as e:
            logger.error(f"Error in report scheduler loop: {e}")

        time.sleep(60)


def start_report_scheduler():
    global _scheduler_started
    with _scheduler_lock:
        if not _scheduler_started:
            _scheduler_started = True
            init_report_tables()
            t = threading.Thread(target=_report_scheduler_loop, daemon=True)
            t.start()
