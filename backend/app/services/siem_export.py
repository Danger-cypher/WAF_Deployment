"""
siem_export.py — CyberSentinel WAF
===============================================
Formats waf_events/ml_events rows (ClickHouse) as CEF (ArcSight Common
Event Format) or LEEF (IBM QRadar Log Event Extended Format) lines for
bulk SIEM export. See routes/siem.py for the pull-based export endpoint
this feeds.

Format rules verified against the actual specs before writing this (not
typed from memory) — see:
  - CEF: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
  - LEEF: IBM's "Log Event Extended Format (LEEF) Version 2" guide.

CEF header fields (pipe-delimited): escape '|' and '\\', and collapse
newlines/CRs to spaces — a raw ModSecurity `message` field can absolutely
contain either. CEF extension values (key=value pairs): escape '=' and
'\\', and turn newlines/CRs into literal \\n/\\r. Spaces inside an
extension value are NOT escaped — CEF parsers scan for the next bare
`key=` token to find a value's end, which is a documented, if unusual,
property of the format; this is a deliberate non-escape, not an oversight.

LEEF uses the simpler tab-separated key=value form (LEEF 1.0/2.0-without-
a-custom-delimiter) rather than the optional custom-delimiter variant —
chosen because it's unambiguous and needs no delimiter negotiation in the
header, at the cost of nothing a real SIEM's LEEF parser doesn't already
support.
"""
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

# CEF severity is 1-10, higher = more severe. This codebase's own severity
# vocabulary (waf_events.severity, alert_dispatcher.py's identical
# _SEVERITY_CODES) is the 5-value {critical,high,medium,low,info} set —
# reused here rather than inventing a second vocabulary, just remapped to
# CEF's numeric direction (which is the OPPOSITE of RFC 5424's, where
# lower = more severe).
_CEF_SEVERITY = {"critical": 10, "high": 7, "medium": 5, "low": 3, "info": 1}

# ml_events has no severity column (it's a raw scoring record, not a
# triaged alert) — derived from `decision` instead, using the same
# routing bands ml-waf/threat_score.py's get_routing_outcome() already
# defines ("block" > "rate_limit" > "log" > "allow").
_ML_DECISION_SEVERITY = {"block": 9, "rate_limit": 6, "log": 4, "allow": 1}


def _cef_header_escape(value: Any) -> str:
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    return s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def _cef_extension_escape(value: Any) -> str:
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace("=", "\\=")
    s = s.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r")
    # Strip other control chars (0x00-0x1F) outside \n/\r/\t, which a raw
    # ModSecurity message or URI could in principle contain — nothing in
    # this codebase currently sanitizes those before they reach here.
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s)


def _leef_escape(value: Any) -> str:
    """LEEF's tab-delimited attribute section breaks if a value contains a
    literal tab; there's no defined escape for one in the base spec, so —
    same conservative choice as the CEF control-char strip above — a
    literal tab in source data is replaced with a space rather than
    silently desynchronizing every attribute after it for the SIEM
    parser."""
    s = "" if value is None else str(value)
    s = s.replace("\t", " ")
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def _epoch_millis(ts: Any) -> int:
    if isinstance(ts, datetime):
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    return 0


def waf_event_to_cef(row: Dict[str, Any]) -> str:
    severity_num = _CEF_SEVERITY.get(str(row.get("severity") or "").lower(), 5)
    signature_id = row.get("rule_id") or "waf-block"
    name = _cef_header_escape(row.get("message") or "ModSecurity rule match")

    ext_parts = [
        f"rt={_epoch_millis(row.get('timestamp'))}",
        f"src={_cef_extension_escape(row.get('client_ip'))}",
        f"requestMethod={_cef_extension_escape(row.get('method'))}",
        f"request={_cef_extension_escape(row.get('uri'))}",
        f"dhost={_cef_extension_escape(row.get('hostname'))}",
        f"outcome={_cef_extension_escape(row.get('http_code'))}",
        f"cs1Label=AttackType cs1={_cef_extension_escape(row.get('attack_type'))}",
        f"cs2Label=SourceASNOrg cs2={_cef_extension_escape(row.get('source_asn_org'))}",
        f"cs3Label=Country cs3={_cef_extension_escape(row.get('country'))}",
        f"externalId={_cef_extension_escape(row.get('id'))}",
    ]

    return (
        f"CEF:0|CyberSentinel|WAF|1.0|{_cef_header_escape(signature_id)}|{name}|{severity_num}|"
        + " ".join(ext_parts)
    )


def ml_event_to_cef(row: Dict[str, Any]) -> str:
    decision = str(row.get("decision") or "log").lower()
    severity_num = _ML_DECISION_SEVERITY.get(decision, 4)
    name = f"ML threat scoring: {decision}"

    ext_parts = [
        f"rt={_epoch_millis(row.get('timestamp'))}",
        f"src={_cef_extension_escape(row.get('remote_addr'))}",
        f"requestMethod={_cef_extension_escape(row.get('method'))}",
        f"request={_cef_extension_escape(row.get('uri'))}",
        f"requestClientApplication={_cef_extension_escape(row.get('ua'))}",
        f"act={_cef_extension_escape(decision)}",
        f"cs1Label=ThreatScore cs1={_cef_extension_escape(row.get('threat_score'))}",
        f"cs2Label=CRSScore cs2={_cef_extension_escape(row.get('crs_score'))}",
        f"cs3Label=XGBoostProb cs3={_cef_extension_escape(row.get('xgb_prob'))}",
        f"cs4Label=IsolationForestScore cs4={_cef_extension_escape(row.get('iso_score'))}",
        f"externalId={_cef_extension_escape(row.get('unique_id'))}",
    ]

    return (
        f"CEF:0|CyberSentinel|ML-WAF|1.0|{_cef_header_escape(decision)}|{_cef_header_escape(name)}|{severity_num}|"
        + " ".join(ext_parts)
    )


def waf_event_to_leef(row: Dict[str, Any]) -> str:
    severity_num = _CEF_SEVERITY.get(str(row.get("severity") or "").lower(), 5)
    signature_id = row.get("rule_id") or "waf-block"

    attrs = [
        f"devTime={_epoch_millis(row.get('timestamp'))}",
        f"src={_leef_escape(row.get('client_ip'))}",
        f"method={_leef_escape(row.get('method'))}",
        f"url={_leef_escape(row.get('uri'))}",
        f"dst={_leef_escape(row.get('hostname'))}",
        f"sev={severity_num}",
        f"cat={_leef_escape(row.get('attack_type'))}",
        f"msg={_leef_escape(row.get('message'))}",
        f"httpStatus={_leef_escape(row.get('http_code'))}",
        f"country={_leef_escape(row.get('country'))}",
    ]

    return f"LEEF:2.0|CyberSentinel|WAF|1.0|{_leef_escape(signature_id)}|" + "\t".join(attrs)


def ml_event_to_leef(row: Dict[str, Any]) -> str:
    decision = str(row.get("decision") or "log").lower()
    severity_num = _ML_DECISION_SEVERITY.get(decision, 4)

    attrs = [
        f"devTime={_epoch_millis(row.get('timestamp'))}",
        f"src={_leef_escape(row.get('remote_addr'))}",
        f"method={_leef_escape(row.get('method'))}",
        f"url={_leef_escape(row.get('uri'))}",
        f"sev={severity_num}",
        "cat=ml_scoring",
        f"usrAgent={_leef_escape(row.get('ua'))}",
        f"threatScore={_leef_escape(row.get('threat_score'))}",
        f"decision={_leef_escape(decision)}",
    ]

    return f"LEEF:2.0|CyberSentinel|ML-WAF|1.0|{_leef_escape(decision)}|" + "\t".join(attrs)


def format_events(waf_rows: List[Dict[str, Any]], ml_rows: List[Dict[str, Any]], fmt: str) -> List[str]:
    """Formats and interleaves both event sources by ingested_at so the
    exported stream is roughly chronological, not "all WAF events then all
    ML events" — matters for a SIEM correlating the two."""
    tagged = [(r["ingested_at"], "waf", r) for r in waf_rows] + [(r["ingested_at"], "ml", r) for r in ml_rows]
    tagged.sort(key=lambda t: t[0])

    lines = []
    for _, kind, row in tagged:
        try:
            if fmt == "leef":
                lines.append(waf_event_to_leef(row) if kind == "waf" else ml_event_to_leef(row))
            else:
                lines.append(waf_event_to_cef(row) if kind == "waf" else ml_event_to_cef(row))
        except Exception:
            # One malformed row must never break the whole export batch —
            # skip it, the poller still advances past everything else.
            continue
    return lines
