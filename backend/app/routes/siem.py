"""
routes/siem.py — CyberSentinel WAF
=====================================
Pull-based bulk SIEM export (roadmap item — closes the gap the CyberSentinel-
vs-Cloudflare audit flagged: the existing syslog notification channel only
fires for events matching a configured alert rule, not the full waf_events/
ml_events stream a real SOC wants for correlation).

Deliberately pull, not push: a SIEM's own collector polls this endpoint on
a schedule (Splunk's generic REST/HTTP input, QRadar's log source, Sentinel's
data connector, or a plain cron+curl — every mainstream SIEM already
supports polling a CEF/LEEF text endpoint). That keeps this WAF from having
to manage outbound delivery, retries, or a destination-type abstraction —
a meaningfully bigger, riskier feature this round deliberately doesn't
build (see project memory).

Auth: same Depends(require_any_role) as every other read route in this
file's sibling routes/logs.py — which already transparently accepts an
X-API-Key header via auth.py's get_current_user() as an alternative to a
session cookie, so a SIEM's automated poller authenticates exactly like an
interactive analyst does, no new auth mechanism needed.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.services import clickhouse_service, siem_export
from app.services.auth import require_any_role, TokenData

router = APIRouter()

_MEDIA_TYPES = {"cef": "text/plain; charset=utf-8", "leef": "text/plain; charset=utf-8"}


@router.get("/siem/export")
async def export_events(
    format: str = Query("cef", pattern="^(cef|leef)$", description="'cef' or 'leef'"),
    source: str = Query("both", pattern="^(waf|ml|both)$", description="'waf', 'ml', or 'both'"),
    since: str = Query(
        None,
        description=(
            "ISO 8601 timestamp — export events ingested strictly after this. "
            "Omit on a poller's first call; every response's X-Next-Cursor header "
            "gives the value to pass on the next call, so a poller only ever needs "
            "to remember one string between polls."
        ),
    ),
    limit: int = Query(500, ge=1, le=5000),
    current_user: TokenData = Depends(require_any_role),
):
    """
    Cursor-based bulk export — NOT offset-paginated, since a continuously
    re-polled export must never shift what "page 2" means between calls
    (see clickhouse_service.query_waf_events_since()'s header comment for
    why). Each call returns everything ingested since `since` (or the last
    ~5 minutes, if this is the poller's first call and it has no cursor
    yet), up to `limit` rows per source, oldest first.

    Response body is plain CEF or LEEF text, one event per line — that's
    the wire format every mainstream SIEM's generic collector already
    expects, not a JSON wrapper. The next cursor rides in a response
    header (X-Next-Cursor) instead, since the body itself is plain text.
    """
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="'since' must be a valid ISO 8601 timestamp.",
            )
    else:
        # First-ever call from a fresh poller: a bounded recent window
        # rather than "the beginning of time" — an admin turning this
        # integration on for the first time almost certainly wants "start
        # from now", not a bulk historical dump of the last 90 days.
        since_dt = datetime.now(timezone.utc).replace(microsecond=0)
        from datetime import timedelta
        since_dt = since_dt - timedelta(minutes=5)

    waf_rows = clickhouse_service.query_waf_events_since(since_dt, limit=limit) if source in ("waf", "both") else []
    ml_rows = clickhouse_service.query_ml_events_since(since_dt, limit=limit) if source in ("ml", "both") else []

    lines = siem_export.format_events(waf_rows, ml_rows, format)

    # Next cursor = the max ingested_at actually returned, not "now" —
    # using wall-clock "now" would silently skip any row whose insert was
    # still in-flight (a slightly-delayed ClickHouse write) at the moment
    # this request ran. Falls back to the request's own `since` when
    # nothing new was returned, so an idle poller's cursor never regresses.
    all_ingested = [r["ingested_at"] for r in waf_rows] + [r["ingested_at"] for r in ml_rows]
    next_cursor = max(all_ingested) if all_ingested else since_dt

    body = ("\n".join(lines) + "\n") if lines else ""
    return Response(
        content=body,
        media_type=_MEDIA_TYPES[format],
        headers={
            "X-Next-Cursor": next_cursor.isoformat(),
            "X-Event-Count": str(len(lines)),
        },
    )
