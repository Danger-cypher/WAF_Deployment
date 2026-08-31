import hashlib
import os
import re
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from typing import List, Dict, Any
from app.models.response_models import PaginatedEndpoints
from app.services import db_service, clickhouse_service, api_spec
from app.services.auth import require_admin, require_any_role, TokenData

router = APIRouter()

# Name patterns (substring match, case-insensitive) that suggest a query
# param carries sensitive data. Deliberately conservative and name-only —
# this flags "worth a human look", not a confirmed leak: a param named
# `email` on a public newsletter signup is normal; the point is surfacing
# it for review, not asserting a violation. Values are never captured (see
# api_discovery.extract_param_names), so this is the only signal available
# short of a real schema/PII classifier.
_SENSITIVE_PARAM_PATTERNS = (
    "email", "e_mail", "phone", "mobile",
    "ssn", "social_security", "tax_id", "passport", "national_id",
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "auth",
    "credit_card", "card_number", "cardnum", "cvv", "cvc",
    "account_number", "iban", "routing_number", "bank",
    "dob", "date_of_birth", "birthdate",
    "address", "zip", "postal",
)


def flag_sensitive_params(param_names: List[str]) -> List[str]:
    """Returns the subset of param_names whose NAME (not value — values are
    never stored) matches a known sensitive-data pattern."""
    if not param_names:
        return []
    return [
        p for p in param_names
        if any(pattern in p.lower() for pattern in _SENSITIVE_PARAM_PATTERNS)
    ]


def _overlay_real_threat_counts(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Replace each endpoint's malicious_count/suspicious_count — normally
    derived at discovery time from nginx status codes plus a narrow
    keyword heuristic (see api_discovery.py) — with real counts from
    ModSecurity's own detections in waf_events, keyed by (uri, method).
    No-ops (leaves the heuristic-derived counts as-is) if ClickHouse isn't
    available, since that heuristic is the only signal SQLite-only
    deployments have.
    """
    if not clickhouse_service.is_available():
        return endpoints
    threat_counts = clickhouse_service.get_endpoint_threat_counts()
    if not threat_counts:
        return endpoints
    for ep in endpoints:
        key = (ep.get("uri", ""), ep.get("method", ""))
        counts = threat_counts.get(key)
        if counts is not None:
            ep["malicious_count"] = counts["malicious_count"]
            ep["suspicious_count"] = counts["suspicious_count"]
    return endpoints


def calculate_endpoint_score(ep: Dict[str, Any]) -> Dict[str, Any]:
    """Computes a security and performance score (0-100) and grade (A-F) for an endpoint."""
    score = 100
    hit_count = ep.get("hit_count", 0)

    # 1. Latency deductions
    avg_latency = ep.get("avg_response_time_ms", 0.0)
    if avg_latency > 2000.0:
        score -= 30
    elif avg_latency > 500.0:
        score -= 15
    elif avg_latency > 200.0:
        score -= 5

    # 2. Error ratio deductions
    if hit_count > 0:
        error_ratio = ep.get("error_count", 0) / hit_count
        score -= int(error_ratio * 40)

    # 3. Threat ratio deductions (malicious and suspicious)
    if hit_count > 0:
        threat_ratio = (
            ep.get("malicious_count", 0) + ep.get("suspicious_count", 0)
        ) / hit_count
        score -= int(threat_ratio * 50)

    # 4. HTTPS deduction — has_https is a tri-state (0=confirmed http,
    # 1=confirmed https, 2=not yet measured; see api_discovery.py). Only
    # deduct on a confirmed-insecure hit — an unmeasured endpoint (older log
    # lines that predate scheme capture) is unknown, not guilty.
    is_confirmed_insecure = ep.get("has_https", 2) == 0
    if is_confirmed_insecure:
        score -= 20

    # 5. Versioning deduction
    if not ep.get("has_versioning", 0):
        score -= 10

    # 6. Compression deduction — content_encoding is "" only when a real
    # response was checked and had no Content-Encoding header; "unknown"
    # means not yet measured and must not be treated as "known absent".
    encoding = ep.get("content_encoding", "unknown")
    if encoding == "":
        score -= 5

    # 7. Sensitive-param-over-plaintext deduction. A sensitive-named param
    # existing at all stays a non-penalized, informational-only signal (see
    # the comment on `sensitive_params` below) — an `email` field on a
    # public signup form isn't a vulnerability. But a sensitive-named param
    # on a CONFIRMED-plaintext (has_https == 0) endpoint is an objective
    # risk regardless of what the field is for, on top of the flat HTTPS
    # deduction above (that penalizes the endpoint being insecure at all;
    # this penalizes it carrying sensitive-looking data while insecure,
    # which is worse).
    sensitive_params = flag_sensitive_params(ep.get("param_names") or [])
    if sensitive_params and is_confirmed_insecure:
        score -= 15

    # Clamp score
    score = max(0, min(100, score))

    # Assign Grade
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    # Traffic Source Classification
    # Determines whether this endpoint is seen predominantly from external internet
    # traffic, internal management traffic, or a mix of both.
    external = ep.get("external_hit_count", 0)
    internal = ep.get("internal_hit_count", 0)
    total_classified = external + internal
    if total_classified == 0:
        traffic_source = "Unknown"
    elif total_classified > 0 and internal == 0:
        traffic_source = "External"
    elif total_classified > 0 and external == 0:
        traffic_source = "Internal"
    elif external / total_classified >= 0.8:
        traffic_source = "External"
    elif internal / total_classified >= 0.8:
        traffic_source = "Internal"
    else:
        traffic_source = "Mixed"

    ep_copy = dict(ep)
    ep_copy["score"] = score
    ep_copy["grade"] = grade
    ep_copy["traffic_source"] = traffic_source
    # p95/p99 are only computed by the ClickHouse read path (see
    # clickhouse_service.get_all_discovered_endpoints) — the SQLite fallback
    # only ever keeps one merged-in-place row per endpoint, so there's no
    # history of per-batch averages left to take a percentile over. Default
    # to 0.0 there rather than omitting the field, so the API's shape is
    # consistent regardless of which store answered the query.
    ep_copy.setdefault("p95_response_time_ms", 0.0)
    ep_copy.setdefault("p99_response_time_ms", 0.0)
    # Name-pattern match only — see the scoring step above for how (and
    # when) this affects `score`/`grade`.
    ep_copy["param_names"] = ep_copy.get("param_names") or []
    ep_copy["sensitive_params"] = sensitive_params
    return ep_copy


def _paginate_scored(scored: List[Dict[str, Any]], page: int, size: int) -> Dict[str, Any]:
    """Slices an already-scored endpoint list for one page. Pagination is
    applied here, in Python, AFTER the (Redis-cached) fetch+score step —
    not pushed into the ClickHouse query — because that step was already
    cheap (~46ms for the full ~380-row set, shared across every page via
    the existing cache; see clickhouse_service._cached). The real cost this
    fixes is what happened after: the frontend previously received and
    rendered every row unpaginated (up to ~380 of them, ~189KB of JSON,
    every 10s poll) regardless of which page it would ever actually show."""
    total = len(scored)
    start = (page - 1) * size
    return {"data": scored[start:start + size], "total": total, "page": page, "size": size}


@router.get("/api-protection/endpoints", response_model=PaginatedEndpoints)
def get_discovered_endpoints(
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
    current_user: TokenData = Depends(require_any_role),
):
    """Returns discovered endpoints with scores, one page at a time.
    Discovery itself runs as a background task (see
    api_discovery.start_api_discovery_service) rather than inline here, so
    this is a plain read."""
    endpoints = _overlay_real_threat_counts(db_service.get_all_discovered_endpoints())
    scored = [calculate_endpoint_score(ep) for ep in endpoints]
    return _paginate_scored(scored, page, size)


@router.get("/api-protection/recently-discovered", response_model=PaginatedEndpoints)
def get_recently_discovered(
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
    current_user: TokenData = Depends(require_any_role),
):
    """Returns endpoints discovered in the last 48 hours, one page at a time."""
    endpoints = _overlay_real_threat_counts(db_service.get_recently_discovered_endpoints(hours=48))
    scored = [calculate_endpoint_score(ep) for ep in endpoints]
    return _paginate_scored(scored, page, size)


@router.get("/api-protection/stale-endpoints", response_model=PaginatedEndpoints)
def get_stale_endpoints(
    days: int = 30,
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
    current_user: TokenData = Depends(require_any_role),
):
    """
    Returns endpoints not seen in at least `days` days, one page at a
    time — shadow/zombie API candidates: things that used to receive
    traffic (so they were real, reachable endpoints) but have gone quiet.
    Could mean deprecated-but-still-live, forgotten debug/admin routes, or
    just a seasonal consumer — worth a human look either way, which is why
    this is a separate view rather than an automatic action.
    """
    endpoints = _overlay_real_threat_counts(db_service.get_stale_discovered_endpoints(days=days))
    scored = [calculate_endpoint_score(ep) for ep in endpoints]
    return _paginate_scored(scored, page, size)


@router.get("/api-protection/analytics", response_model=Dict[str, Any])
def get_api_protection_analytics(current_user: TokenData = Depends(require_any_role)):
    """Computes API analytics such as most consumed, slowest, and traffic band breakdown."""
    endpoints = _overlay_real_threat_counts(db_service.get_all_discovered_endpoints())
    scored_endpoints = [calculate_endpoint_score(ep) for ep in endpoints]

    # Sort for top lists
    most_consumed = sorted(
        scored_endpoints, key=lambda x: x["hit_count"], reverse=True
    )[:5]
    slowest = sorted(
        scored_endpoints, key=lambda x: x["avg_response_time_ms"], reverse=True
    )[:5]

    # Compute traffic bands
    total_hits = sum(ep["hit_count"] for ep in scored_endpoints)
    total_malicious = sum(ep["malicious_count"] for ep in scored_endpoints)
    total_suspicious = sum(ep["suspicious_count"] for ep in scored_endpoints)
    total_normal = max(0, total_hits - total_malicious - total_suspicious)

    # Calculate average response time across all endpoints
    avg_response_time = 0.0
    if total_hits > 0:
        weighted_sum = sum(
            ep["avg_response_time_ms"] * ep["hit_count"] for ep in scored_endpoints
        )
        avg_response_time = round(weighted_sum / total_hits, 2)

    return {
        "most_consumed": most_consumed,
        "resource_intensive": slowest,
        "avg_response_time_ms": avg_response_time,
        "traffic_bands": {
            "normal": total_normal,
            "suspicious": total_suspicious,
            "malicious": total_malicious,
        },
        "total_endpoints_count": len(scored_endpoints),
    }


# ============================================================================
# "Block this endpoint" — generates a ModSecurity rule denying a specific
# method+URI. Shares custom-rules.conf with Virtual Patching (routes/rules.py)
# and reuses nginx_manager's validate-before-apply pipeline, but only ever
# touches its own clearly-delimited, machine-managed section of the file so
# an admin's hand-written Virtual Patching rules are never disturbed.
# ============================================================================

CUSTOM_RULES_FILE = "/etc/nginx/modsec/custom-rules.conf"

_SECTION_START_MARKER = "# >>> API-PROTECTION-AUTO-GENERATED-START (do not edit manually) >>>"
_SECTION_END_MARKER = "# <<< API-PROTECTION-AUTO-GENERATED-END <<<"
_BLOCK_MARKER_RE = re.compile(r"^# api-protection-block: (\S+) (.+)$")


class EndpointBlockRequest(BaseModel):
    method: str
    uri: str


def _sanitize_for_rule(value: str) -> str:
    """Strips characters that could break out of the generated SecRule's
    quoted operand/msg strings, AND out of the marker comment line — a
    newline in particular would terminate the '#' comment and let the rest
    of the string inject arbitrary lines into custom-rules.conf. Callers
    must sanitize method/uri with this BEFORE passing them to any of the
    _block_marker/_generate_block_snippet/_rule_id_for/_upsert_block/
    _remove_block helpers below — they all trust their input is clean."""
    return re.sub(r"[\"'\\\n\r]", "", value)


def _block_marker(method: str, uri: str) -> str:
    return f"# api-protection-block: {method} {uri}"


def _rule_id_for(method: str, uri: str) -> int:
    """Deterministic rule ID so the same endpoint always maps to the same
    ID (add/remove stays idempotent across restarts). Landed in a band
    clearly outside CRS's own 900000-999999 range and the 999999 paranoia
    SecAction already used elsewhere in this codebase. Uses SHA-256, not
    Python's built-in hash(), which is randomized per-process and would
    make the same endpoint map to a different ID on every restart."""
    digest = hashlib.sha256(f"{method}:{uri}".encode("utf-8")).hexdigest()
    return 5_000_000 + (int(digest, 16) % 900_000)


def _generate_block_snippet(method: str, uri: str) -> str:
    rule_id = _rule_id_for(method, uri)
    return (
        f"{_block_marker(method, uri)}\n"
        f'SecRule REQUEST_METHOD "@streq {method}" '
        f'"id:{rule_id},phase:1,deny,status:403,log,'
        f"msg:'Blocked by API Protection: {method} {uri}',chain\"\n"
        f'    SecRule REQUEST_FILENAME "@streq {uri}" ""\n'
    )


def _read_custom_rules() -> str:
    if not os.path.exists(CUSTOM_RULES_FILE):
        return ""
    with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
        return f.read()


def _list_blocked_endpoints(content: str) -> List[Dict[str, str]]:
    blocked = []
    for line in content.split("\n"):
        m = _BLOCK_MARKER_RE.match(line.strip())
        if m:
            blocked.append({"method": m.group(1), "uri": m.group(2)})
    return blocked


def _upsert_block(content: str, method: str, uri: str) -> str:
    """Adds a block rule for (method, uri), creating the auto-generated
    section if it doesn't exist yet. No-op if already blocked."""
    if _block_marker(method, uri) in content:
        return content

    snippet = _generate_block_snippet(method, uri)

    if _SECTION_START_MARKER in content and _SECTION_END_MARKER in content:
        return content.replace(_SECTION_END_MARKER, snippet + _SECTION_END_MARKER)

    separator = "\n" if content and not content.endswith("\n") else ""
    return (
        content + separator +
        f"\n{_SECTION_START_MARKER}\n" + snippet + f"{_SECTION_END_MARKER}\n"
    )


def _remove_block(content: str, method: str, uri: str) -> str:
    """Removes the 3-line block group (marker + chained SecRule pair) for
    (method, uri) if present. Leaves an otherwise-empty auto-generated
    section in place rather than also tidying up the wrapper markers —
    keeps this idempotent and simple; an empty section is harmless."""
    marker = _block_marker(method, uri)
    if marker not in content:
        return content
    lines = content.split("\n")
    out = []
    i = 0
    while i < len(lines):
        if lines[i].strip() == marker:
            i += 3  # marker line + SecRule line + chained SecRule line
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


@router.get("/api-protection/blocked-endpoints")
def get_blocked_endpoints(current_user: TokenData = Depends(require_any_role)):
    """Lists endpoints currently blocked via API Protection's generated rules."""
    return _list_blocked_endpoints(_read_custom_rules())


@router.post("/api-protection/endpoints/block")
def block_endpoint(req: EndpointBlockRequest, current_user: TokenData = Depends(require_admin)):
    """Generates and applies a ModSecurity rule that denies every request
    to this exact method+URI (Admin only — this can take down a live,
    legitimately-used endpoint if used carelessly)."""
    from app.services.nginx_manager import write_and_apply_configs

    method = _sanitize_for_rule(req.method.strip().upper())
    uri = _sanitize_for_rule(req.uri.strip())
    if not method or not uri:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="method and uri are required.")

    current_content = _read_custom_rules()
    new_content = _upsert_block(current_content, method, uri)
    if new_content == current_content:
        return {"message": f"{method} {uri} is already blocked."}

    success, err_msg = write_and_apply_configs({CUSTOM_RULES_FILE: new_content})
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to apply endpoint block: {err_msg}",
        )
    return {"message": f"{method} {uri} is now blocked."}


@router.post("/api-protection/endpoints/unblock")
def unblock_endpoint(req: EndpointBlockRequest, current_user: TokenData = Depends(require_admin)):
    """Removes a previously-generated block rule for this endpoint (Admin only)."""
    from app.services.nginx_manager import write_and_apply_configs

    method = _sanitize_for_rule(req.method.strip().upper())
    uri = _sanitize_for_rule(req.uri.strip())

    current_content = _read_custom_rules()
    new_content = _remove_block(current_content, method, uri)
    if new_content == current_content:
        return {"message": f"{method} {uri} was not blocked."}

    success, err_msg = write_and_apply_configs({CUSTOM_RULES_FILE: new_content})
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove endpoint block: {err_msg}",
        )
    return {"message": f"{method} {uri} is no longer blocked."}


# ============================================================================
# OpenAPI/Swagger spec upload + traffic-drift comparison — shadow endpoints
# (seen in traffic, undocumented) and undocumented spec endpoints (documented,
# never observed). Single active spec, no versioning/history (see api_spec.py
# and the api_spec table for the reasoning).
# ============================================================================

class ApiSpecUploadRequest(BaseModel):
    filename: str
    content: str


@router.post("/api-protection/spec")
def upload_api_spec(req: ApiSpecUploadRequest, current_user: TokenData = Depends(require_admin)):
    """Uploads/replaces the active OpenAPI/Swagger spec (Admin only —
    this changes what every other user sees as the documented/shadow
    endpoint breakdown)."""
    try:
        parsed = api_spec.parse_spec(req.content)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    db_service.save_api_spec(
        filename=req.filename,
        version=parsed["version"],
        raw_content=req.content,
        endpoint_count=len(parsed["endpoints"]),
        uploaded_by=current_user.username,
        uploaded_at=datetime.now(timezone.utc).isoformat(),
    )
    return {
        "message": f"Spec uploaded: {len(parsed['endpoints'])} operations found.",
        "filename": req.filename,
        "version": parsed["version"],
        "endpoint_count": len(parsed["endpoints"]),
    }


@router.get("/api-protection/spec")
def get_api_spec_metadata(current_user: TokenData = Depends(require_any_role)):
    """Returns metadata about the currently active spec, or null if none uploaded."""
    spec = db_service.get_api_spec()
    if not spec:
        return None
    return {
        "filename": spec["filename"],
        "version": spec["version"],
        "endpoint_count": spec["endpoint_count"],
        "uploaded_by": spec["uploaded_by"],
        "uploaded_at": spec["uploaded_at"],
    }


@router.delete("/api-protection/spec")
def remove_api_spec(current_user: TokenData = Depends(require_admin)):
    """Clears the active spec (Admin only)."""
    db_service.delete_api_spec()
    return {"message": "Spec removed."}


@router.get("/api-protection/drift")
def get_api_drift(current_user: TokenData = Depends(require_any_role)):
    """
    Compares the active spec against real observed traffic:
    - shadow_endpoints: real, reachable endpoints with no matching spec path
    - undocumented_spec_endpoints: documented paths never observed in traffic
    Returns spec_loaded: false with empty lists if no spec has been uploaded.
    """
    spec = db_service.get_api_spec()
    if not spec:
        return {
            "spec_loaded": False,
            "shadow_endpoints": [],
            "undocumented_spec_endpoints": [],
            "spec_endpoint_count": 0,
            "matched_spec_endpoint_count": 0,
        }

    try:
        parsed = api_spec.parse_spec(spec["raw_content"])
    except ValueError as e:
        # Spec was valid at upload time but somehow isn't now (shouldn't
        # happen — surfaced rather than silently returning stale/empty data).
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Stored spec failed to re-parse: {e}")

    discovered = db_service.get_all_discovered_endpoints()
    drift = api_spec.compute_drift(parsed["endpoints"], discovered)
    drift["spec_loaded"] = True
    return drift


@router.post("/api-protection/reconcile")
def reconcile_data_stores(current_user: TokenData = Depends(require_admin)):
    """
    Repairs a ClickHouse/SQLite data-store split for discovered API
    endpoints (Admin only — writes to ClickHouse). Typically needed after
    a ClickHouse outage: SQLite kept recording the whole time, but
    ClickHouse only sees traffic from after it came back, so the two
    stores' totals diverge until this runs. Safe to run anytime, including
    when nothing is actually out of sync (a no-op in that case).
    """
    result = db_service.reconcile_clickhouse_from_sqlite()
    if not result.get("ok"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result.get("message", "Reconcile failed."),
        )
    return result
