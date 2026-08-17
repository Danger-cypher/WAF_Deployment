import os
import re
import logging
import ipaddress
from datetime import datetime
import threading
from app.services import db_service

logger = logging.getLogger(__name__)

# Private/internal address ranges to exclude from API discovery metrics.
# These correspond to loopback, RFC1918, link-local, and Docker bridge subnets.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),     # Loopback
    ipaddress.ip_network("10.0.0.0/8"),      # RFC1918 Class A (includes Docker 10.x.x.x bridges)
    ipaddress.ip_network("172.16.0.0/12"),   # RFC1918 Class B (Docker default bridge 172.17.x.x)
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918 Class C
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
]


def is_internal_ip(ip_str: str) -> bool:
    """Returns True if the given IP address belongs to an internal/management network.
    Uses Python's ipaddress module for precise CIDR matching.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _INTERNAL_NETWORKS)
    except ValueError:
        # Unparseable IP (e.g. hostname) — treat as external to avoid silent drops
        return False

_discovery_lock = threading.Lock()

# NGINX waf_extended log format regex (current format: real timing + real
# scheme/Content-Encoding for API Protection's TLS/Compression scoring).
# e.g., 10.200.11.33 - - [08/Jun/2026:10:35:51 +0530] "GET /api/stats HTTP/1.1" 200 154 "-" "Mozilla/5.0" 0.012 0.010 https "gzip"
ACCESS_LINE_RE = re.compile(
    r"^(?P<ip>[\d\.:a-fA-F]+) - (?P<user>[^ ]+) \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<uri>[^ ]+) (?P<proto>[^"]+)" '
    r"(?P<status>\d+) (?P<bytes>\d+) "
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)" '
    r'(?P<request_time>[\d\.\-]+) (?P<upstream_time>[\d\.\-]+) '
    r'(?P<scheme>https?) "(?P<encoding>[^"]*)"'
)

# Fallback tier: format used between the request-timing rollout and the
# scheme/Content-Encoding rollout — has real timing but not scheme/encoding.
ACCESS_LINE_RE_TIMING_ONLY = re.compile(
    r"^(?P<ip>[\d\.:a-fA-F]+) - (?P<user>[^ ]+) \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<uri>[^ ]+) (?P<proto>[^"]+)" '
    r"(?P<status>\d+) (?P<bytes>\d+) "
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)" '
    r'(?P<request_time>[\d\.\-]+) (?P<upstream_time>[\d\.\-]+)'
)

# Oldest fallback tier: legacy combined format, no timing/scheme/encoding at all.
ACCESS_LINE_RE_LEGACY = re.compile(
    r"^(?P<ip>[\d\.:a-fA-F]+) - (?P<user>[^ ]+) \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<uri>[^ ]+) (?P<proto>[^"]+)" '
    r"(?P<status>\d+) (?P<bytes>\d+) "
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

# Sentinel values for has_https / content_encoding when the log line's
# format tier doesn't capture real scheme/Content-Encoding data. Using
# sentinels instead of NULL avoids a live schema migration on the
# non-nullable ClickHouse columns (has_https UInt8, content_encoding
# LowCardinality(String)) while still letting scoring/UI distinguish
# "measured" from "not yet measured" instead of silently fabricating a value.
HTTPS_UNKNOWN = 2  # vs. 1 = confirmed https, 0 = confirmed http
ENCODING_UNKNOWN = "unknown"  # vs. "" = confirmed no Content-Encoding header, or a real value like "gzip"

# Last read file position. Persisted to SQLite (ingestion_state) so a
# backend restart doesn't forget where it left off — without this, every
# cold start reseeks to `filesize - 100KB`, which can silently reprocess
# (double-count) or skip lines depending on how much the log grew while the
# process was down.
_LAST_POSITION_STATE_KEY = "api_discovery_last_position"
_last_position = None  # None = not yet loaded from persisted state this process
NGINX_ACCESS_LOG = "/var/log/nginx/access.log"

# Static files patterns to ignore in API Discovery
STATIC_EXTENSIONS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
)


def parse_nginx_timestamp(ts_str: str) -> str:
    # Format: 08/Jun/2026:10:35:51 +0530
    try:
        # Strip timezone offset for simplicity
        base_time = ts_str.split(" ")[0]
        dt = datetime.strptime(base_time, "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_request_time(raw: str) -> float:
    """
    Convert the nginx $request_time string to milliseconds.
    nginx logs request_time in seconds (e.g. '0.043').
    Returns 0.0 if the field is missing or '-' (no upstream).
    """
    try:
        val = float(raw)
        return round(val * 1000, 2)  # convert seconds → milliseconds
    except (ValueError, TypeError):
        return 0.0


def run_api_discovery():
    """
    Parses new lines in nginx access log, detects API endpoints,
    computes performance/reputation metrics and stores them in the DB
    using an atomic bulk transaction for high performance.
    """
    global _last_position

    with _discovery_lock:
        if not os.path.isfile(NGINX_ACCESS_LOG):
            logger.warning(f"Nginx access log not found: {NGINX_ACCESS_LOG}")
            return

        if not os.access(NGINX_ACCESS_LOG, os.R_OK):
            logger.error(
                f"Cannot read nginx access log: {NGINX_ACCESS_LOG}. Permission denied."
            )
            return

        try:
            file_size = os.path.getsize(NGINX_ACCESS_LOG)

            # First call this process: load the cursor persisted by a prior
            # run instead of assuming a cold start. Falls back to "last
            # 100KB" only if nothing was ever persisted (fresh install).
            if _last_position is None:
                saved = db_service.get_ingestion_state(_LAST_POSITION_STATE_KEY)
                _last_position = int(saved) if saved is not None else max(0, file_size - 100 * 1024)

            # If file was truncated/rotated, reset position to 0
            if file_size < _last_position:
                _last_position = 0

            with open(NGINX_ACCESS_LOG, "r", encoding="utf-8", errors="replace") as f:
                if _last_position > 0:
                    f.seek(_last_position)
                    # Discard the first partial line
                    f.readline()

                lines = f.readlines()
                # Hold the new position temporarily
                new_position = f.tell()

            if not lines:
                return

            endpoints_aggregated = {}
            internal_lines = 0

            for line in lines:
                # Try the current format first (real timing + real scheme/encoding),
                # then progressively older formats for lines written before each rollout.
                stripped = line.strip()
                match = ACCESS_LINE_RE.match(stripped)
                format_tier = "full"
                if not match:
                    match = ACCESS_LINE_RE_TIMING_ONLY.match(stripped)
                    format_tier = "timing_only"
                if not match:
                    match = ACCESS_LINE_RE_LEGACY.match(stripped)
                    format_tier = "legacy"
                if not match:
                    continue
                is_legacy = format_tier == "legacy"

                # Internal/management traffic (dashboard polling, RFC1918
                # scanners) is tagged, not dropped. It used to be discarded
                # entirely here so it couldn't inflate hit counts or distort
                # threat ratios — but that also meant internal_hit_count could
                # never be nonzero and the "Internal"/"Mixed" Traffic Source
                # badge in the UI was unreachable dead code. Below, an
                # internal hit still counts toward internal_hit_count (so the
                # badge is meaningful) but is excluded from hit_count,
                # error/malicious/suspicious counts, latency, and the
                # https/encoding measurements — every score-driving metric
                # stays exactly as protected from internal-traffic skew as
                # before.
                client_ip = match.group("ip")
                is_internal = is_internal_ip(client_ip)
                if is_internal:
                    internal_lines += 1

                data = match.groupdict()
                uri = data["uri"]
                method = data["method"]
                status_code = int(data["status"])

                clean_uri = uri.split("?")[0]

                if clean_uri.lower().endswith(STATIC_EXTENSIONS):
                    continue

                # Skip WebSocket upgrade paths
                if "ws" in clean_uri or "socket" in clean_uri:
                    continue

                # Skip WAF dashboard's own internal API polling paths.
                # These are requests from the dashboard browser polling /api/stats,
                # /api/logs, etc. — they must never appear as "discovered" customer endpoints.
                WAF_INTERNAL_PREFIXES = (
                    "/api/stats", "/api/logs", "/api/timeline", "/api/top-",
                    "/api/attack-types", "/api/severity", "/api/health",
                    "/api/rules", "/api/auth", "/api/ddos", "/api/ml",
                    "/api/settings", "/api/false-positives", "/api/exclusions",
                    "/api/api-protection", "/api/hardening", "/api/anti-defacement",
                )
                if any(clean_uri.startswith(p) for p in WAF_INTERNAL_PREFIXES):
                    continue

                timestamp = parse_nginx_timestamp(data["time"])

                # Use real request_time from log if available (new waf_extended format);
                # fall back to 0.0 for legacy lines written before the format change.
                if is_legacy:
                    response_time_ms = 0.0
                else:
                    response_time_ms = parse_request_time(data.get("request_time", "-"))

                is_error = status_code >= 400
                is_malicious = status_code == 403

                is_suspicious = (status_code in (400, 404, 405, 422)) or any(
                    x in uri.lower()
                    for x in (
                        "..",
                        "etc/passwd",
                        "select",
                        "union",
                        "<script>",
                        "alert(",
                    )
                )

                # Real measurements from the "full" format tier; sentinels
                # (not a guess) for older log lines that don't carry this data.
                if format_tier == "full":
                    has_https = 1 if data.get("scheme") == "https" else 0
                    content_encoding = data.get("encoding") or ""
                else:
                    has_https = HTTPS_UNKNOWN
                    content_encoding = ENCODING_UNKNOWN

                has_versioning = (
                    1
                    if any(
                        v in clean_uri.lower()
                        for v in ("/v1/", "/v2/", "/v3/", "/api/")
                    )
                    else 0
                )

                key = (clean_uri, method)
                if key not in endpoints_aggregated:
                    endpoints_aggregated[key] = {
                        "response_time_ms_sum": 0.0,
                        "hit_count": 0,
                        "error_count": 0,
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "external_hit_count": 0,
                        "internal_hit_count": 0,
                        "has_https": HTTPS_UNKNOWN,
                        "has_versioning": has_versioning,
                        "content_encoding": ENCODING_UNKNOWN,
                        "timestamp": timestamp,
                    }

                ep = endpoints_aggregated[key]
                # Keep the latest timestamp regardless of traffic origin —
                # an internal-only hit still means the endpoint is alive.
                ep["timestamp"] = timestamp

                if is_internal:
                    # Registers the endpoint and its Traffic Source
                    # classification without touching any score-driving
                    # metric (hit_count, error/malicious/suspicious counts,
                    # latency, https/encoding) — matches the original
                    # anti-skew intent, just without discarding the endpoint.
                    ep["internal_hit_count"] += 1
                    continue

                ep["response_time_ms_sum"] += response_time_ms
                ep["hit_count"] += 1
                ep["external_hit_count"] += 1
                if is_error:
                    ep["error_count"] += 1
                if is_malicious:
                    ep["malicious_count"] += 1
                if is_suspicious:
                    ep["suspicious_count"] += 1
                # Prefer known measurements over the unknown sentinel within
                # this batch. For has_https, a confirmed-insecure hit (0)
                # always wins even over a confirmed-secure one (1) — a real
                # plaintext hit is a genuine finding worth surfacing, not
                # something a later HTTPS hit should paper over.
                ep["has_https"] = min(ep["has_https"], has_https)
                if content_encoding != ENCODING_UNKNOWN:
                    ep["content_encoding"] = content_encoding

            if internal_lines > 0:
                logger.debug(
                    f"API Discovery: {internal_lines} internal/RFC1918 IP lines tagged as internal "
                    f"(counted toward internal_hit_count, excluded from score-driving metrics)."
                )

            if endpoints_aggregated:
                db_service.bulk_upsert_discovered_endpoints(endpoints_aggregated)
                logger.info(
                    f"Bulk processed {len(lines)} access log records into {len(endpoints_aggregated)} unique API endpoints "
                    f"({internal_lines} internal-IP lines tagged)."
                )

            # ONLY update the file position after successful DB commit, and
            # persist it so a restart resumes from here instead of guessing.
            _last_position = new_position
            db_service.set_ingestion_state(_LAST_POSITION_STATE_KEY, str(new_position))

        except Exception as e:
            logger.error(f"Error executing API discovery: {e}")
