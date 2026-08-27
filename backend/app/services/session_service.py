"""
CyberSentinel WAF - Session Service (P1-8 Part B)
====================================================
Fine-grained, per-session revocation on top of user_service's existing
session_version column (which only supports killing ALL of a user's
sessions at once — a role change, password reset, or disable bumps it and
every outstanding token dies together). That's still the right tool for
"this whole account is compromised, kill everything" — this module adds
the missing complement: "kill just this one session" (a laptop left
logged in, a session opened on a shared machine) without disturbing any
of that account's other active sessions.

Each login mints a session id ("sid") embedded in the JWT (see
routes/auth.py's _issue_session()) and records one Redis hash per
(username, sid), TTL'd to match ACCESS_TOKEN_EXPIRE_MINUTES so a session
that's simply expired needs no separate cleanup — it just stops existing.
Revoking a session is a single DELETE; decode_token() in services/auth.py
checks for the record's existence on every request (on top of, not
instead of, the existing session_version check) and rejects the token
immediately if it's gone, even though the JWT signature/exp/session_version
are all still otherwise valid.

Fail-open on Redis unavailability, deliberately (confirmed with the repo
owner rather than assumed): unlike rate_limiter.py, which falls back to an
in-process limiter specifically so login brute-force throttling is never
silently disabled, making THIS check hard-fail would turn Redis into a new
hard dependency for all authentication in this app — today nothing in the
login/session path needs Redis at all. If Redis is down, per-session
revoke is simply unavailable until it's back; the existing session_version
mechanism (SQLite-backed, unaffected by Redis) remains available as the
coarse fallback. The exposure window this trades away — a specifically-
revoked session still working if Redis happens to be down at that exact
moment — is bounded by ACCESS_TOKEN_EXPIRE_MINUTES, the same window an
already-issued, not-yet-expired token has today regardless of this
feature.

Tokens minted before this feature shipped simply have no "sid" claim;
decode_token() skips this check entirely for those (nothing to revoke
individually until they naturally expire) — a zero-disruption rollout.
"""
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.utils.redis_client import get_global_redis_client

logger = logging.getLogger(__name__)

SESSION_KEY_PREFIX = "session:"

# get_global_redis_client() only caches a *successful* connection — a
# failed one leaves its internal state at None forever, so every call
# retries the full connect-and-timeout (measured ~4s against an
# unreachable host in this environment) rather than failing fast. That's
# fine for a periodic background sync but is exactly wrong for a check
# that's supposed to run on every single authenticated request and fail
# open quickly when Redis is down — without this, a Redis outage would
# turn into a ~4s stall added to every login and every API call, a
# self-inflicted latency problem far worse than the feature it's guarding.
# Mirrors rate_limiter.py's cache-the-client-once approach, but with a
# bounded recheck interval rather than caching forever, so a recovered
# Redis is picked back up automatically without a process restart.
_client = None
_client_checked_at = 0.0
_CLIENT_RECHECK_INTERVAL_SECONDS = 30.0


def _get_client():
    global _client, _client_checked_at
    if _client is not None:
        return _client
    now = time.monotonic()
    if now - _client_checked_at < _CLIENT_RECHECK_INTERVAL_SECONDS:
        return None
    _client_checked_at = now
    _client = get_global_redis_client()
    return _client


def _key(username: str, sid: str) -> str:
    return f"{SESSION_KEY_PREFIX}{username}:{sid}"


def create_session(username: str, ip: str, user_agent: str, ttl_seconds: int) -> Optional[str]:
    """Mints a new session id and records it in Redis. Returns the sid, or
    None if Redis is unavailable — callers must omit the sid claim from
    the JWT entirely in that case (see _issue_session()), never embed a
    sid with no backing record (is_session_active() would then find no
    record and fail the request closed on a fail-open feature, which is
    exactly backwards)."""
    client = _get_client()
    if client is None:
        return None
    sid = secrets.token_urlsafe(16)
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        key = _key(username, sid)
        client.hset(key, mapping={
            "ip": ip or "unknown",
            "user_agent": (user_agent or "unknown")[:300],
            "created_at": now_iso,
            "last_seen_at": now_iso,
        })
        client.expire(key, ttl_seconds)
        return sid
    except Exception as e:
        logger.warning(f"[Sessions] Failed to record new session for {username}: {e}")
        return None


def is_session_active(username: str, sid: str) -> bool:
    """True if the session record still exists (not revoked, not expired)
    OR if Redis is unavailable (fail open — see module docstring). False
    only on a genuine, confirmed absence of the record. Opportunistically
    bumps last_seen_at on a live hit — best-effort, never lets a failure
    there affect the returned liveness result."""
    client = _get_client()
    if client is None:
        return True
    key = _key(username, sid)
    try:
        exists = client.exists(key)
    except Exception as e:
        logger.warning(f"[Sessions] Liveness check failed for {username}, failing open: {e}")
        return True

    if exists:
        try:
            client.hset(key, "last_seen_at", datetime.now(timezone.utc).isoformat())
        except Exception:
            pass
    return bool(exists)


def list_sessions(username: str) -> List[Dict[str, Any]]:
    """Active sessions for a user, via SCAN over the key prefix rather
    than a separately-maintained index — a TTL'd-out key just stops
    appearing here on its own, no stale-reference pruning needed (same
    pattern as auto_reputation_service.get_auto_blocked_ips())."""
    client = _get_client()
    if client is None:
        return []
    prefix = f"{SESSION_KEY_PREFIX}{username}:"
    results = []
    try:
        cursor = 0
        while True:
            cursor, keys = client.scan(cursor=cursor, match=f"{prefix}*", count=100)
            for key in keys:
                data = client.hgetall(key)
                if not data:
                    continue
                ttl = client.ttl(key)
                results.append({
                    "session_id": key[len(prefix):],
                    "ip": data.get("ip", "unknown"),
                    "user_agent": data.get("user_agent", "unknown"),
                    "created_at": data.get("created_at"),
                    "last_seen_at": data.get("last_seen_at"),
                    "expires_in_seconds": ttl if ttl and ttl > 0 else 0,
                })
            if cursor == 0:
                break
    except Exception as e:
        logger.warning(f"[Sessions] Failed to list sessions for {username}: {e}")
        return []
    results.sort(key=lambda s: s.get("last_seen_at") or "", reverse=True)
    return results


def revoke_session(username: str, sid: str) -> bool:
    """Deletes the session record — the very next request using this sid
    (or an already-open request mid-flight after this call) finds no
    record and is rejected by decode_token(). Returns False if the record
    didn't exist (already revoked/expired) or Redis is unavailable."""
    client = _get_client()
    if client is None:
        return False
    try:
        deleted = client.delete(_key(username, sid))
        return bool(deleted)
    except Exception as e:
        logger.warning(f"[Sessions] Failed to revoke session {sid} for {username}: {e}")
        return False
