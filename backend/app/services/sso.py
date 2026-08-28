"""
CyberSentinel WAF - SIEM SSO (mint-and-redirect JWT exchange)

Implements the receiving side of the SIEM's standard SSO contract (the
same model DLP and SOAR already run on): the SIEM mints a short-lived
signed JWT describing the analyst and redirects the browser to our
/auth/sso landing page with it in the URL fragment. This module verifies
that token and maps its claims onto our own user/role model; the actual
account lookup/JIT-provisioning and session issuance live in
routes/sso.py and services/user_service.py.

Two verification modes, staged per the SIEM's rollout plan:
  - HS256: shared secret (WAF_SSO_SECRET), built first.
  - RS256: verified against the SIEM's published JWKS (SIEM_JWKS_URL),
    routed to by the token's own `alg` header. Only active once
    SIEM_JWKS_URL is configured.
"""
import re
import ssl
import logging
import secrets
from typing import Any, Dict, Optional

import jwt

from app.config.settings import settings
from app.utils.redis_client import get_global_redis_client

logger = logging.getLogger(__name__)

# Underscore, not hyphen — matches what the SIEM's /waf/sso/login actually
# mints, confirmed against a real decoded token. The original onboarding
# doc said "sso-exchange" (hyphen); that was wrong, not this.
REQUIRED_PURPOSE = "sso_exchange"

# In-process fallback for single-use nonce tracking when Redis is
# unavailable — mirrors utils/rate_limiter.py's fallback approach. This
# backend runs as a single instance (no `replicas:` in docker-compose.yml),
# so an in-memory set actually holds here; it just doesn't survive a
# process restart, unlike the Redis-backed version.
_nonce_local_seen: Dict[str, float] = {}


class SsoTokenError(ValueError):
    """Raised for any SSO token that fails verification. The message is
    safe to log but deliberately generic in the HTTP response — we don't
    want to hand an attacker a verification oracle."""


def _consume_nonce(nonce: str, ttl_seconds: int) -> bool:
    """Atomically claims a nonce. Returns True the first time a given
    nonce is seen within the TTL window, False on any replay."""
    client = get_global_redis_client()
    if client is not None:
        try:
            return bool(client.set(f"sso:nonce:{nonce}", "1", nx=True, ex=ttl_seconds))
        except Exception as e:
            logger.error(f"Redis error checking SSO nonce, falling back to in-process set: {e}")

    import time
    now = time.monotonic()
    # Purge expired entries so this dict doesn't grow unbounded.
    for key, expires_at in list(_nonce_local_seen.items()):
        if expires_at <= now:
            del _nonce_local_seen[key]
    if nonce in _nonce_local_seen:
        return False
    _nonce_local_seen[nonce] = now + ttl_seconds
    return True



# Cache the PyJWKClient itself (not just the underlying key set) across
# requests — instantiating a fresh client per call, as an earlier version
# of this function did, defeats the client's own jwk-set caching since
# that cache lives on the instance. Re-created only if SIEM_JWKS_URL
# changes (picked up without a restart, e.g. after editing .env + a
# config reload), which is why this checks the URL rather than just
# checking "is it None".
_jwks_client: Optional["jwt.PyJWKClient"] = None
_jwks_client_url: Optional[str] = None
_jwks_client_cert: Optional[str] = None


def _build_jwks_ssl_context() -> Optional[ssl.SSLContext]:
    """Builds the SSL context for the JWKS fetch: the system trust store
    plus the SIEM's edge cert, if configured. Additive, not a replacement
    — this backend also makes other outbound HTTPS calls (threat-intel
    feeds), which must keep trusting public CAs regardless of this
    deployment's SIEM cert. Returns None (i.e. "use urllib's default
    context") when no SIEM cert is configured, so an unset
    SIEM_SSO_CA_CERT fails closed against the SIEM's self-signed cert
    rather than silently trusting it."""
    if not settings.SIEM_SSO_CA_CERT:
        return None
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=settings.SIEM_SSO_CA_CERT)
    return ctx


def _get_jwks_client() -> "jwt.PyJWKClient":
    global _jwks_client, _jwks_client_url, _jwks_client_cert
    if (
        _jwks_client is None
        or _jwks_client_url != settings.SIEM_JWKS_URL
        or _jwks_client_cert != settings.SIEM_SSO_CA_CERT
    ):
        _jwks_client = jwt.PyJWKClient(
            settings.SIEM_JWKS_URL,
            cache_keys=True,
            # SIEM signing keys rotate infrequently; an hour balances not
            # re-fetching on every login against not going too stale if
            # the SIEM does rotate. A `kid` miss (e.g. right after a
            # rotation) still forces an immediate re-fetch — see
            # PyJWKClient.get_signing_key_from_jwt.
            lifespan=3600,
            timeout=5,
            # PyJWKClient fetches over urllib.request, not `requests` — a
            # REQUESTS_CA_BUNDLE env var has no effect on this call at
            # all. Trust is wired explicitly here instead.
            ssl_context=_build_jwks_ssl_context(),
        )
        _jwks_client_url = settings.SIEM_JWKS_URL
        _jwks_client_cert = settings.SIEM_SSO_CA_CERT
    return _jwks_client


def _get_signing_key(token: str):
    """Resolves the key to verify `token` with, based on its own `alg`
    header. Raises SsoTokenError if that algorithm isn't enabled for this
    deployment."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise SsoTokenError("Malformed token header")

    alg = header.get("alg")
    if alg == "HS256":
        if not settings.WAF_SSO_SECRET:
            raise SsoTokenError("HS256 SSO not configured (WAF_SSO_SECRET unset)")
        return settings.WAF_SSO_SECRET, "HS256"
    if alg == "RS256":
        if not settings.SIEM_JWKS_URL:
            raise SsoTokenError("RS256 SSO not enabled (SIEM_JWKS_URL unset)")
        try:
            signing_key = _get_jwks_client().get_signing_key_from_jwt(token)
        except jwt.PyJWKClientError as e:
            raise SsoTokenError(f"Could not resolve SIEM signing key: {e}")
        return signing_key.key, "RS256"

    raise SsoTokenError(f"Unsupported SSO token algorithm: {alg!r}")


def verify_sso_exchange_token(token: str) -> Dict[str, Any]:
    """Verifies a SIEM SSO exchange JWT end to end: signature, issuer,
    audience, timing claims, purpose, and single-use nonce. Returns the
    decoded claims on success; raises SsoTokenError otherwise."""
    key, alg = _get_signing_key(token)

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[alg],
            issuer=settings.SSO_ISSUER,
            audience=settings.SSO_AUDIENCE,
            # Our own session JWTs (services/auth.py) don't set iat/nbf, so
            # PyJWT's defaults don't require them — the SIEM's contract
            # does, so enforce it explicitly here.
            options={"require": ["exp", "iat", "nbf", "sub"]},
            # ~60s of allowed clock skew, matching the SIEM's stated leeway.
            leeway=60,
        )
    except jwt.PyJWTError as e:
        raise SsoTokenError(f"Token verification failed: {e}")

    if claims.get("purpose") != REQUIRED_PURPOSE:
        raise SsoTokenError("Token purpose is not sso_exchange")

    nonce = claims.get("nonce")
    if not nonce or not isinstance(nonce, str):
        raise SsoTokenError("Token missing nonce")
    if not _consume_nonce(nonce, settings.SSO_NONCE_TTL_SECONDS):
        raise SsoTokenError("Token nonce already used (replay)")

    return claims


# SIEM role -> WAF role, per the onboarding doc's §5 mapping table.
# Unknown/missing role -> least privilege ('analyst', read-only via the
# `access` claim), never 'admin'. 'app_admin' is a manually-granted,
# per-app-scoped role in our product and is never assigned via SSO.
_ROLE_MAP = {
    "administrator": "admin",
    "L3-Analyst": "analyst",
    "L2-Analyst": "analyst",
    "L1-Analyst": "analyst",
    "read-only": "analyst",
}


def map_siem_role(claims: Dict[str, Any]) -> str:
    role = claims.get("role")
    return _ROLE_MAP.get(role, "analyst")


_USERNAME_CHARS = re.compile(r"[^a-zA-Z0-9_.-]")


def generate_sso_username(claims: Dict[str, Any], username_exists) -> str:
    """Derives a username for a brand-new JIT-provisioned account.
    `username_exists` is a callable (typically user_service.username_exists)
    used to guarantee uniqueness against the live table."""
    email = claims.get("email") or ""
    name = claims.get("name") or ""
    sub = claims.get("sub") or ""

    candidate = _USERNAME_CHARS.sub("", email.split("@")[0]) if email else ""
    if not candidate:
        candidate = _USERNAME_CHARS.sub("", name.replace(" ", "."))
    if not candidate:
        candidate = f"sso-{_USERNAME_CHARS.sub('', sub)}"

    candidate = candidate[:24].strip(".-_") or "sso-user"

    base = candidate
    suffix = 0
    while username_exists(candidate) or len(candidate) < 3:
        suffix += 1
        candidate = f"{base}-{suffix}"[:32]
    return candidate
