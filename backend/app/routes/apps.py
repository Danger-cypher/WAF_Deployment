import re
import os
import json
import shutil
import subprocess
import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status, Request
from pydantic import BaseModel, Field, field_validator
from typing import Any, Dict, List, Optional
from app.services import db_service, nginx_manager, api_spec
from app.services.auth import require_admin, require_any_role, require_app_view_access, require_app_write_access, TokenData
from app.utils.audit import log_admin_action

logger = logging.getLogger(__name__)

router = APIRouter()


class OriginModel(BaseModel):
    """One extra backend server for load balancing (P1-14) — see
    ProtectedAppBase.additional_origins. Same shape/validation as the
    primary upstream_host/upstream_port pair, just repeatable."""
    host: str = Field(..., min_length=1)
    port: int = Field(..., ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.match(r'^[a-zA-Z0-9.\-_]+$', cleaned):
            raise ValueError("Origin host contains invalid characters. Only alphanumeric, hyphens, dots, and underscores are allowed.")
        return cleaned


class ProtectedAppBase(BaseModel):
    name: str = Field(..., min_length=1, description="Friendly name of the application")
    domain: str = Field(..., min_length=1, description="Domain name (e.g. app.localhost) or '_'")
    upstream_host: str = Field(..., min_length=1, description="Internal container name or IP address")
    upstream_port: int = Field(..., ge=1, le=65535, description="Upstream network port")
    protocol: str = Field("http", description="Upstream protocol: 'http' or 'https'")
    is_active: int = Field(1, ge=0, le=1, description="1 = active, 0 = inactive")
    additional_origins: List[OriginModel] = Field(
        default_factory=list,
        description=(
            "Extra backend servers for load balancing (P1-14) — nginx round-robins "
            "across upstream_host/upstream_port plus these, with automatic passive "
            "failover away from one that starts erroring. Same protocol for all."
        ),
    )

    @field_validator("additional_origins", mode="before")
    @classmethod
    def parse_additional_origins(cls, value):
        # DB rows carry this as a pre-serialized JSON string (see
        # db_service.py); a request body carries it as a real JSON array
        # already. Accept either so ProtectedAppResponse can be built
        # directly from a raw DB dict without a separate parsing step at
        # every route handler.
        if isinstance(value, str):
            if not value.strip():
                return []
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return []
        return value or []
    rate_limit_rps: int = Field(50, ge=1, le=10000, description="RPS limit per client IP")
    burst_tolerance: int = Field(100, ge=1, le=20000, description="Rate limit burst allowance")
    ssl_option: str = Field("self-signed", description="SSL mode: 'letsencrypt', 'custom', 'self-signed'")
    require_auth: int = Field(0, ge=0, le=1, description="1 = deny requests missing the configured auth header/cookie")
    auth_check_type: str = Field("header", description="'header' or 'cookie' — where to check for auth_header_name")
    auth_header_name: str = Field("Authorization", min_length=1, description="Header or cookie name whose mere presence is required")
    enable_response_cache: int = Field(
        0, ge=0, le=1,
        description=(
            "1 = cache this app's cacheable GET/HEAD responses at the WAF gateway "
            "(nginx's own Set-Cookie/Cache-Control-respecting defaults still apply — "
            "this doesn't override the origin's own caching directives, only enables "
            "the mechanism). Off by default."
        ),
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        # `name` is interpolated straight into the generated nginx config as a
        # comment line (nginx_manager.sync_protected_apps_to_nginx, the
        # "# --- Upstream App {id}: {name} ({domain}) ---" lines). Every other
        # free-text field reaching that generator is already character-
        # restricted — `domain` and `upstream_host` above, `auth_header_name`
        # via re.sub in nginx_manager — but this one was not, so a newline in
        # it terminated the comment and let arbitrary nginx directives be
        # injected into the shared gateway config, `content_by_lua_block`
        # included. That is code execution in the OpenResty container, and
        # since PUT /apps/{app_id} is gated by require_app_write_access (which
        # accepts the deliberately app-scoped 'app_admin' role), it was an
        # escalation path from one tenant's app admin to root on the gateway
        # serving every tenant.
        #
        # Rejecting control characters is what actually closes the injection;
        # '{' '}' ';' '#' are rejected too so a name can never read as nginx
        # syntax even if it later gets interpolated somewhere less careful.
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Name cannot be empty.")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
            raise ValueError("Name cannot contain control characters or line breaks.")
        if any(ch in cleaned for ch in "{};#\\"):
            raise ValueError("Name cannot contain any of: { } ; # \\")
        if len(cleaned) > 64:
            raise ValueError("Name cannot exceed 64 characters.")
        return cleaned

    @field_validator("auth_check_type")
    @classmethod
    def validate_auth_check_type(cls, value: str) -> str:
        allowed = {"header", "cookie"}
        if value not in allowed:
            raise ValueError(f"auth_check_type must be one of: {', '.join(allowed)}")
        return value

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        # Allow alphanumeric, hyphens, periods, underscores, and wildcards
        cleaned = value.strip().lower()
        if not re.match(r'^[a-zA-Z0-9\-._*]+$', cleaned):
            raise ValueError("Domain contains invalid characters. Only alphanumeric, hyphens, dots, underscores, and '*' are allowed.")
        # `domain` is used directly as a path segment for SSL cert storage
        # (os.path.join(SSL_DIR, "letsencrypt"/"custom", domain)) — the regex
        # above allows '.', so a value like ".." would otherwise pass through
        # unsanitized and let a cert get written one directory level outside
        # its intended per-app sandbox. No valid domain ever contains "..".
        if ".." in cleaned:
            raise ValueError("Domain cannot contain '..'.")
        return cleaned

    @field_validator("upstream_host")
    @classmethod
    def validate_upstream_host(cls, value: str) -> str:
        # Allow hostnames, IP addresses, Docker container names (alphanumeric, dots, hyphens, underscores)
        cleaned = value.strip()
        if not re.match(r'^[a-zA-Z0-9.\-_]+$', cleaned):
            raise ValueError("Upstream host contains invalid characters. Only alphanumeric, hyphens, dots, and underscores are allowed.")
        return cleaned

    @field_validator("ssl_option")
    @classmethod
    def validate_ssl_option(cls, value: str) -> str:
        allowed = {"letsencrypt", "custom", "self-signed", "none"}
        if value not in allowed:
            raise ValueError(f"ssl_option must be one of: {', '.join(allowed)}")
        return value


class ProtectedAppCreate(ProtectedAppBase):
    pass


class ProtectedAppResponse(ProtectedAppBase):
    id: int
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None


def _serialize_origins(origins: List[OriginModel]) -> Optional[str]:
    """None (not '[]') when empty, matching every other optional per-app
    JSON-blob column's NULL-means-absent convention (e.g. api_schema)."""
    if not origins:
        return None
    return json.dumps([o.model_dump() for o in origins])


@router.get("/apps", response_model=List[ProtectedAppResponse])
async def list_apps(current_user: TokenData = Depends(require_any_role)):
    """List all registered protected applications — 'admin'/'analyst' see
    everything (unchanged); a scoped 'app_admin' sees only their own apps."""
    apps = db_service.get_all_protected_apps()
    if current_user.role == "app_admin":
        allowed_ids = set(db_service.get_app_ids_for_user(current_user.username))
        apps = [a for a in apps if a.get("id") in allowed_ids]
    return apps


@router.get("/apps/{app_id}", response_model=ProtectedAppResponse)
async def get_app(app_id: int, current_user: TokenData = Depends(require_app_view_access)):
    """Get details of a specific protected application."""
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protected application with ID {app_id} not found"
        )
    return app


@router.post("/apps", response_model=ProtectedAppResponse, status_code=status.HTTP_201_CREATED)
async def add_app(request: Request, app_data: ProtectedAppCreate, current_user: TokenData = Depends(require_admin)):
    """Add a new protected application and apply Nginx settings."""
    # Check if domain already exists
    existing_apps = db_service.get_all_protected_apps()
    domain_lower = app_data.domain.strip().lower()
    if any(app.get("domain") == domain_lower for app in existing_apps):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"An application with domain '{domain_lower}' is already registered."
        )

    app = db_service.create_protected_app(
        name=app_data.name,
        domain=app_data.domain,
        upstream_host=app_data.upstream_host,
        upstream_port=app_data.upstream_port,
        protocol=app_data.protocol,
        is_active=app_data.is_active,
        rate_limit_rps=app_data.rate_limit_rps,
        burst_tolerance=app_data.burst_tolerance,
        ssl_option=app_data.ssl_option,
        require_auth=app_data.require_auth,
        auth_check_type=app_data.auth_check_type,
        auth_header_name=app_data.auth_header_name,
        additional_origins=_serialize_origins(app_data.additional_origins),
        enable_response_cache=app_data.enable_response_cache,
    )
    if not app:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register application in database."
        )

    # Sync configurations with Nginx
    success, err_msg = nginx_manager.sync_protected_apps_to_nginx()
    if not success:
        # Revert database insertion if sync failed to keep system in sync
        db_service.delete_protected_app(app["id"])
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate Nginx config or reload service. Reverting database registration. {err_msg}"
        )

    log_admin_action("app", str(app["id"]), "create", current_user, details={"name": app_data.name, "domain": domain_lower}, request=request)
    return app


@router.put("/apps/{app_id}", response_model=ProtectedAppResponse)
async def update_app(request: Request, app_id: int, app_data: ProtectedAppCreate, current_user: TokenData = Depends(require_app_write_access)):
    """Update details of an existing application and sync configuration."""
    existing_app = db_service.get_protected_app_by_id(app_id)
    if not existing_app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protected application with ID {app_id} not found"
        )

    # Validate duplicate domain check
    domain_lower = app_data.domain.strip().lower()
    all_apps = db_service.get_all_protected_apps()
    if any(app.get("domain") == domain_lower and app.get("id") != app_id for app in all_apps):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"An application with domain '{domain_lower}' is already registered."
        )

    app = db_service.update_protected_app(
        app_id=app_id,
        name=app_data.name,
        domain=app_data.domain,
        upstream_host=app_data.upstream_host,
        upstream_port=app_data.upstream_port,
        protocol=app_data.protocol,
        is_active=app_data.is_active,
        rate_limit_rps=app_data.rate_limit_rps,
        burst_tolerance=app_data.burst_tolerance,
        ssl_option=app_data.ssl_option,
        require_auth=app_data.require_auth,
        auth_check_type=app_data.auth_check_type,
        auth_header_name=app_data.auth_header_name,
        additional_origins=_serialize_origins(app_data.additional_origins),
        enable_response_cache=app_data.enable_response_cache,
    )
    if not app:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update application in database."
        )

    # Sync configurations with Nginx
    success, err_msg = nginx_manager.sync_protected_apps_to_nginx()
    if not success:
        # Revert database update on Nginx reload failure. Also restores
        # ssl_option (previously missing here — would've silently reset to
        # 'self-signed' on rollback) alongside the new require_auth fields.
        db_service.update_protected_app(
            app_id=app_id,
            name=existing_app["name"],
            domain=existing_app["domain"],
            upstream_host=existing_app["upstream_host"],
            upstream_port=existing_app["upstream_port"],
            protocol=existing_app["protocol"],
            is_active=existing_app["is_active"],
            rate_limit_rps=existing_app.get("rate_limit_rps", 50),
            burst_tolerance=existing_app.get("burst_tolerance", 100),
            ssl_option=existing_app.get("ssl_option", "self-signed"),
            require_auth=existing_app.get("require_auth", 0),
            auth_check_type=existing_app.get("auth_check_type", "header"),
            auth_header_name=existing_app.get("auth_header_name", "Authorization"),
            additional_origins=existing_app.get("additional_origins"),
            enable_response_cache=existing_app.get("enable_response_cache", 0),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate Nginx config or reload service. Reverting database changes. {err_msg}"
        )

    log_admin_action("app", str(app_id), "update", current_user, details={"name": app_data.name, "domain": domain_lower}, request=request)
    return app


@router.delete("/apps/{app_id}")
async def remove_app(request: Request, app_id: int, current_user: TokenData = Depends(require_app_write_access)):
    """Delete a protected application and sync configuration."""
    existing_app = db_service.get_protected_app_by_id(app_id)
    if not existing_app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protected application with ID {app_id} not found"
        )

    # Validation removed to support fallback server configuration

    success_db = db_service.delete_protected_app(app_id)
    if not success_db:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete application from database."
        )

    # Sync configurations with Nginx
    success_nginx, err_msg = nginx_manager.sync_protected_apps_to_nginx()
    if not success_nginx:
        # Revert database deletion if Nginx reload fails. Restores ssl_option
        # and the provisioned cert paths too (previously missing — a
        # recreated app would've lost a provisioned Let's Encrypt/custom
        # cert reference here), alongside the new require_auth fields.
        db_service.create_protected_app(
            name=existing_app["name"],
            domain=existing_app["domain"],
            upstream_host=existing_app["upstream_host"],
            upstream_port=existing_app["upstream_port"],
            protocol=existing_app["protocol"],
            is_active=existing_app["is_active"],
            rate_limit_rps=existing_app.get("rate_limit_rps", 50),
            burst_tolerance=existing_app.get("burst_tolerance", 100),
            ssl_option=existing_app.get("ssl_option", "self-signed"),
            ssl_cert_path=existing_app.get("ssl_cert_path"),
            ssl_key_path=existing_app.get("ssl_key_path"),
            require_auth=existing_app.get("require_auth", 0),
            auth_check_type=existing_app.get("auth_check_type", "header"),
            auth_header_name=existing_app.get("auth_header_name", "Authorization"),
            additional_origins=existing_app.get("additional_origins"),
            enable_response_cache=existing_app.get("enable_response_cache", 0),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update Nginx config or reload service. Reverting database changes. {err_msg}"
        )

    # Best-effort cleanup of any provisioned cert/key files — previously
    # left behind indefinitely on disk (including the private key) after
    # the app referencing them was gone. Never fatal: the app is already
    # deleted and nginx already reloaded by this point, so a cleanup
    # failure here shouldn't be reported as a failed delete.
    ssl_option = existing_app.get("ssl_option")
    if ssl_option in ("letsencrypt", "custom"):
        try:
            cert_dir = _safe_cert_dir(ssl_option, existing_app["domain"])
            shutil.rmtree(cert_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Failed to clean up cert directory for deleted app {app_id}: {e}")

    # Same gap, same fix, for the per-app require-auth conf file — it's
    # only ever referenced by this app's own (now regenerated) server
    # block, so once the app is gone the file is pure orphaned disk state.
    try:
        from app.services.nginx_manager import app_auth_conf_path
        auth_conf_path = app_auth_conf_path(app_id)
        if os.path.exists(auth_conf_path):
            os.remove(auth_conf_path)
    except Exception as e:
        logger.warning(f"Failed to clean up app-auth conf for deleted app {app_id}: {e}")

    # Same gap, same fix, for the per-domain API schema Redis key — without
    # this, a domain that gets reused by a different app later would
    # silently inherit the deleted app's schema.
    try:
        nginx_manager.apply_api_schema_settings(existing_app["domain"], None, "log")
    except Exception as e:
        logger.warning(f"Failed to clean up API schema for deleted app {app_id}: {e}")

    # Same gap, same fix, for the per-app mTLS CA cert file — orphaned
    # disk state once the app referencing it is gone.
    mtls_ca_path = existing_app.get("mtls_ca_cert_path")
    if mtls_ca_path and os.path.exists(mtls_ca_path):
        try:
            os.remove(mtls_ca_path)
        except Exception as e:
            logger.warning(f"Failed to clean up mTLS CA cert for deleted app {app_id}: {e}")

    log_admin_action("app", str(app_id), "delete", current_user, details={"name": existing_app["name"], "domain": existing_app["domain"]}, request=request)
    return {"message": "Protected application deleted successfully!"}


@router.post("/apps/{app_id}/toggle", response_model=ProtectedAppResponse)
async def toggle_app_active(request: Request, app_id: int, current_user: TokenData = Depends(require_app_write_access)):
    """Toggle the enabled status of a protected application."""
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protected application with ID {app_id} not found"
        )

    new_status = 0 if app.get("is_active", 1) == 1 else 1

    # Validation removed to support fallback server configuration

    updated_app = db_service.update_protected_app(
        app_id=app_id,
        name=app["name"],
        domain=app["domain"],
        upstream_host=app["upstream_host"],
        upstream_port=app["upstream_port"],
        protocol=app["protocol"],
        is_active=new_status,
        rate_limit_rps=app.get("rate_limit_rps", 50),
        burst_tolerance=app.get("burst_tolerance", 100),
        ssl_option=app.get("ssl_option", "self-signed"),
        require_auth=app.get("require_auth", 0),
        auth_check_type=app.get("auth_check_type", "header"),
        auth_header_name=app.get("auth_header_name", "Authorization"),
        additional_origins=app.get("additional_origins"),
        enable_response_cache=app.get("enable_response_cache", 0),
    )

    # Sync configurations with Nginx
    success, err_msg = nginx_manager.sync_protected_apps_to_nginx()
    if not success:
        # Revert database status update on Nginx reload failure
        db_service.update_protected_app(
            app_id=app_id,
            name=app["name"],
            domain=app["domain"],
            upstream_host=app["upstream_host"],
            upstream_port=app["upstream_port"],
            protocol=app["protocol"],
            is_active=app["is_active"],
            rate_limit_rps=app.get("rate_limit_rps", 50),
            burst_tolerance=app.get("burst_tolerance", 100),
            ssl_option=app.get("ssl_option", "self-signed"),
            require_auth=app.get("require_auth", 0),
            auth_check_type=app.get("auth_check_type", "header"),
            auth_header_name=app.get("auth_header_name", "Authorization"),
            additional_origins=app.get("additional_origins"),
            enable_response_cache=app.get("enable_response_cache", 0),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate Nginx config or reload service. Reverting status change. {err_msg}"
        )

    log_admin_action("app", str(app_id), "toggle", current_user, details={"is_active": new_status}, request=request)
    return updated_app


# ---------------------------------------------------------------------------
# SSL Provisioning Endpoints
# ---------------------------------------------------------------------------

# Shared directory for per-domain certs (inside the container's nginx ssl dir)
SSL_DIR = "/etc/nginx/ssl"


def _safe_cert_dir(subdir: str, domain: str) -> str:
    """
    Builds the per-domain cert directory and verifies the resolved path is
    still inside SSL_DIR/subdir. The `domain` validator already rejects '..'
    for new/updated apps, but this is a second, independent check at the
    point the path is actually used — so a pre-existing DB row from before
    that validator existed can't write outside its per-app sandbox either.
    """
    base = os.path.realpath(os.path.join(SSL_DIR, subdir))
    cert_dir = os.path.realpath(os.path.join(base, domain))
    if cert_dir != base and not cert_dir.startswith(base + os.sep):
        raise HTTPException(status_code=400, detail="Invalid domain: resolves outside the SSL certificate directory.")
    return cert_dir


@router.post("/apps/{app_id}/provision-ssl")
async def provision_letsencrypt(request: Request,
    app_id: int,
    current_user: TokenData = Depends(require_app_write_access),
):
    """
    Trigger Let's Encrypt certificate provisioning for a domain-based protected app.
    Uses the HTTP-01 challenge via the shared acme-challenge webroot.

    Runs certbot inside the dedicated `waf-certbot` container (docker-compose's
    `certbot` service — image certbot/certbot, only otherwise running a
    `certbot renew` loop that does nothing for a brand-new domain) via
    `docker exec`, the same mechanism nginx_manager.reload_nginx() already
    uses for `docker exec waf-openresty ...` through the docker-socket-proxy.
    The backend's own container has no certbot binary installed — a previous
    version of this route tried to run a local `certbot` binary directly and
    could never succeed (always hit FileNotFoundError).
    """
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Protected application not found")

    domain = app.get("domain", "")
    if domain == "_" or not domain:
        raise HTTPException(
            status_code=400,
            detail="Let's Encrypt requires a real domain name, not a wildcard or catch-all."
        )

    # Cert output location as seen from THIS (backend) container.
    # `./configs/nginx/ssl/letsencrypt` on the host is bind-mounted as
    # `/etc/letsencrypt/live` inside waf-certbot (docker-compose.yml), and
    # separately as `/etc/nginx/ssl/letsencrypt` inside both this backend
    # container (via the broader `./configs/nginx:/etc/nginx` mount) and
    # waf-openresty — so whatever certbot writes to its own `live/{domain}/`
    # is immediately visible here at the same relative path, no copying
    # needed. SSL_DIR = "/etc/nginx/ssl", so this is that same shared host
    # directory.
    cert_dir = _safe_cert_dir("letsencrypt", domain)

    # certbot's own container mounts the shared acme-challenge directory at
    # `/acme-challenge` (docker-compose.yml's `certbot` service) — that's
    # the webroot path *inside waf-certbot*. A previous version of this
    # route used a webroot path local to the backend's own container
    # instead, which pointed at a directory openresty/certbot never share
    # with the backend at all — a request for /.well-known/acme-challenge/
    # would never have found the token certbot expected to place there.
    CERTBOT_CONTAINER_WEBROOT = "/acme-challenge"

    try:
        cmd = [
            "docker", "exec", "waf-certbot",
            "certbot", "certonly",
            "--webroot", "-w", CERTBOT_CONTAINER_WEBROOT,
            "-d", domain,
            "--non-interactive",
            "--agree-tos",
            "--email", "admin@" + domain,
        ]

        try:
            # subprocess.run() blocks — running it inline on the event loop
            # would stall every other logged-in user's request for the
            # full duration (real ACME HTTP-01 validation can take a while).
            result = await asyncio.to_thread(
                subprocess.run,
                cmd, capture_output=True, text=True, timeout=120  # nosec B603 B607
            )
            output = result.stdout if result.returncode == 0 else None
            last_error = None if result.returncode == 0 else result.stderr.strip()
        except FileNotFoundError:
            output, last_error = None, "docker CLI not available in this container"
        except subprocess.TimeoutExpired:
            output, last_error = None, "certbot timed out after 120s"

        if output is None:
            raise HTTPException(
                status_code=500,
                detail=f"certbot failed: {last_error}"
            )

        # certbot's real output filenames are fullchain.pem + privkey.pem
        # (not "key.pem" — a previous version of this code looked for the
        # wrong filename here and would have saved a ssl_key_path pointing
        # at a file that never exists, breaking the app's SSL config once
        # NGINX was resynced). No copying needed: cert_dir already IS the
        # shared host directory waf-certbot just wrote into (see comment
        # on cert_dir above), so a successful certbot run means these
        # files already exist here.
        fullchain = os.path.join(cert_dir, "fullchain.pem")
        privkey = os.path.join(cert_dir, "privkey.pem")
        if not os.path.exists(fullchain) or not os.path.exists(privkey):
            raise HTTPException(
                status_code=500,
                detail=(
                    f"certbot reported success but {fullchain} was not found on the "
                    "shared certificate volume — check the waf-certbot container's "
                    "mounts match this backend's expectations."
                ),
            )

        # Persist paths to DB
        db_service.update_protected_app(
            app_id=app_id,
            name=app["name"],
            domain=app["domain"],
            upstream_host=app["upstream_host"],
            upstream_port=app["upstream_port"],
            protocol=app["protocol"],
            is_active=app["is_active"],
            rate_limit_rps=app.get("rate_limit_rps", 50),
            burst_tolerance=app.get("burst_tolerance", 100),
            ssl_option="letsencrypt",
            ssl_cert_path=fullchain,
            ssl_key_path=privkey,
            # These three were previously omitted here entirely, which
            # meant provisioning a Let's Encrypt cert silently reset
            # require_auth/auth_check_type/auth_header_name to their
            # function defaults for this app (require_auth back to
            # disabled) — a real pre-existing bug, fixed in passing while
            # already touching this call site to add additional_origins.
            require_auth=app.get("require_auth", 0),
            auth_check_type=app.get("auth_check_type", "header"),
            auth_header_name=app.get("auth_header_name", "Authorization"),
            additional_origins=app.get("additional_origins"),
            enable_response_cache=app.get("enable_response_cache", 0),
        )

        # Regenerate Nginx config to use the real cert
        nginx_synced, nginx_err = nginx_manager.sync_protected_apps_to_nginx()
        if not nginx_synced:
            # The cert was issued and persisted, but nginx isn't serving it
            # yet — surface that clearly instead of a bare "success".
            log_admin_action("app", str(app_id), "provision_ssl", current_user, details={"domain": domain, "status": "partial"}, request=request)
            return {
                "status": "partial",
                "message": (
                    f"Let's Encrypt certificate issued for {domain}, but applying it to "
                    f"NGINX failed: {nginx_err}. The certificate is saved and will be used "
                    f"once the config is successfully synced (e.g. by saving the app again)."
                ),
                "cert_path": fullchain,
            }

        log_admin_action("app", str(app_id), "provision_ssl", current_user, details={"domain": domain, "status": "success"}, request=request)
        return {
            "status": "success",
            "message": f"Let's Encrypt certificate issued for {domain}",
            "cert_path": fullchain,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL provisioning error: {str(e)}")


@router.post("/apps/{app_id}/upload-cert")
async def upload_custom_cert(request: Request,
    app_id: int,
    cert_file: UploadFile = File(..., description="TLS certificate file (.crt / .pem)"),
    key_file: UploadFile = File(..., description="Private key file (.key / .pem)"),
    current_user: TokenData = Depends(require_app_write_access),
):
    """
    Upload a custom TLS certificate and private key for a protected app.
    Files are saved to /etc/nginx/ssl/custom/{domain}/ and the Nginx config is reloaded.
    """
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Protected application not found")

    domain = app.get("domain", "")
    if domain == "_":
        raise HTTPException(
            status_code=400,
            detail="Custom certificates require a real domain name."
        )

    # Validate file extensions as a basic content check
    allowed_exts = {".crt", ".pem", ".key", ".cer"}
    for upload in (cert_file, key_file):
        ext = os.path.splitext(upload.filename or "")[1].lower()
        if ext not in allowed_exts:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file type '{ext}'. Allowed: {', '.join(allowed_exts)}"
            )

    cert_dir = _safe_cert_dir("custom", domain)
    os.makedirs(cert_dir, exist_ok=True)

    cert_path = os.path.join(cert_dir, "cert.pem")
    key_path = os.path.join(cert_dir, "key.pem")

    try:
        cert_data = await cert_file.read()
        key_data = await key_file.read()

        # Sanity check: cert should start with PEM header
        if not cert_data.strip().startswith(b"-----BEGIN"):
            raise HTTPException(status_code=400, detail="Certificate does not appear to be a valid PEM file.")
        if not key_data.strip().startswith(b"-----BEGIN"):
            raise HTTPException(status_code=400, detail="Private key does not appear to be a valid PEM file.")

        # Malware scan (P1-10) — opt-in, same ClamAV sidecar the
        # protected-app upload path (@inspectFile) uses. A PEM cert/key is
        # low-value malware bait, but scanning it too costs nothing extra
        # and keeps "every file upload in this app gets scanned" uniform
        # once an admin turns the feature on.
        from app.services.settings_manager import settings_manager as _settings_manager

        scan_settings = _settings_manager.get_malware_scanning()
        if scan_settings.get("enabled", False):
            from app.services.malware_scan_service import scan_bytes

            for label, data in (("certificate", cert_data), ("private key", key_data)):
                allowed, detail = scan_bytes(
                    data,
                    timeout_seconds=scan_settings.get("scan_timeout_seconds", 5),
                    fail_mode=scan_settings.get("fail_mode", "open"),
                )
                if not allowed:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Uploaded {label} failed malware scan: {detail}",
                    )

        with open(cert_path, "wb") as f:
            f.write(cert_data)
        with open(key_path, "wb") as f:
            f.write(key_data)

        # Secure permissions on the private key
        os.chmod(key_path, 0o600)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save certificate files: {str(e)}")

    # Persist paths to DB
    db_service.update_protected_app(
        app_id=app_id,
        name=app["name"],
        domain=app["domain"],
        upstream_host=app["upstream_host"],
        upstream_port=app["upstream_port"],
        protocol=app["protocol"],
        is_active=app["is_active"],
        rate_limit_rps=app.get("rate_limit_rps", 50),
        burst_tolerance=app.get("burst_tolerance", 100),
        ssl_option="custom",
        ssl_cert_path=cert_path,
        ssl_key_path=key_path,
        # Same pre-existing gap fixed in the Let's Encrypt provisioning
        # call above — see the comment there.
        require_auth=app.get("require_auth", 0),
        auth_check_type=app.get("auth_check_type", "header"),
        auth_header_name=app.get("auth_header_name", "Authorization"),
        additional_origins=app.get("additional_origins"),
        enable_response_cache=app.get("enable_response_cache", 0),
    )

    # Regenerate Nginx config
    nginx_synced, nginx_err = nginx_manager.sync_protected_apps_to_nginx()
    if not nginx_synced:
        log_admin_action("app", str(app_id), "upload_cert", current_user, details={"domain": domain, "status": "partial"}, request=request)
        return {
            "status": "partial",
            "message": (
                f"Custom certificate saved for {domain}, but applying it to NGINX failed: "
                f"{nginx_err}. The certificate is saved and will be used once the config is "
                f"successfully synced (e.g. by saving the app again)."
            ),
            "cert_path": cert_path,
        }

    log_admin_action("app", str(app_id), "upload_cert", current_user, details={"domain": domain, "status": "success"}, request=request)
    return {
        "status": "success",
        "message": f"Custom certificate uploaded and applied for {domain}",
        "cert_path": cert_path,
    }


_VALID_FIELD_TYPES = {"string", "number", "boolean", "enum"}


class ApiFieldTypeSpec(BaseModel):
    """Optional per-field constraint beyond simple presence/allowlisting —
    presence-only checks let a numeric field accept a SQL fragment. All
    fields optional and additive: an endpoint with no field_types entry for
    a given field keeps today's presence/allowlist-only behavior."""
    type: Optional[str] = None  # one of _VALID_FIELD_TYPES, or None (no type check)
    max_length: Optional[int] = None  # only meaningful for type == "string"
    enum: List[Any] = []  # only meaningful for type == "enum"
    pattern: Optional[str] = None  # only meaningful for type == "string"; PCRE, matched via ngx.re at enforcement time


class ApiSchemaEndpoint(BaseModel):
    method: str
    path: str
    required_fields: List[str] = []
    allowed_fields: List[str] = []
    field_types: Dict[str, ApiFieldTypeSpec] = {}


class ApiSchemaPayload(BaseModel):
    mode: str = "log"  # "log" (record violations, never block) | "enforce" (reject with 400)
    endpoints: List[ApiSchemaEndpoint] = []


@router.get("/apps/{app_id}/schema")
async def get_app_schema(app_id: int, current_user: TokenData = Depends(require_app_view_access)):
    """
    Positive-security API schema for this app — the known-good endpoint
    list ml_check.lua's schema_validate module enforces (or just logs
    against, in "log" mode). Empty/unset means no schema configured, which
    is a no-op everywhere else this app's traffic is inspected — same
    "absence never means deny-all" convention as Positive Security.
    """
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Protected application not found")

    raw = app.get("api_schema")
    endpoints = json.loads(raw)["endpoints"] if raw else []
    return {"mode": app.get("api_schema_mode") or "log", "endpoints": endpoints}


@router.put("/apps/{app_id}/schema")
async def update_app_schema(request: Request,
    app_id: int,
    payload: ApiSchemaPayload,
    current_user: TokenData = Depends(require_app_write_access),
):
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Protected application not found")

    if payload.mode not in ("log", "enforce"):
        raise HTTPException(status_code=400, detail="mode must be 'log' or 'enforce'.")

    valid_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    for ep in payload.endpoints:
        if ep.method.upper() not in valid_methods:
            raise HTTPException(status_code=400, detail=f"Invalid HTTP method: '{ep.method}'")
        if not ep.path.startswith("/"):
            raise HTTPException(status_code=400, detail=f"Endpoint path must start with '/': '{ep.path}'")
        for field_name, spec in ep.field_types.items():
            if spec.type is not None and spec.type not in _VALID_FIELD_TYPES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid type '{spec.type}' for field '{field_name}' — must be one of {sorted(_VALID_FIELD_TYPES)}.",
                )
            if spec.type == "enum" and not spec.enum:
                raise HTTPException(
                    status_code=400,
                    detail=f"Field '{field_name}' declares type 'enum' but no enum values were given.",
                )
            if spec.max_length is not None and spec.max_length < 1:
                raise HTTPException(
                    status_code=400,
                    detail=f"max_length for field '{field_name}' must be a positive integer.",
                )
            if spec.pattern:
                try:
                    re.compile(spec.pattern)
                except re.error as exc:
                    # Best-effort syntax check only — enforcement runs the
                    # pattern through PCRE via ngx.re at request time, not
                    # Python's re engine. Catches typos, not every possible
                    # engine-specific divergence.
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid regex pattern for field '{field_name}': {exc}",
                    )

    schema_json = (
        json.dumps({"endpoints": [ep.dict() for ep in payload.endpoints]})
        if payload.endpoints else None
    )
    db_service.update_app_api_schema(app_id, schema_json, payload.mode)

    success, err_msg = nginx_manager.apply_api_schema_settings(app["domain"], schema_json, payload.mode)
    if not success:
        raise HTTPException(
            status_code=500,
            detail=f"Saved, but failed to apply the API schema. {err_msg}",
        )

    log_admin_action(
        "app", str(app_id), "update_api_schema", current_user,
        details={"mode": payload.mode, "endpoint_count": len(payload.endpoints)},
        request=request,
    )
    return {"status": "success", "mode": payload.mode, "endpoints": [ep.dict() for ep in payload.endpoints]}


class OpenApiSchemaImportRequest(BaseModel):
    filename: str = ""
    content: str = Field(..., min_length=1)


@router.post("/apps/{app_id}/schema/import-openapi")
async def import_app_schema_from_openapi(request: Request,
    app_id: int,
    payload: OpenApiSchemaImportRequest,
    current_user: TokenData = Depends(require_app_write_access),
):
    """
    Parses an uploaded OpenAPI 3.x/Swagger 2.0 document into this app's
    Positive-Security schema format (ApiSchemaEndpoint list, same shape
    PUT /apps/{app_id}/schema already accepts).

    Returns a PREVIEW only — nothing is saved or applied here. The admin
    reviews/edits the parsed result in the existing schema editor and
    applies it via the existing PUT route, so this adds zero new
    validation or Redis-write logic; it only produces input for a save
    path that's already trusted. See api_spec.extract_positive_security_schema
    for the parsing rules — notably, endpoints with a {templated} path
    segment are excluded (not matchable by this WAF's exact-path schema
    enforcement) and reported in `skipped` instead, rather than silently
    imported as a rule that could never actually apply.
    """
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Protected application not found")

    try:
        result = api_spec.extract_positive_security_schema(payload.content)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    log_admin_action(
        "app", str(app_id), "import_openapi_schema", current_user,
        details={
            "filename": payload.filename,
            "endpoint_count": len(result["endpoints"]),
            "skipped_count": len(result["skipped"]),
        },
        request=request,
    )
    return result


# ============================================================================
# mTLS for API auth (roadmap item) — client-certificate verification,
# scoped to each app's /api path only (see ml_check.lua's check_mtls() and
# nginx_manager.py's per-app server-block generation for why: SSL
# verification happens once per TLS handshake, before nginx knows the
# request path, so nginx is only ever told to REQUEST a client cert
# — `ssl_verify_client optional` — never to require one; the actual
# /api-only enforcement is a Lua-side check on $ssl_client_verify).
#
# Settings (enabled + mode) and the CA cert file are two separate routes,
# same separation the SSL cert upload routes already keep from the main
# app fields — a CA cert upload doesn't fit the JSON app-form shape, and
# keeping it as its own dedicated updater (like update_app_api_schema)
# means the 8 existing create/update/rollback call sites elsewhere in this
# file never needed to change at all.
# ============================================================================

class MtlsSettingsModel(BaseModel):
    enabled: bool
    mode: str = "log"  # "log" (request+record, never block) | "enforce" (reject with 403)


@router.get("/apps/{app_id}/mtls")
async def get_app_mtls(app_id: int, current_user: TokenData = Depends(require_app_view_access)):
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Protected application not found")
    return {
        "enabled": bool(app.get("mtls_enabled", 0)),
        "mode": app.get("mtls_mode") or "log",
        "ca_cert_uploaded": bool(app.get("mtls_ca_cert_path")),
    }


@router.put("/apps/{app_id}/mtls")
async def update_app_mtls_settings(request: Request,
    app_id: int,
    payload: MtlsSettingsModel,
    current_user: TokenData = Depends(require_app_write_access),
):
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Protected application not found")

    if payload.mode not in ("log", "enforce"):
        raise HTTPException(status_code=400, detail="mode must be 'log' or 'enforce'.")

    if payload.enabled and not app.get("mtls_ca_cert_path"):
        raise HTTPException(
            status_code=400,
            detail="Upload a CA certificate for this app before enabling mTLS.",
        )

    db_service.update_app_mtls(app_id, 1 if payload.enabled else 0, payload.mode)

    success, err_msg = nginx_manager.sync_protected_apps_to_nginx()
    if not success:
        # Roll the DB flag back too — a failed nginx sync must not leave
        # the admin believing mTLS is active when it isn't (or vice versa).
        db_service.update_app_mtls(app_id, app.get("mtls_enabled", 0), app.get("mtls_mode") or "log")
        raise HTTPException(
            status_code=500,
            detail=f"Saved, but failed to apply mTLS settings to NGINX. {err_msg}",
        )

    log_admin_action(
        "app", str(app_id), "update_mtls", current_user,
        details={"enabled": payload.enabled, "mode": payload.mode},
        request=request,
    )
    return {"enabled": payload.enabled, "mode": payload.mode}


@router.post("/apps/{app_id}/mtls/ca-cert")
async def upload_mtls_ca_cert(request: Request,
    app_id: int,
    ca_file: UploadFile = File(..., description="CA certificate (PEM) trusted to verify client certificates"),
    current_user: TokenData = Depends(require_app_write_access),
):
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Protected application not found")

    ext = os.path.splitext(ca_file.filename or "")[1].lower()
    if ext not in {".crt", ".pem", ".cer"}:
        raise HTTPException(status_code=400, detail=f"Invalid file type '{ext}'. Allowed: .crt, .pem, .cer")

    ca_data = await ca_file.read()
    if not ca_data.strip().startswith(b"-----BEGIN"):
        raise HTTPException(status_code=400, detail="CA certificate does not appear to be a valid PEM file.")

    # Same opt-in malware scan every other upload path in this file goes
    # through — see upload_custom_cert's identical block for why scanning
    # a low-value-bait PEM file is still worth the uniformity.
    from app.services.settings_manager import settings_manager as _settings_manager

    scan_settings = _settings_manager.get_malware_scanning()
    if scan_settings.get("enabled", False):
        from app.services.malware_scan_service import scan_bytes

        allowed, detail = scan_bytes(
            ca_data,
            timeout_seconds=scan_settings.get("scan_timeout_seconds", 5),
            fail_mode=scan_settings.get("fail_mode", "open"),
        )
        if not allowed:
            raise HTTPException(status_code=400, detail=f"Uploaded CA certificate failed malware scan: {detail}")

    ca_path = nginx_manager.app_mtls_ca_path(app_id)
    os.makedirs(os.path.dirname(ca_path), exist_ok=True)
    try:
        with open(ca_path, "wb") as f:
            f.write(ca_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save CA certificate: {e}")

    db_service.set_app_mtls_ca_cert(app_id, ca_path)

    # Deliberately NOT syncing nginx here — uploading a CA cert alone
    # doesn't turn mTLS on (mtls_enabled is still whatever it was), same
    # "upload is inert until the settings route enables it" shape as the
    # OpenAPI import preview above. The next enable (or any other config
    # change) picks the new file up naturally.

    log_admin_action("app", str(app_id), "upload_mtls_ca_cert", current_user, details={"filename": ca_file.filename}, request=request)
    return {"status": "success", "message": "CA certificate uploaded."}


@router.delete("/apps/{app_id}/mtls/ca-cert")
async def remove_mtls_ca_cert(request: Request, app_id: int, current_user: TokenData = Depends(require_app_write_access)):
    app = db_service.get_protected_app_by_id(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Protected application not found")

    # Also disables mTLS — nginx_manager.py's mtls_active check already
    # fails safe if the DB flag is on but the file is gone (see its
    # comment), but there's no reason to leave the flag on pointing at
    # nothing once the admin has explicitly removed the cert.
    db_service.update_app_mtls(app_id, 0, app.get("mtls_mode") or "log")
    db_service.set_app_mtls_ca_cert(app_id, None)

    ca_path = app.get("mtls_ca_cert_path")
    if ca_path and os.path.exists(ca_path):
        try:
            os.remove(ca_path)
        except Exception as e:
            logger.warning(f"Failed to remove mTLS CA cert file for app {app_id}: {e}")

    success, err_msg = nginx_manager.sync_protected_apps_to_nginx()
    if not success:
        raise HTTPException(
            status_code=500,
            detail=f"CA certificate removed, but failed to apply the change to NGINX. {err_msg}",
        )

    log_admin_action("app", str(app_id), "remove_mtls_ca_cert", current_user, request=request)
    return {"status": "success", "message": "CA certificate removed; mTLS disabled."}
