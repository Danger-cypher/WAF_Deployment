import re
import os
import json
import shutil
import subprocess
import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from pydantic import BaseModel, Field, field_validator
from typing import Any, Dict, List, Optional
from app.services import db_service, nginx_manager
from app.services.auth import require_admin, require_any_role, require_app_view_access, require_app_write_access, TokenData
from app.utils.audit import log_admin_action

logger = logging.getLogger(__name__)

router = APIRouter()


class ProtectedAppBase(BaseModel):
    name: str = Field(..., min_length=1, description="Friendly name of the application")
    domain: str = Field(..., min_length=1, description="Domain name (e.g. app.localhost) or '_'")
    upstream_host: str = Field(..., min_length=1, description="Internal container name or IP address")
    upstream_port: int = Field(..., ge=1, le=65535, description="Upstream network port")
    protocol: str = Field("http", description="Upstream protocol: 'http' or 'https'")
    is_active: int = Field(1, ge=0, le=1, description="1 = active, 0 = inactive")
    rate_limit_rps: int = Field(50, ge=1, le=10000, description="RPS limit per client IP")
    burst_tolerance: int = Field(100, ge=1, le=20000, description="Rate limit burst allowance")
    ssl_option: str = Field("self-signed", description="SSL mode: 'letsencrypt', 'custom', 'self-signed'")
    require_auth: int = Field(0, ge=0, le=1, description="1 = deny requests missing the configured auth header/cookie")
    auth_check_type: str = Field("header", description="'header' or 'cookie' — where to check for auth_header_name")
    auth_header_name: str = Field("Authorization", min_length=1, description="Header or cookie name whose mere presence is required")

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
async def add_app(app_data: ProtectedAppCreate, current_user: TokenData = Depends(require_admin)):
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

    log_admin_action("app", str(app["id"]), "create", current_user, details={"name": app_data.name, "domain": domain_lower})
    return app


@router.put("/apps/{app_id}", response_model=ProtectedAppResponse)
async def update_app(app_id: int, app_data: ProtectedAppCreate, current_user: TokenData = Depends(require_app_write_access)):
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
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate Nginx config or reload service. Reverting database changes. {err_msg}"
        )

    log_admin_action("app", str(app_id), "update", current_user, details={"name": app_data.name, "domain": domain_lower})
    return app


@router.delete("/apps/{app_id}")
async def remove_app(app_id: int, current_user: TokenData = Depends(require_app_write_access)):
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

    log_admin_action("app", str(app_id), "delete", current_user, details={"name": existing_app["name"], "domain": existing_app["domain"]})
    return {"message": "Protected application deleted successfully!"}


@router.post("/apps/{app_id}/toggle", response_model=ProtectedAppResponse)
async def toggle_app_active(app_id: int, current_user: TokenData = Depends(require_app_write_access)):
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
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate Nginx config or reload service. Reverting status change. {err_msg}"
        )

    log_admin_action("app", str(app_id), "toggle", current_user, details={"is_active": new_status})
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
async def provision_letsencrypt(
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
        )

        # Regenerate Nginx config to use the real cert
        nginx_synced, nginx_err = nginx_manager.sync_protected_apps_to_nginx()
        if not nginx_synced:
            # The cert was issued and persisted, but nginx isn't serving it
            # yet — surface that clearly instead of a bare "success".
            log_admin_action("app", str(app_id), "provision_ssl", current_user, details={"domain": domain, "status": "partial"})
            return {
                "status": "partial",
                "message": (
                    f"Let's Encrypt certificate issued for {domain}, but applying it to "
                    f"NGINX failed: {nginx_err}. The certificate is saved and will be used "
                    f"once the config is successfully synced (e.g. by saving the app again)."
                ),
                "cert_path": fullchain,
            }

        log_admin_action("app", str(app_id), "provision_ssl", current_user, details={"domain": domain, "status": "success"})
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
async def upload_custom_cert(
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
    )

    # Regenerate Nginx config
    nginx_synced, nginx_err = nginx_manager.sync_protected_apps_to_nginx()
    if not nginx_synced:
        log_admin_action("app", str(app_id), "upload_cert", current_user, details={"domain": domain, "status": "partial"})
        return {
            "status": "partial",
            "message": (
                f"Custom certificate saved for {domain}, but applying it to NGINX failed: "
                f"{nginx_err}. The certificate is saved and will be used once the config is "
                f"successfully synced (e.g. by saving the app again)."
            ),
            "cert_path": cert_path,
        }

    log_admin_action("app", str(app_id), "upload_cert", current_user, details={"domain": domain, "status": "success"})
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
async def update_app_schema(
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
    )
    return {"status": "success", "mode": payload.mode, "endpoints": [ep.dict() for ep in payload.endpoints]}
