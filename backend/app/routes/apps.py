import re
import os
import shutil
import subprocess
import asyncio
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from app.services import db_service, nginx_manager
from app.services.auth import require_admin, require_any_role, TokenData

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
    """List all registered protected applications."""
    return db_service.get_all_protected_apps()


@router.get("/apps/{app_id}", response_model=ProtectedAppResponse)
async def get_app(app_id: int, current_user: TokenData = Depends(require_any_role)):
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

    return app


@router.put("/apps/{app_id}", response_model=ProtectedAppResponse)
async def update_app(app_id: int, app_data: ProtectedAppCreate, current_user: TokenData = Depends(require_admin)):
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

    return app


@router.delete("/apps/{app_id}")
async def remove_app(app_id: int, current_user: TokenData = Depends(require_admin)):
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

    return {"message": "Protected application deleted successfully!"}


@router.post("/apps/{app_id}/toggle", response_model=ProtectedAppResponse)
async def toggle_app_active(app_id: int, current_user: TokenData = Depends(require_admin)):
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

    return updated_app


# ---------------------------------------------------------------------------
# SSL Provisioning Endpoints
# ---------------------------------------------------------------------------

# Shared directory for per-domain certs (inside the container's nginx ssl dir)
SSL_DIR = "/etc/nginx/ssl"
ACME_WEBROOT = "/etc/nginx/acme-challenge"


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
    current_user: TokenData = Depends(require_admin),
):
    """
    Trigger Let's Encrypt certificate provisioning for a domain-based protected app.
    Uses the HTTP-01 challenge via the shared acme-challenge webroot.
    Requires certbot installed on the host (available via host volume or container).
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

    # Cert + key will be written here by certbot, then symlinked to nginx ssl dir
    cert_dir = _safe_cert_dir("letsencrypt", domain)
    os.makedirs(cert_dir, exist_ok=True)
    os.makedirs(ACME_WEBROOT, exist_ok=True)

    try:
        # Try certbot inside container first, then fall back to host via docker exec
        certbot_cmds = [
            [
                "certbot", "certonly",
                "--webroot", "-w", ACME_WEBROOT,
                "-d", domain,
                "--non-interactive",
                "--agree-tos",
                "--email", "admin@" + domain,
                "--cert-path", os.path.join(cert_dir, "cert.pem"),
                "--key-path", os.path.join(cert_dir, "key.pem"),
                "--fullchain-path", os.path.join(cert_dir, "fullchain.pem"),
            ],
            # Fallback: host certbot writing to letsencrypt default path
            [
                "certbot", "certonly",
                "--webroot", "-w", ACME_WEBROOT,
                "-d", domain,
                "--non-interactive",
                "--agree-tos",
                "--email", "admin@" + domain,
            ],
        ]

        output = None
        last_error = None
        for cmd in certbot_cmds:
            try:
                # subprocess.run() blocks — up to 120s per attempt, up to two
                # attempts. Running that inline on the event loop would stall
                # every other logged-in user's request for the same duration.
                result = await asyncio.to_thread(
                    subprocess.run,
                    cmd, capture_output=True, text=True, timeout=120  # nosec B603
                )
                if result.returncode == 0:
                    output = result.stdout
                    break
                else:
                    last_error = result.stderr.strip()
            except FileNotFoundError:
                last_error = "certbot binary not found in this path"
                continue
            except subprocess.TimeoutExpired:
                last_error = "certbot timed out after 120s"
                continue

        if output is None:
            raise HTTPException(
                status_code=500,
                detail=f"certbot failed: {last_error}"
            )

        # Resolve cert paths — prefer explicit output, fall back to /etc/letsencrypt default
        fullchain = os.path.join(cert_dir, "fullchain.pem")
        privkey = os.path.join(cert_dir, "key.pem")
        if not os.path.exists(fullchain):
            # Fallback: symlink from /etc/letsencrypt/live/{domain}/
            le_live = f"/etc/letsencrypt/live/{domain}"
            if os.path.exists(le_live):
                src_chain = os.path.join(le_live, "fullchain.pem")
                src_key = os.path.join(le_live, "privkey.pem")
                shutil.copy2(src_chain, fullchain)
                shutil.copy2(src_key, privkey)

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
            return {
                "status": "partial",
                "message": (
                    f"Let's Encrypt certificate issued for {domain}, but applying it to "
                    f"NGINX failed: {nginx_err}. The certificate is saved and will be used "
                    f"once the config is successfully synced (e.g. by saving the app again)."
                ),
                "cert_path": fullchain,
            }

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
    current_user: TokenData = Depends(require_admin),
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
        return {
            "status": "partial",
            "message": (
                f"Custom certificate saved for {domain}, but applying it to NGINX failed: "
                f"{nginx_err}. The certificate is saved and will be used once the config is "
                f"successfully synced (e.g. by saving the app again)."
            ),
            "cert_path": cert_path,
        }

    return {
        "status": "success",
        "message": f"Custom certificate uploaded and applied for {domain}",
        "cert_path": cert_path,
    }
