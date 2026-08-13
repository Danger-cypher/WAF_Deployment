"""
System-level API endpoints for WAF configuration and administrative actions.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import socket
import subprocess
import requests
import asyncio
import logging
from app.services.auth import require_admin, require_any_role, TokenData

logger = logging.getLogger(__name__)
router = APIRouter()


class DNSVerification(BaseModel):
    domain: str


async def _resolve_waf_server_ip() -> dict:
    """Shared implementation behind GET /waf-ip, also called internally by
    /verify-dns — kept separate from the route so it can be called as a
    plain function without FastAPI trying to resolve `Depends(...)` as an
    argument."""
    try:
        # requests.get() is blocking — running it inline in this async route
        # would stall the whole event loop (every other logged-in user's
        # request) for up to the 3s timeout if the outbound call is slow.
        response = await asyncio.to_thread(
            requests.get, 'https://api.ipify.org?format=json', timeout=3
        )
        if response.status_code == 200:
            public_ip = response.json().get('ip')
            return {"public_ip": public_ip, "server_ip": public_ip}
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        server_ip = socket.gethostbyname(hostname)
        return {"server_ip": server_ip, "public_ip": None}
    except Exception:
        return {"server_ip": "127.0.0.1", "public_ip": None}


@router.get("/waf-ip")
async def get_waf_server_ip(current_user: TokenData = Depends(require_any_role)):
    """
    Get the WAF server's public IP address (any authenticated role — used
    by the Protected App wizard's DNS-configuration step).
    """
    return await _resolve_waf_server_ip()


@router.post("/verify-dns")
async def verify_dns_configuration(
    data: DNSVerification, current_user: TokenData = Depends(require_any_role)
):
    """
    Verify if a domain's DNS points to this WAF server
    """
    try:
        waf_ip_data = await _resolve_waf_server_ip()
        waf_ip = waf_ip_data.get("public_ip") or waf_ip_data.get("server_ip")
        resolved_ip = socket.gethostbyname(data.domain)
        points_to_waf = (resolved_ip == waf_ip)
        return {
            "domain": data.domain,
            "resolved_ip": resolved_ip,
            "waf_ip": waf_ip,
            "points_to_waf": points_to_waf,
            "message": "DNS is correctly configured" if points_to_waf else f"DNS points to {resolved_ip} instead of {waf_ip}"
        }
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Could not resolve domain: {data.domain}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS verification failed: {str(e)}")


@router.post("/nginx-reload")
@router.post("/reload-nginx")
async def nginx_reload_endpoint(current_user: TokenData = Depends(require_admin)):
    """
    Reload OpenResty/Nginx WAF configuration gracefully.
    Accepts both /nginx-reload and /reload-nginx for compatibility.
    Delegates to nginx_manager.reload_nginx() which targets the correct waf-openresty container.
    """
    from app.services.nginx_manager import reload_nginx as reload_waf_nginx, test_nginx_config

    # Every other config-writing path (DDoS/hardening/positive-security/virtual
    # patching) validates with `nginx -t` before signaling a reload — this
    # manual button was the one path that skipped it, so it would happily
    # apply-by-reload whatever is currently on disk even if it's broken
    # (e.g. from a hand-edited file), taking the WAF down.
    valid, err_msg = await asyncio.to_thread(test_nginx_config)
    if not valid:
        raise HTTPException(
            status_code=400,
            detail=f"NGINX configuration is currently invalid — reload aborted to avoid taking the WAF down: {err_msg}",
        )

    success = await asyncio.to_thread(reload_waf_nginx)
    if success:
        return {"status": "success", "message": "NGINX service reloaded gracefully."}
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to reload NGINX service. Check system logs and permissions."
        )


def _restart_waf_engine_blocking() -> dict:
    """
    Synchronous implementation of the WAF-engine restart — up to ~80s of
    subprocess.run() calls in the worst case (docker-check + 2 restarts, or
    systemctl fallback with its own two calls). Must run off the event loop
    (see restart_waf_engine below) or it stalls every other request on the
    single-process FastAPI server for the whole duration.
    """
    try:
        # Check if Docker is available in the environment
        docker_available = False
        try:
            res = subprocess.run(["docker", "--version"], capture_output=True)  # nosec B603 B607
            if res.returncode == 0:
                docker_available = True
        except Exception:
            pass

        if docker_available:
            logger.info("Docker environment detected. Restarting WAF containers...")
            # Restart openresty (runs ModSecurity)
            result = subprocess.run(
                ["docker", "restart", "waf-openresty"],
                capture_output=True, text=True, timeout=30
            )  # nosec B603 B607
            if result.returncode != 0:
                logger.error(f"Restart waf-openresty container failed: {result.stderr}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to restart waf-openresty container: {result.stderr.strip()}"
                )

            # Restart ml container (best-effort — warn but don't fail)
            result_ml = subprocess.run(
                ["docker", "restart", "waf-ml"],
                capture_output=True, text=True, timeout=20
            )  # nosec B603 B607
            if result_ml.returncode != 0:
                logger.warning(f"Restart waf-ml container failed: {result_ml.stderr}")

            return {"status": "success", "message": "WAF CyberSentinel Engine container restarted successfully."}

        # Fallback to systemctl (host deployments)
        result = subprocess.run(
            ["sudo", "/usr/bin/systemctl", "restart", "openresty"],
            capture_output=True, text=True, timeout=15
        )  # nosec B603 B607
        if result.returncode != 0:
            logger.error(f"Restart openresty failed: {result.stderr}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to restart OpenResty WAF Engine: {result.stderr.strip()}"
            )

        # Also restart ml-waf service (best-effort)
        subprocess.run(
            ["sudo", "/usr/bin/systemctl", "restart", "ml-waf"],
            capture_output=True, text=True, timeout=15
        )  # nosec B603 B607

        return {"status": "success", "message": "WAF ModSecurity Engine and ML Daemon restarted successfully."}

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Restart command timed out. Please check system status.")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="docker/systemctl command not available in this environment")
    except Exception as e:
        logger.error(f"Error during WAF restart: {e}")
        raise HTTPException(status_code=500, detail=f"System error during restart: {str(e)}")


@router.post("/restart")
async def restart_waf_engine(current_user: TokenData = Depends(require_admin)):
    """
    Restart the WAF Engine (OpenResty + ML containers), with Docker-first then systemctl fallback.
    """
    logger.info("Restart WAF Engine triggered.")
    return await asyncio.to_thread(_restart_waf_engine_blocking)


@router.post("/purge-cache")
async def purge_stats_cache(current_user: TokenData = Depends(require_admin)):
    """
    Purge the in-memory log and stats cache, forcing a full re-scan on next request.
    Useful after bulk log deletion or when the UI shows stale data.
    """
    try:
        import app.services.log_reader as log_reader
        log_reader.cached_logs = []
        log_reader.last_scan_time = 0.0
        log_reader.parsed_entries = {}
        log_reader._nginx_cache = []
        log_reader._nginx_cache_time = 0.0

        # Also trigger an immediate re-scan
        try:
            log_reader.scan_log_directory()
        except Exception:
            pass  # Re-scan is best-effort — cache is already cleared

        # Also clear stats_calculator nginx request count cache
        try:
            import app.services.stats_calculator as stats_calc
            if hasattr(stats_calc, '_nginx_req_cache'):
                stats_calc._nginx_req_cache = {}
                stats_calc._nginx_req_cache_time = {}
        except Exception:
            pass

        logger.info("Cache purged via admin action")
        return {"status": "success", "message": "Dashboard analytics cache purged and rebuilt successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cache purge failed: {str(e)}")


@router.post("/sync-signatures")
async def sync_signatures_endpoint(current_user: TokenData = Depends(require_admin)):
    """
    Reloads ModSecurity to pick up whatever CRS rule files are currently on
    disk in configs/nginx/modsec/coreruleset.

    This does NOT fetch anything — there is no wired-up upstream (git remote,
    package feed, etc.) to pull new OWASP CRS signatures from. It previously
    faked a "download" with a bare asyncio.sleep(1.5) and then logged an
    audit event claiming signatures were "successfully downloaded and
    synchronized," which was false: nothing was ever fetched, only whatever
    was already on disk got reloaded. Updating the CRS ruleset itself still
    requires a manual `git pull` (or replacing the files) in that directory.
    """
    logger.info("Signature reload triggered (reloads currently on-disk CRS rules; does not fetch updates).")

    from app.services.nginx_manager import reload_nginx as reload_waf_nginx, test_nginx_config
    from app.services import rule_manager

    valid, err_msg = await asyncio.to_thread(test_nginx_config)
    if not valid:
        raise HTTPException(
            status_code=400,
            detail=f"NGINX configuration is currently invalid — reload aborted: {err_msg}",
        )

    success = await asyncio.to_thread(reload_waf_nginx)

    # Record the audit event
    try:
        rule_manager.record_audit_event(
            action="sync_signatures",
            details="Reloaded ModSecurity with the CRS rule files currently on disk (no new signatures were fetched).",
            username=current_user.username,
        )
    except Exception:
        pass  # Audit logging is best-effort

    if success:
        return {
            "status": "success",
            "message": "ModSecurity reloaded with the current on-disk rule set. No new signatures were downloaded — this deployment has no upstream signature feed configured.",
        }
    else:
        raise HTTPException(
            status_code=500,
            detail="Reload failed — OpenResty reload unsuccessful. Check backend logs."
        )
