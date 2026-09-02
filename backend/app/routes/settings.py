import asyncio
import ipaddress
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status, Depends, Query, Request
from pydantic import BaseModel, field_validator
from typing import Dict, Any, Optional, List

from app.services.settings_manager import settings_manager
from app.services.auth import verify_password, require_admin, require_any_role, TokenData
from app.utils.audit import log_admin_action
from app.utils.security import get_client_ip, is_ip_in_networks

logger = logging.getLogger(__name__)
router = APIRouter()


def _validate_ip_or_cidr(ip_str: str) -> bool:
    """Shared by the hardening and admin-login-allowlist routes: accepts
    either a plain IP address or a CIDR network string."""
    s = ip_str.strip()
    if not s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        try:
            ipaddress.ip_network(s, strict=False)
            return True
        except ValueError:
            return False


class GeneralSettingsModel(BaseModel):
    refreshInterval: str
    logsPerPage: str
    liveUpdates: bool


class WAFSettingsModel(BaseModel):
    secRuleEngine: str
    detectionMode: str
    paranoiaLevel: int


class LogSettingsModel(BaseModel):
    auditEnabled: bool
    logFormat: str
    concurrentLogging: bool
    retention: str


class PasswordChangeModel(BaseModel):
    currentPassword: str
    newPassword: str


class AutoLearningModel(BaseModel):
    enabled: bool
    learning_period: str
    confidence_threshold: int


class CustomResponseModel(BaseModel):

    html_content: str


from typing import List


class PositiveSecurityModel(BaseModel):
    # Not actually used to validate the request body — update_positive_security
    # below takes an EncodedPayloadModel and decodes it manually (see the
    # Base64 handling there). Kept here to document the real shape of
    # what's stored/generated into NGINX. Defaults to disabled: turning this
    # on enforces allowed_methods/allowed_content_types/restricted_extensions
    # for every protected app's traffic — never the dashboard's own API.
    enabled: bool = False
    allowed_methods: List[str]
    allowed_content_types: List[str]
    restricted_extensions: List[str]


class AdvancedRuleModel(BaseModel):
    id: str
    name: str
    parameter_type: str  # 'URI', 'Method', 'Header', 'Referrer', 'Content-Type', 'IP', 'Country', 'ISP/ASN'
    parameter_value: str
    rate_limit_rps: int
    burst_tolerance: int
    enabled: bool


class DdosBotMitigationModel(BaseModel):
    rate_limit_rps: int
    burst_tolerance: int
    trusted_ips: List[str]
    bot_mitigation_action: str
    advanced_rules: List[AdvancedRuleModel] = []
    # Independent of bot_mitigation_action's "JS Challenge" (which gates on
    # the bad-bot User-Agent signal) — this triggers the same interstitial
    # off the ML risk score's "log" band (0.40-0.70) instead. Off by
    # default: a deployment that hasn't explicitly opted in sees zero
    # behavior change.
    risk_challenge_enabled: bool = False
    # Independent of both toggles above — a tighter, Lua/Redis-enforced
    # rate check for IPs whose reputation has crossed a threshold, layered
    # on top of (never replacing) the native limit_req zones. Off by
    # default, same reasoning as risk_challenge_enabled.
    adaptive_throttle_enabled: bool = False


class HardeningModel(BaseModel):
    hsts_enabled: bool
    hsts_max_age: int
    server_cloaking: bool
    ip_blacklist: List[str]
    ip_whitelist: List[str]


class AdminLoginAllowlistModel(BaseModel):
    enabled: bool
    allowed_networks: List[str]


class GeoBlockModel(BaseModel):
    enabled: bool
    mode: str  # "deny" (block listed countries) | "allow" (block everyone else)
    countries: List[str]  # ISO 3166-1 alpha-2 codes, e.g. "RU", "CN"


class ThreatIntelModel(BaseModel):
    enabled: bool
    sync_interval_hours: int


class AutoReputationModel(BaseModel):
    enabled: bool
    block_threshold: int
    window_hours: int
    block_ttl_hours: int
    sync_interval_minutes: int


class AntiDefacementModel(BaseModel):
    enabled: bool
    monitored_files: List[str]
    check_interval_seconds: int


class ThreatGlobeModel(BaseModel):
    # server_lat/lon/label/auto_detected are read-only outputs of the
    # startup auto-detection (threat_globe_location.py) — accepted here
    # too (rather than split into a separate response-only model) so a
    # round-trip GET-then-POST from the settings form doesn't have to
    # strip fields; update_threat_globe_settings below re-derives them
    # from the previous value regardless of what's submitted.
    server_lat: Optional[float] = None
    server_lon: Optional[float] = None
    server_label: str = ""
    auto_detected: bool = False
    override_enabled: bool
    override_lat: Optional[float] = None
    override_lon: Optional[float] = None
    override_label: str = ""

    @field_validator("override_lat")
    @classmethod
    def validate_override_lat(cls, v):
        if v is not None and not (-90 <= v <= 90):
            raise ValueError("override_lat must be between -90 and 90.")
        return v

    @field_validator("override_lon")
    @classmethod
    def validate_override_lon(cls, v):
        if v is not None and not (-180 <= v <= 180):
            raise ValueError("override_lon must be between -180 and 180.")
        return v


class MalwareScanningModel(BaseModel):
    enabled: bool
    fail_mode: str
    scan_timeout_seconds: int

    @field_validator("fail_mode")
    @classmethod
    def validate_fail_mode(cls, value: str) -> str:
        allowed = {"open", "closed"}
        if value not in allowed:
            raise ValueError(f"fail_mode must be one of: {', '.join(allowed)}")
        return value


# 1. General Settings Routes
@router.get("/settings/general", response_model=Dict[str, Any])
async def get_general_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_general_settings()


@router.post("/settings/general", response_model=Dict[str, Any])
async def update_general_settings(
    settings: GeneralSettingsModel, current_user: TokenData = Depends(require_admin)
):
    result = settings_manager.update_general_settings(settings.dict())
    log_admin_action("settings", "general", "update", current_user, details=settings.dict())
    return result


# 2. WAF Settings Routes
@router.get("/settings/waf", response_model=Dict[str, Any])
async def get_waf_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_waf_settings()


@router.post("/settings/waf", response_model=Dict[str, Any])
async def update_waf_settings(
    settings: WAFSettingsModel, current_user: TokenData = Depends(require_admin)
):
    if settings.paranoiaLevel < 1 or settings.paranoiaLevel > 4:
        raise HTTPException(
            status_code=400, detail="Paranoia level must be between 1 and 4"
        )
    result = settings_manager.update_waf_settings(settings.dict())
    log_admin_action("settings", "waf", "update", current_user, details=settings.dict())
    return result


# 3. Log Settings Routes
@router.get("/settings/logs", response_model=Dict[str, Any])
async def get_log_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_log_settings()


@router.post("/settings/logs", response_model=Dict[str, Any])
async def update_log_settings(
    settings: LogSettingsModel, current_user: TokenData = Depends(require_admin)
):
    result = settings_manager.update_log_settings(settings.dict())
    log_admin_action("settings", "logs", "update", current_user, details=settings.dict())
    return result


# 3.5 Custom Response Settings Routes
@router.get("/settings/response", response_model=Dict[str, Any])
async def get_custom_response(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_custom_response()


import base64


@router.post("/settings/response", response_model=Dict[str, Any])
async def update_custom_response(
    settings: CustomResponseModel, current_user: TokenData = Depends(require_admin)
):
    logger.info("Updating Custom Response block page.")
    if not settings.html_content.strip():
        raise HTTPException(status_code=400, detail="Block page HTML cannot be empty.")

    saved_settings = settings_manager.update_custom_response(settings.dict())

    from app.services import nginx_manager

    success, err_msg = nginx_manager.apply_custom_response_page(settings.html_content)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Saved, but failed to apply the block page in NGINX. {err_msg}",
        )

    log_admin_action(
        "settings", "response", "update", current_user,
        details={"html_length": len(settings.html_content)},
    )
    return saved_settings


class EncodedPayloadModel(BaseModel):
    payload: str


# 3.6 Positive Security Settings Routes
@router.get("/settings/positive-security", response_model=Dict[str, Any])
async def get_positive_security(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_positive_security()


import json


@router.post("/settings/positive-security", response_model=Dict[str, Any])
async def update_positive_security(
    settings_payload: EncodedPayloadModel,
    current_user: TokenData = Depends(require_admin),
):
    logger.info("Updating Positive Security allowlist.")
    # Payload is Base64-encoded JSON — restricted_extensions/allowed_content_types
    # values (".bak", "application/x-www-form-urlencoded", etc.) previously
    # tripped CRS's own inspection of the dashboard's admin traffic, so this
    # used to be sent under a "WAF_BYPASS_" prefix that deliberately broke
    # the Base64 encoding just so CRS's t:base64Decode transform couldn't
    # decode it and match the real content — smuggling admin payloads past
    # the WAF's inspection of its own traffic. The dashboard vhost's
    # SecRuleRemoveById whitelist (configs/nginx/sites-available/cybersentinel)
    # already covers this false-positive class directly; verified a plain
    # payload with SQLi/XSS/path-traversal-shaped content in every field
    # passes cleanly, so the prefix trick added no protection, just noise.
    try:
        json_str = base64.b64decode(settings_payload.payload).decode("utf-8")
        settings_dict = json.loads(json_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload")

    saved_settings = settings_manager.update_positive_security(settings_dict)

    from app.services import nginx_manager

    success, err_msg = nginx_manager.apply_positive_security_settings(saved_settings)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to apply and reload Positive Security policy in NGINX. {err_msg}",
        )

    log_admin_action("settings", "positive-security", "update", current_user, details=settings_dict)
    return saved_settings


# 3.7 Auto-Learning Settings Routes
@router.get("/settings/auto-learning", response_model=Dict[str, Any])
async def get_auto_learning(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_auto_learning()


@router.post("/settings/auto-learning", response_model=Dict[str, Any])
async def update_auto_learning(
    settings: AutoLearningModel, current_user: TokenData = Depends(require_admin)
):
    result = settings_manager.update_auto_learning(settings.dict())
    log_admin_action("settings", "auto-learning", "update", current_user, details=settings.dict())
    return result


# 3.8 Anti-DDoS & Bot Mitigation Settings Routes

@router.get("/settings/ddos-bot", response_model=Dict[str, Any])
async def get_ddos_bot_mitigation(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_ddos_bot_mitigation()


@router.post("/settings/ddos-bot", response_model=Dict[str, Any])
async def update_ddos_bot_mitigation(
    settings: DdosBotMitigationModel, current_user: TokenData = Depends(require_admin)
):
    import ipaddress

    logger.info("Updating Anti-DDoS & Bot Mitigation settings.")

    # Validate trusted IP address and CIDR inputs
    def validate_ip_or_cidr(ip_str: str) -> bool:
        s = ip_str.strip()
        if not s:
            return False
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            try:
                ipaddress.ip_network(s, strict=False)
                return True
            except ValueError:
                return False

    for ip in settings.trusted_ips:
        if ip.strip() and not validate_ip_or_cidr(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address or CIDR network in Trusted IPs: {ip}",
            )

    # Save to settings JSON
    saved_settings = settings_manager.update_ddos_bot_mitigation(settings.dict())

    # Apply to NGINX
    from app.services import nginx_manager

    success, err_msg = nginx_manager.apply_ddos_settings(saved_settings)
    if not success:
        logger.error(f"Failed to apply DDoS config to NGINX: {err_msg}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to apply and reload DDoS settings in NGINX. {err_msg}",
        )

    log_admin_action("settings", "ddos-bot", "update", current_user, details=settings.dict())
    return saved_settings


# 3.9 Infrastructure Hardening & Server Cloaking Routes
@router.get("/settings/hardening", response_model=Dict[str, Any])
async def get_hardening_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_hardening()


@router.post("/settings/hardening", response_model=Dict[str, Any])
async def update_hardening_settings(
    settings: HardeningModel, current_user: TokenData = Depends(require_admin)
):
    logger.info("Updating Infrastructure Hardening & Cloaking settings.")

    for ip in settings.ip_blacklist:
        if ip.strip() and not _validate_ip_or_cidr(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address or CIDR network in Blacklist: {ip}",
            )

    for ip in settings.ip_whitelist:
        if ip.strip() and not _validate_ip_or_cidr(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address or CIDR network in Whitelist: {ip}",
            )

    saved_settings = settings_manager.update_hardening(settings.dict())

    # Apply to NGINX
    from app.services import nginx_manager

    success, err_msg = nginx_manager.apply_hardening_settings(saved_settings)
    if not success:
        logger.error(f"Failed to apply hardening settings to NGINX: {err_msg}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to apply and reload settings in NGINX. {err_msg}",
        )

    log_admin_action("settings", "hardening", "update", current_user, details=settings.dict())
    return saved_settings


@router.get("/settings/admin-login-allowlist", response_model=Dict[str, Any])
async def get_admin_login_allowlist_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_admin_login_allowlist()


@router.post("/settings/admin-login-allowlist", response_model=Dict[str, Any])
async def update_admin_login_allowlist_settings(
    settings: AdminLoginAllowlistModel, request: Request, current_user: TokenData = Depends(require_admin)
):
    """Restricts /auth/login (and /auth/login/mfa) to the given IPs/CIDRs.
    Distinct from /settings/hardening's ip_whitelist/ip_blacklist, which
    gates all site traffic — this gates only the dashboard's own login."""
    logger.info("Updating admin-login IP allowlist settings.")

    for ip in settings.allowed_networks:
        if ip.strip() and not _validate_ip_or_cidr(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address or CIDR network: {ip}",
            )

    # Refuse to enable a list that would lock the requester themself out —
    # there's no other admin-facing way back in once every account's login
    # is blocked, short of direct DB/Redis/file access on the server.
    if settings.enabled:
        requester_ip = get_client_ip(request)
        if not is_ip_in_networks(requester_ip, settings.allowed_networks):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Refusing to enable: your current IP address ({requester_ip}) is not "
                    "included in the allowlist you're saving, which would lock you out "
                    "immediately. Add your own IP or CIDR first."
                ),
            )

    saved_settings = settings_manager.update_admin_login_allowlist(settings.dict())

    log_admin_action(
        "settings", "admin_login_allowlist", "update", current_user, details=settings.dict()
    )
    return saved_settings


# 3.9.1 Geo-Block Settings Routes
@router.get("/settings/geo-block", response_model=Dict[str, Any])
async def get_geo_block_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_geo_block()


@router.post("/settings/geo-block", response_model=Dict[str, Any])
async def update_geo_block_settings(
    settings: GeoBlockModel, current_user: TokenData = Depends(require_admin)
):
    import re as _re

    if settings.mode not in ("allow", "deny"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="mode must be 'allow' or 'deny'.",
        )

    iso_code_re = _re.compile(r"^[A-Za-z]{2}$")
    for code in settings.countries:
        if not iso_code_re.match(code.strip()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid ISO 3166-1 alpha-2 country code: '{code}'",
            )

    saved_settings = settings_manager.update_geo_block(settings.dict())

    from app.services import nginx_manager

    success, err_msg = nginx_manager.apply_geo_block_settings(saved_settings)
    if not success:
        logger.error(f"Failed to apply geo-block settings: {err_msg}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Saved, but failed to apply the geo-block list. {err_msg}",
        )

    log_admin_action("settings", "geo_block", "update", current_user, details=settings.dict())
    return saved_settings


# 3.9.2 External Threat-Intel Feed Settings Routes
@router.get("/settings/threat-intel", response_model=Dict[str, Any])
async def get_threat_intel_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_threat_intel()


@router.post("/settings/threat-intel", response_model=Dict[str, Any])
async def update_threat_intel_settings(
    settings: ThreatIntelModel, current_user: TokenData = Depends(require_admin)
):
    if settings.sync_interval_hours < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="sync_interval_hours must be at least 1.",
        )

    # Merge rather than replace — last_sync_* are status fields the
    # background service owns, not part of this admin-editable form; a full
    # replace here would silently wipe them on every settings save.
    current = settings_manager.get_threat_intel()
    merged = {**current, "enabled": settings.enabled, "sync_interval_hours": settings.sync_interval_hours}
    saved_settings = settings_manager.update_threat_intel(merged)

    log_admin_action("settings", "threat_intel", "update", current_user, details=settings.dict())
    return saved_settings


@router.post("/settings/threat-intel/sync-now", response_model=Dict[str, Any])
async def trigger_threat_intel_sync(current_user: TokenData = Depends(require_admin)):
    """Runs a sync cycle immediately, bypassing the enabled check — lets an
    admin verify the feed works, or refresh, without waiting for the
    scheduled interval or leaving auto-sync permanently on."""
    from app.services.threat_intel_service import run_threat_intel_sync

    result = await asyncio.to_thread(run_threat_intel_sync, force=True)

    log_admin_action("settings", "threat_intel", "sync_now", current_user, details=result)

    if result.get("status") == "error":
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Threat-intel sync failed: {result.get('error', 'unknown error')}",
        )
    return result


# 3.9.3 Self-Learned IP Reputation Settings Routes (P1-7)
@router.get("/settings/auto-reputation", response_model=Dict[str, Any])
async def get_auto_reputation_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_auto_reputation()


@router.post("/settings/auto-reputation", response_model=Dict[str, Any])
async def update_auto_reputation_settings(
    settings: AutoReputationModel, current_user: TokenData = Depends(require_admin)
):
    if settings.block_threshold < 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="block_threshold must be at least 1.")
    if settings.window_hours < 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="window_hours must be at least 1.")
    if settings.block_ttl_hours < 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="block_ttl_hours must be at least 1.")
    if settings.sync_interval_minutes < 5:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="sync_interval_minutes must be at least 5.")

    # Merge rather than replace — last_sync_* are status fields the
    # background service owns, not part of this admin-editable form; a full
    # replace here would silently wipe them on every settings save.
    current = settings_manager.get_auto_reputation()
    merged = {
        **current,
        "enabled": settings.enabled,
        "block_threshold": settings.block_threshold,
        "window_hours": settings.window_hours,
        "block_ttl_hours": settings.block_ttl_hours,
        "sync_interval_minutes": settings.sync_interval_minutes,
    }
    saved_settings = settings_manager.update_auto_reputation(merged)

    log_admin_action("settings", "auto_reputation", "update", current_user, details=settings.dict())
    return saved_settings


@router.post("/settings/auto-reputation/sync-now", response_model=Dict[str, Any])
async def trigger_auto_reputation_sync(current_user: TokenData = Depends(require_admin)):
    """Runs a sync cycle immediately, bypassing the enabled check — lets an
    admin verify the threshold/window before waiting for the scheduled
    interval or leaving auto-sync permanently on."""
    from app.services.auto_reputation_service import run_auto_reputation_sync

    result = await asyncio.to_thread(run_auto_reputation_sync, force=True)

    log_admin_action("settings", "auto_reputation", "sync_now", current_user, details=result)

    if result.get("status") == "error":
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Auto-reputation sync failed: {result.get('error', 'unknown error')}",
        )
    return result


@router.get("/settings/auto-reputation/blocked")
async def list_auto_blocked_ips(current_user: TokenData = Depends(require_admin)):
    from app.services.auto_reputation_service import get_auto_blocked_ips

    return await asyncio.to_thread(get_auto_blocked_ips)


@router.post("/settings/auto-reputation/release/{ip}")
async def release_auto_blocked_ip_route(ip: str, current_user: TokenData = Depends(require_admin)):
    from app.services.auto_reputation_service import release_auto_blocked_ip

    released = await asyncio.to_thread(release_auto_blocked_ip, ip)
    if not released:
        raise HTTPException(status_code=404, detail=f"{ip} is not currently auto-blocked.")

    log_admin_action("settings", "auto_reputation", "release_ip", current_user, details={"ip": ip})
    return {"message": f"{ip} released from auto-block."}


# 3.10 Web Anti-Defacement Settings Routes
@router.get("/settings/anti-defacement", response_model=Dict[str, Any])
async def get_anti_defacement_settings(
    current_user: TokenData = Depends(require_admin),
):
    return settings_manager.get_anti_defacement()


@router.post("/settings/anti-defacement", response_model=Dict[str, Any])
async def update_anti_defacement_settings(
    settings: AntiDefacementModel, current_user: TokenData = Depends(require_admin)
):
    logger.info("Updating Web Anti-Defacement settings.")
    if settings.check_interval_seconds < 1 or settings.check_interval_seconds > 3600:
        raise HTTPException(
            status_code=400, detail="Check interval must be between 1 and 3600 seconds."
        )
    result = settings_manager.update_anti_defacement(settings.dict())
    log_admin_action("settings", "anti-defacement", "update", current_user, details=settings.dict())
    return result


# 3.10b Threat Globe destination — read is any authenticated role (the
# globe view itself is a dashboard page an Analyst can see), the override
# is admin-only like every other write in this file.
@router.get("/settings/threat-globe", response_model=Dict[str, Any])
async def get_threat_globe_settings(current_user: TokenData = Depends(require_any_role)):
    return settings_manager.get_threat_globe()


@router.post("/settings/threat-globe", response_model=Dict[str, Any])
async def update_threat_globe_settings(
    settings: ThreatGlobeModel, current_user: TokenData = Depends(require_admin)
):
    if settings.override_enabled and (settings.override_lat is None or settings.override_lon is None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="override_lat and override_lon are required when override_enabled is true.",
        )
    # server_lat/lon/label/auto_detected are the auto-detection's own
    # output — preserved from the current stored value rather than taken
    # from the submitted body, so a settings-form round-trip can never
    # accidentally overwrite what threat_globe_location.py detected.
    current = settings_manager.get_threat_globe()
    payload = settings.dict()
    payload["server_lat"] = current.get("server_lat")
    payload["server_lon"] = current.get("server_lon")
    payload["server_label"] = current.get("server_label", "")
    payload["auto_detected"] = current.get("auto_detected", False)

    result = settings_manager.update_threat_globe(payload)
    log_admin_action("settings", "threat-globe", "update", current_user, details=payload)
    return result


# 3.11 Malware Scanning Settings Routes (P1-10)
@router.get("/settings/malware-scanning", response_model=Dict[str, Any])
async def get_malware_scanning_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_malware_scanning()


@router.post("/settings/malware-scanning", response_model=Dict[str, Any])
async def update_malware_scanning_settings(
    settings: MalwareScanningModel, current_user: TokenData = Depends(require_admin)
):
    if settings.scan_timeout_seconds < 1 or settings.scan_timeout_seconds > 60:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_timeout_seconds must be between 1 and 60.",
        )

    # Merge rather than replace — last_check_* are status fields the
    # background monitor owns, not part of this admin-editable form.
    current = settings_manager.get_malware_scanning()
    merged = {
        **current,
        "enabled": settings.enabled,
        "fail_mode": settings.fail_mode,
        "scan_timeout_seconds": settings.scan_timeout_seconds,
    }
    saved_settings = settings_manager.update_malware_scanning(merged)

    from app.services import nginx_manager

    success, err_msg = nginx_manager.apply_malware_scanning_settings(saved_settings)
    if not success:
        logger.error(f"Failed to apply malware scanning settings to NGINX: {err_msg}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to apply and reload settings in NGINX. {err_msg}",
        )

    log_admin_action("settings", "malware_scanning", "update", current_user, details=settings.dict())
    return saved_settings


@router.post("/settings/malware-scanning/check-now", response_model=Dict[str, Any])
async def check_malware_scanning_now(current_user: TokenData = Depends(require_admin)):
    """Pings ClamAV immediately, bypassing the 60s monitor cycle — lets an
    admin verify connectivity right after enabling the feature instead of
    waiting for the next scheduled check."""
    from app.services.malware_scan_service import ping

    reachable = await asyncio.to_thread(ping)
    now_iso = datetime.now(timezone.utc).isoformat()

    current = settings_manager.get_malware_scanning()
    saved_settings = settings_manager.update_malware_scanning({
        **current,
        "last_check_status": "ok" if reachable else "degraded",
        "last_check_at": now_iso,
        "last_check_error": None if reachable else "ClamAV unreachable or ping timed out",
    })

    log_admin_action("settings", "malware_scanning", "check_now", current_user, details={"reachable": reachable})
    return saved_settings


# 4. Password Change Route
# NOTE: kept at its original path for frontend backward-compatibility. It now
# reads/writes through user_service (users.db) instead of settings.json, and
# changes the currently logged-in user's own password (previously this only
# ever touched the hardcoded "admin" record). Admin-issued resets for OTHER
# accounts live in /users/{id}/reset-password (app/routes/users.py).
@router.post("/settings/password")
async def change_password(
    payload: PasswordChangeModel, current_user: TokenData = Depends(require_admin)
):
    from app.services.user_service import user_service

    user = user_service.get_by_username(current_user.username)
    if not user or not verify_password(payload.currentPassword, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password"
        )
    from app.models.user_models import _validate_password_strength

    try:
        _validate_password_strength((payload.newPassword or "").strip())
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    user_service.set_password(user["id"], payload.newPassword)
    log_admin_action("settings", "password", "change_own_password", current_user)
    return {"message": "Password updated successfully!"}


@router.get("/settings/audit-log", response_model=Dict[str, Any])
async def get_audit_log(
    entity_type: Optional[str] = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    hours: Optional[int] = None,
    current_user: TokenData = Depends(require_admin),
):
    """
    Admin-action audit trail (who changed what WAF config, when) — reads
    the ClickHouse audit_log table written by log_admin_action() across
    settings/apps/users/false-positives/rules routes.
    """
    from app.services import clickhouse_service

    rows, total = clickhouse_service.get_audit_log(
        entity_type=entity_type, page=page, size=size, hours=hours
    )
    return {"data": rows, "total": total, "page": page, "size": size}

# NOTE: System administrative actions (restart, reload-nginx, purge-cache, sync-signatures)
# are now exclusively handled by the /system router in app/routes/system.py.
# Those routes are registered under the '/system' prefix in main.py.

