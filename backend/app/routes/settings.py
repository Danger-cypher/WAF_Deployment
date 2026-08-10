import logging
import asyncio
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from typing import Dict, Any

from app.services.settings_manager import settings_manager
from app.services.auth import verify_password, require_admin, TokenData

logger = logging.getLogger(__name__)
router = APIRouter()


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


class HardeningModel(BaseModel):
    hsts_enabled: bool
    hsts_max_age: int
    server_cloaking: bool
    ip_blacklist: List[str]
    ip_whitelist: List[str]


class AntiDefacementModel(BaseModel):
    enabled: bool
    monitored_files: List[str]
    check_interval_seconds: int


# 1. General Settings Routes
@router.get("/settings/general", response_model=Dict[str, Any])
async def get_general_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_general_settings()


@router.post("/settings/general", response_model=Dict[str, Any])
async def update_general_settings(
    settings: GeneralSettingsModel, current_user: TokenData = Depends(require_admin)
):
    return settings_manager.update_general_settings(settings.dict())


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
    return settings_manager.update_waf_settings(settings.dict())


# 3. Log Settings Routes
@router.get("/settings/logs", response_model=Dict[str, Any])
async def get_log_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_log_settings()


@router.post("/settings/logs", response_model=Dict[str, Any])
async def update_log_settings(
    settings: LogSettingsModel, current_user: TokenData = Depends(require_admin)
):
    return settings_manager.update_log_settings(settings.dict())


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
    # Decode the placeholder payload to bypass WAF XSS rules
    try:
        decoded_html = settings.html_content.replace("__LT__", "<").replace(
            "__GT__", ">"
        )
        settings.html_content = decoded_html
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload")

    # Simulate writing this to NGINX config dir (e.g. /etc/nginx/html/waf_block.html)
    await asyncio.sleep(0.5)
    return settings_manager.update_custom_response(settings.dict())


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
    # Decode WAF evasion payload
    try:
        encoded_str = settings_payload.payload
        if encoded_str.startswith("WAF_BYPASS_"):
            encoded_str = encoded_str[len("WAF_BYPASS_") :]
        json_str = base64.b64decode(encoded_str).decode("utf-8")
        settings_dict = json.loads(json_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload")

    # Simulate saving this to CRS configuration files
    await asyncio.sleep(0.5)
    return settings_manager.update_positive_security(settings_dict)


# 3.7 Auto-Learning Settings Routes
@router.get("/settings/auto-learning", response_model=Dict[str, Any])
async def get_auto_learning(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_auto_learning()


@router.post("/settings/auto-learning", response_model=Dict[str, Any])
async def update_auto_learning(
    settings: AutoLearningModel, current_user: TokenData = Depends(require_admin)
):
    return settings_manager.update_auto_learning(settings.dict())


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

    success = nginx_manager.apply_ddos_settings(saved_settings)
    if not success:
        logger.error("Failed to apply DDoS config to NGINX. Check permissions.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to apply and reload DDoS settings in NGINX. Check system permissions.",
        )

    return saved_settings


# 3.9 Infrastructure Hardening & Server Cloaking Routes
@router.get("/settings/hardening", response_model=Dict[str, Any])
async def get_hardening_settings(current_user: TokenData = Depends(require_admin)):
    return settings_manager.get_hardening()


@router.post("/settings/hardening", response_model=Dict[str, Any])
async def update_hardening_settings(
    settings: HardeningModel, current_user: TokenData = Depends(require_admin)
):
    import ipaddress

    logger.info("Updating Infrastructure Hardening & Cloaking settings.")

    # Validate IP address and CIDR inputs
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

    for ip in settings.ip_blacklist:
        if ip.strip() and not validate_ip_or_cidr(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address or CIDR network in Blacklist: {ip}",
            )

    for ip in settings.ip_whitelist:
        if ip.strip() and not validate_ip_or_cidr(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address or CIDR network in Whitelist: {ip}",
            )

    saved_settings = settings_manager.update_hardening(settings.dict())

    # Apply to NGINX
    from app.services import nginx_manager

    success = nginx_manager.apply_hardening_settings(saved_settings)
    if not success:
        logger.error("Failed to apply hardening settings to NGINX. Check permissions.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to apply and reload settings in NGINX. Check system permissions.",
        )

    return saved_settings


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
    return settings_manager.update_anti_defacement(settings.dict())


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
    if not payload.newPassword or len(payload.newPassword.strip()) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters long",
        )
    user_service.set_password(user["id"], payload.newPassword)
    return {"message": "Password updated successfully!"}

# NOTE: System administrative actions (restart, reload-nginx, purge-cache, sync-signatures)
# are now exclusively handled by the /system router in app/routes/system.py.
# Those routes are registered under the '/system' prefix in main.py.

