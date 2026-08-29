"""
CyberSentinel WAF - CVE Virtual Patch Library Routes (P1-5)
Browse the curated CVE template library and deploy/undeploy/switch-mode
for a specific CVE's virtual patch. See virtual_patch_service.py.
"""
import logging
from typing import Dict, List, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from app.services import virtual_patch_service
from app.services.auth import require_admin, require_any_role, TokenData
from app.utils.audit import log_admin_action

logger = logging.getLogger(__name__)
router = APIRouter()


class DeployRequest(BaseModel):
    mode: Literal["detect", "block"]


@router.get("/virtual-patches", response_model=List[Dict])
async def list_virtual_patch_library(current_user: TokenData = Depends(require_any_role)):
    """The full curated CVE template library, each entry annotated with
    whether/how it's currently deployed."""
    return virtual_patch_service.get_library()


@router.get("/virtual-patches/{cve_id}/hits")
async def get_virtual_patch_hits(
    cve_id: str, hours: int = Query(default=24, ge=1, le=720),
    current_user: TokenData = Depends(require_any_role),
):
    """Real-traffic hit count for a deployed virtual patch, reusing the
    same generic per-rule-id ClickHouse lookup the CRS canary report uses
    — this rule's numeric id is just another rule id from that data's
    point of view."""
    template = virtual_patch_service.get_template(cve_id)
    if template is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown CVE template.")

    from app.services import clickhouse_service

    rule_id = virtual_patch_service.rule_id_for(cve_id)
    return clickhouse_service.get_rule_canary_report(str(rule_id), hours=hours)


@router.post("/virtual-patches/{cve_id}/deploy")
async def deploy_virtual_patch(
    cve_id: str, payload: DeployRequest, current_user: TokenData = Depends(require_admin)
):
    """Deploy (or redeploy — e.g. to switch mode) a virtual patch (Admin
    only). mode="detect" logs matches without blocking (pass,log) — the
    recommended first step so real hits can be reviewed before switching
    to mode="block"."""
    template = virtual_patch_service.get_template(cve_id)
    if template is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown CVE template.")

    success, err_msg = virtual_patch_service.deploy(cve_id, payload.mode)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=err_msg)

    log_admin_action(
        "virtual_patch", cve_id, "deploy", current_user,
        details={"mode": payload.mode, "title": template["title"]},
    )
    return {"message": f"{cve_id} deployed in {payload.mode} mode."}


@router.post("/virtual-patches/{cve_id}/undeploy")
async def undeploy_virtual_patch(cve_id: str, current_user: TokenData = Depends(require_admin)):
    """Remove a deployed virtual patch (Admin only)."""
    template = virtual_patch_service.get_template(cve_id)
    if template is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown CVE template.")

    success, err_msg = virtual_patch_service.undeploy(cve_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=err_msg)

    log_admin_action("virtual_patch", cve_id, "undeploy", current_user, details={"title": template["title"]})
    return {"message": f"{cve_id} removed."}
