import re
from fastapi import APIRouter, Depends, HTTPException, status
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

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        # Allow alphanumeric, hyphens, periods, underscores, and wildcards
        cleaned = value.strip().lower()
        if not re.match(r'^[a-zA-Z0-9\-._*]+$', cleaned):
            raise ValueError("Domain contains invalid characters. Only alphanumeric, hyphens, dots, underscores, and '*' are allowed.")
        return cleaned

    @field_validator("upstream_host")
    @classmethod
    def validate_upstream_host(cls, value: str) -> str:
        # Allow hostnames, IP addresses, Docker container names (alphanumeric, dots, hyphens, underscores)
        cleaned = value.strip()
        if not re.match(r'^[a-zA-Z0-9.\-_]+$', cleaned):
            raise ValueError("Upstream host contains invalid characters. Only alphanumeric, hyphens, dots, and underscores are allowed.")
        return cleaned


class ProtectedAppCreate(ProtectedAppBase):
    pass


class ProtectedAppResponse(ProtectedAppBase):
    id: int


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
        burst_tolerance=app_data.burst_tolerance
    )
    if not app:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register application in database."
        )

    # Sync configurations with Nginx
    success = nginx_manager.sync_protected_apps_to_nginx()
    if not success:
        # Revert database insertion if sync failed to keep system in sync
        db_service.delete_protected_app(app["id"])
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Nginx config or reload service. Reverting database registration."
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
        burst_tolerance=app_data.burst_tolerance
    )
    if not app:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update application in database."
        )

    # Sync configurations with Nginx
    success = nginx_manager.sync_protected_apps_to_nginx()
    if not success:
        # Revert database update on Nginx reload failure
        db_service.update_protected_app(
            app_id=app_id,
            name=existing_app["name"],
            domain=existing_app["domain"],
            upstream_host=existing_app["upstream_host"],
            upstream_port=existing_app["upstream_port"],
            protocol=existing_app["protocol"],
            is_active=existing_app["is_active"],
            rate_limit_rps=existing_app.get("rate_limit_rps", 50),
            burst_tolerance=existing_app.get("burst_tolerance", 100)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Nginx config or reload service. Reverting database changes."
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

    # Prevent deleting the last active app to avoid empty Nginx config
    all_apps = db_service.get_all_protected_apps()
    active_apps = [app for app in all_apps if app.get("is_active", 1) == 1]
    if len(active_apps) <= 1 and existing_app.get("is_active", 1) == 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the last active protected application. At least one application must remain active."
        )

    success_db = db_service.delete_protected_app(app_id)
    if not success_db:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete application from database."
        )

    # Sync configurations with Nginx
    success_nginx = nginx_manager.sync_protected_apps_to_nginx()
    if not success_nginx:
        # Revert database deletion if Nginx reload fails
        db_service.create_protected_app(
            name=existing_app["name"],
            domain=existing_app["domain"],
            upstream_host=existing_app["upstream_host"],
            upstream_port=existing_app["upstream_port"],
            protocol=existing_app["protocol"],
            is_active=existing_app["is_active"],
            rate_limit_rps=existing_app.get("rate_limit_rps", 50),
            burst_tolerance=existing_app.get("burst_tolerance", 100)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update Nginx config or reload service. Reverting database changes."
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

    # Validation: Do not allow disabling the last active application
    if new_status == 0:
        all_apps = db_service.get_all_protected_apps()
        active_apps = [a for a in all_apps if a.get("is_active", 1) == 1]
        if len(active_apps) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot disable the last active protected application. At least one application must remain active."
            )

    updated_app = db_service.update_protected_app(
        app_id=app_id,
        name=app["name"],
        domain=app["domain"],
        upstream_host=app["upstream_host"],
        upstream_port=app["upstream_port"],
        protocol=app["protocol"],
        is_active=new_status,
        rate_limit_rps=app.get("rate_limit_rps", 50),
        burst_tolerance=app.get("burst_tolerance", 100)
    )

    # Sync configurations with Nginx
    success = nginx_manager.sync_protected_apps_to_nginx()
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
            burst_tolerance=app.get("burst_tolerance", 100)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Nginx config or reload service. Reverting status change."
        )

    return updated_app
