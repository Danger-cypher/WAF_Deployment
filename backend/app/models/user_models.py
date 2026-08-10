"""
CyberSentinel WAF - User Management Data Models
Pydantic models for dashboard user accounts (admin/analyst) and self-service profile.
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Literal


class UserOut(BaseModel):
    id: int
    username: str
    role: Literal["admin", "analyst"]
    display_name: Optional[str] = None
    email: Optional[str] = None
    enabled: bool
    mfa_enabled: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    last_login_at: Optional[str] = None


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=8)
    role: Literal["admin", "analyst"]
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None


class UserUpdate(BaseModel):
    role: Optional[Literal["admin", "analyst"]] = None
    enabled: Optional[bool] = None
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None


class AdminPasswordReset(BaseModel):
    new_password: str = Field(min_length=8)


class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None


class SelfPasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class NotificationPreferences(BaseModel):
    muted_severities: list[Literal["critical", "high", "medium", "low", "info"]] = []
    muted_event_types: list[str] = []


class MfaStatus(BaseModel):
    enabled: bool


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code_png_base64: str


class MfaConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class MfaDisableRequest(BaseModel):
    current_password: str
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class MfaLoginRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
