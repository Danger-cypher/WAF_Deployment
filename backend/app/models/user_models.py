"""
CyberSentinel WAF - User Management Data Models
Pydantic models for dashboard user accounts (admin/analyst) and self-service profile.
"""
import re
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, Literal

# Common breached/default passwords worth blocking outright even though
# there's no live breach-list lookup here — these are the ones an attacker
# tries first against any admin panel, WAF or otherwise.
_COMMON_PASSWORDS = {
    "password", "password123", "12345678", "123456789", "1234567890",
    "qwerty123", "admin123", "administrator", "letmein123", "welcome123",
    "changeme123", "cybersentinel", "waf123456", "iloveyou1", "password1",
}


def _validate_password_strength(value: str) -> str:
    """
    Shared strength check for every account whose password controls WAF
    rules / ML retraining. Previously this was just `min_length=8` with no
    complexity requirement anywhere in the app — thin for accounts with
    that level of control. Requires 12+ chars and at least 3 of the 4
    character classes (upper/lower/digit/special); no live breach-list
    lookup (no external network dependency here), but blocks the obvious
    top-of-list guesses directly.
    """
    if len(value) < 12:
        raise ValueError("Password must be at least 12 characters long.")
    if value.lower() in _COMMON_PASSWORDS:
        raise ValueError("This password is too common. Choose something less guessable.")
    classes_present = sum([
        bool(re.search(r"[a-z]", value)),
        bool(re.search(r"[A-Z]", value)),
        bool(re.search(r"\d", value)),
        bool(re.search(r"[^a-zA-Z0-9]", value)),
    ])
    if classes_present < 3:
        raise ValueError(
            "Password must include at least 3 of: lowercase, uppercase, digit, special character."
        )
    return value


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
    password: str = Field(min_length=12)
    role: Literal["admin", "analyst"]
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None

    _validate_password = field_validator("password")(_validate_password_strength)


class UserUpdate(BaseModel):
    role: Optional[Literal["admin", "analyst"]] = None
    enabled: Optional[bool] = None
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None


class AdminPasswordReset(BaseModel):
    new_password: str = Field(min_length=12)

    _validate_password = field_validator("new_password")(_validate_password_strength)


class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None


class SelfPasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12)

    _validate_password = field_validator("new_password")(_validate_password_strength)


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
