import os
import secrets
import logging
from pydantic_settings import BaseSettings
from typing import List, Union
from pydantic import field_validator

# Minimum JWT secret length enforced for security
_MIN_JWT_SECRET_BYTES = 32


class Settings(BaseSettings):
    # API Settings
    PROJECT_NAME: str = "WAF Dashboard API"

    # CORS
    BACKEND_CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3020",
        "http://127.0.0.1:3020",
        "http://192.168.2.70:3020",
        "https://192.168.2.70",
        "https://192.168.2.70:443",
        "https://localhost",
        "https://127.0.0.1",
    ]

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    import json
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    # Log Parsing Directory
    LOG_DIR: str = "/var/log/modsecurity/audit"

    # Security
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Shared secret used by internal service-to-service callers (e.g. the
    # waf-ml container hitting POST /alerts/trigger). Not a user credential.
    INTERNAL_ALERT_TRIGGER_KEY: str = ""

    # ------------------------------------------------------------------
    # SIEM SSO (mint-and-redirect JWT exchange — see docs onboarding doc).
    # Universal/fixed side (per the doc's §10 config split): our audience
    # name and the SIEM's issuer are hardcoded, matching what the SIEM
    # route hardcodes for us. Client-specific side: the HS256 shared
    # secret is per-deployment and lives in .env.
    # ------------------------------------------------------------------
    SSO_ISSUER: str = "cybersentinel-siem"
    SSO_AUDIENCE: str = "cybersentinel-waf"
    # HS256 phase (build first, per the doc's rollout plan).
    WAF_SSO_SECRET: str = ""
    # RS256/JWKS phase — set once the SIEM has this deployment's audience
    # verified against its live JWKS and flips it into SSO_RS256_TARGETS.
    # Leaving this unset keeps the exchange endpoint on HS256-only.
    SIEM_JWKS_URL: str = ""
    # Replay window for the token's single-use `nonce` claim. Comfortably
    # longer than the SIEM's ~120s token TTL + ~60s nbf back-date skew.
    SSO_NONCE_TTL_SECONDS: int = 300

    # ClickHouse — Log Storage
    CLICKHOUSE_HOST: str = "waf-clickhouse"
    CLICKHOUSE_PORT: int = 8123
    CLICKHOUSE_USER: str = "wafuser"
    CLICKHOUSE_PASSWORD: str = ""
    CLICKHOUSE_DB: str = "cybersentinel"

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"

    def get_secret(self) -> str:
        """
        Returns a validated JWT secret key with minimum entropy enforcement.
        Key must be at least 32 bytes (256 bits) for HS256 security compliance.
        """
        secret = self.JWT_SECRET_KEY

        # Try loading from file if env var is empty/missing
        if not secret and os.path.exists("jwt_secret.txt"):
            with open("jwt_secret.txt", "r") as f:
                secret = f.read().strip()

        # Enforce minimum entropy — reject weak/short secrets
        if secret and len(secret.encode("utf-8")) < _MIN_JWT_SECRET_BYTES:
            logging.critical(
                f"SECURITY ERROR: JWT_SECRET_KEY is only {len(secret.encode())} bytes. "
                f"Minimum required is {_MIN_JWT_SECRET_BYTES} bytes (256 bits). "
                "Auto-generating a secure random key for this session. "
                "Please update your .env file with a stronger secret: "
                f"python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
            secret = None  # Force auto-generation

        if secret:
            return secret

        # Safe fallback: auto-generate cryptographically secure secret
        logging.warning(
            "JWT_SECRET_KEY not found or insufficient. "
            "Generating ephemeral 64-byte random secret. "
            "Sessions will NOT persist across restarts. "
            "Set JWT_SECRET_KEY in your .env file to fix this."
        )
        return secrets.token_hex(32)


settings = Settings()
settings.JWT_SECRET_KEY = settings.get_secret()

if not settings.INTERNAL_ALERT_TRIGGER_KEY:
    logging.warning(
        "INTERNAL_ALERT_TRIGGER_KEY not set. Generating an ephemeral key for "
        "this process — the waf-ml container's alert triggers will fail to "
        "authenticate until it is also given this value (restart required). "
        "Set INTERNAL_ALERT_TRIGGER_KEY in .env to fix this permanently."
    )
    settings.INTERNAL_ALERT_TRIGGER_KEY = secrets.token_hex(32)
