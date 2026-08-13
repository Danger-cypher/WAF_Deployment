"""
Security utilities for the WAF Dashboard.
Includes input sanitization, XSS/SQLi pattern detection, and security helpers.
"""
import os
import re
import html
import json
from typing import Any, Dict, List, Union, Optional
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Request
import logging

logger = logging.getLogger(__name__)

# SQL Injection patterns (simplified - production should use parameterized queries)
SQL_INJECTION_PATTERNS = [
    r"(?i)(\b(select|union|insert|update|delete|drop|alter|create|truncate)\b.*\b(from|into|table|database)\b)",
    r"(?i)(\b(or|and)\b\s+\d+\s*=\s*\d+)",
    r"(?i)('\s*or\s*'1'\s*=\s*'1)",
    r"(?i)(--|#|/\*)",
    r"(?i)(;\s*(drop|delete|update|insert))",
    r"(?i)(\bexec\b.*\b(xp_cmdshell|sp_executesql)\b)",
    r"(?i)(';\s*(shutdown|pause|kill))",
]

# Command injection patterns
COMMAND_INJECTION_PATTERNS = [
    r"(;|\||`|\$\(|\$\{|\n|\r)",
    r"(?i)(wget|curl|nc|netcat|bash|sh|python|perl)\s",
    r"(?i)(;|&|\|\|)\s*(wget|curl|nc|bash|sh)",
    r"(?i)(%0A|%0D|%00|\.\./)",
]

# XSS patterns
XSS_PATTERNS = [
    r"(?i)(<script[^>]*>|</script>)",
    r"(?i)(javascript\s*:)",
    r"(?i)(on\w+\s*=)",
    r"(?i)(<iframe|<object|<embed|<link|<style)[^>]*>",
    r"(?i)(data\s*:\s*text/html)",
    r"(?i)(expression\s*\()",  # IE CSS expression
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"(\.\./|\.\.\\)",
    r"(?i)(%2e%2e%2f|%2e%2e/|%2e%2e%5c|%252e%252e%252f)",
    r"(?i)(/etc/passwd|/etc/shadow|/proc/self)",
]


def sanitize_string(value: str, max_length: int = 1024) -> str:
    """
    Sanitize a string by:
    1. Truncating to max_length
    2. HTML-encoding special characters
    3. Removing null bytes
    4. Normalizing whitespace
    """
    if not isinstance(value, str):
        return str(value)
    
    # Truncate
    value = value[:max_length]
    
    # Remove null bytes
    value = value.replace('\x00', '')
    
    # HTML encode to prevent XSS
    value = html.escape(value, quote=True)
    
    # Normalize whitespace
    value = ' '.join(value.split())
    
    return value.strip()


def sanitize_dict(data: Dict[str, Any], max_depth: int = 5, max_length: int = 1024) -> Dict[str, Any]:
    """
    Recursively sanitize a dictionary by sanitizing all string values.
    """
    if max_depth <= 0:
        return data
    
    sanitized = {}
    for key, value in data.items():
        if isinstance(value, str):
            sanitized[key] = sanitize_string(value, max_length)
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value, max_depth - 1, max_length)
        elif isinstance(value, list):
            sanitized[key] = sanitize_list(value, max_depth - 1, max_length)
        else:
            sanitized[key] = value
    
    return sanitized


def sanitize_list(items: List[Any], max_depth: int = 5, max_length: int = 1024) -> List[Any]:
    """
    Recursively sanitize a list by sanitizing all string values.
    """
    if max_depth <= 0:
        return items
    
    sanitized = []
    for item in items:
        if isinstance(item, str):
            sanitized.append(sanitize_string(item, max_length))
        elif isinstance(item, dict):
            sanitized.append(sanitize_dict(item, max_depth - 1, max_length))
        elif isinstance(item, list):
            sanitized.append(sanitize_list(item, max_depth - 1, max_length))
        else:
            sanitized.append(item)
    
    return sanitized


def detect_sql_injection(value: str) -> bool:
    """Check if value contains SQL injection patterns."""
    value_lower = value.lower()
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value_lower):
            return True
    return False


def detect_command_injection(value: str) -> bool:
    """Check if value contains command injection patterns."""
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, value):
            return True
    return False


def detect_xss(value: str) -> bool:
    """Check if value contains XSS patterns."""
    for pattern in XSS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False


def detect_path_traversal(value: str) -> bool:
    """Check if value contains path traversal patterns."""
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False


def validate_content_type(content_type: Optional[str], allowed_types: List[str]) -> bool:
    """
    Validate Content-Type header against allowed types.
    Returns True if valid, False otherwise.
    """
    if not content_type:
        return False
    
    content_type_lower = content_type.lower()
    for allowed in allowed_types:
        if allowed.lower() in content_type_lower:
            return True
    return False


def get_client_ip(request: Request) -> str:
    """
    Extract client IP from request, handling reverse proxy headers.

    Prefers X-Real-IP because nginx sets it directly from $remote_addr (see
    every proxy_set_header X-Real-IP line in configs/nginx/sites-available/*)
    — a trustworthy value the client cannot influence. X-Forwarded-For is
    NOT used here even though it's also set: nginx uses
    $proxy_add_x_forwarded_for, which APPENDS to whatever XFF value the
    client already sent rather than replacing it, so the leftmost entry is
    attacker-controlled. Using it directly let anyone bypass the login
    rate-limiter/lockout by sending a fresh fake X-Forwarded-For on every
    attempt (login/MFA lockout in app/routes/auth.py keys off this
    function's return value).
    """
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    if request.client:
        return request.client.host

    return "unknown"


class SecurityAuditLogger:
    """
    Security audit logger for tracking authentication events,
    rate limiting triggers, and input validation failures.
    """
    
    def __init__(self, log_dir: Optional[str] = None):
        if log_dir is None:
            log_dir = os.environ.get("SECURITY_AUDIT_LOG_DIR", "/var/log/cybersentinel")
        self.log_dir = Path(log_dir)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create security audit log directory {self.log_dir}: {e}")
        self.audit_log = self.log_dir / "security_audit.log"
        
    def _log(self, level: str, event_type: str, details: Dict[str, Any]):
        """Write a log entry to the security audit log."""
        timestamp = datetime.now(timezone.utc).isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "level": level,
            "event_type": event_type,
            **details
        }
        
        try:
            with open(self.audit_log, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except IOError as e:
            logger.error(f"Failed to write security audit log: {e}")
    
    def log_auth_attempt(
        self,
        client_ip: str,
        username: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log an authentication attempt."""
        self._log(
            level="INFO" if success else "WARNING",
            event_type="AUTH_ATTEMPT",
            details={
                "client_ip": client_ip,
                "username": username,
                "success": success,
                **(details or {})
            }
        )
    
    def log_rate_limit_trigger(
        self,
        client_ip: str,
        endpoint: str,
        attempts: int,
        block_duration: int
    ):
        """Log a rate limit trigger event."""
        self._log(
            level="WARNING",
            event_type="RATE_LIMIT_TRIGGER",
            details={
                "client_ip": client_ip,
                "endpoint": endpoint,
                "attempts": attempts,
                "block_duration_seconds": block_duration
            }
        )
    
    def log_input_validation_failure(
        self,
        client_ip: str,
        field: str,
        value: str,
        violation_type: str,
        action_taken: str
    ):
        """Log an input validation failure."""
        # Truncate value for logging
        truncated_value = value[:100] if len(value) > 100 else value
        
        self._log(
            level="WARNING",
            event_type="INPUT_VALIDATION_FAILURE",
            details={
                "client_ip": client_ip,
                "field": field,
                "value": truncated_value,
                "violation_type": violation_type,
                "action_taken": action_taken
            }
        )
    
    def log_csrf_failure(
        self,
        client_ip: str,
        endpoint: str,
        details: Optional[str] = None
    ):
        """Log a CSRF token validation failure."""
        self._log(
            level="WARNING",
            event_type="CSRF_FAILURE",
            details={
                "client_ip": client_ip,
                "endpoint": endpoint,
                "details": details or "CSRF token mismatch"
            }
        )
    
    def get_recent_events(
        self,
        event_type: Optional[str] = None,
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get recent security audit events."""
        if not self.audit_log.exists():
            return []
        
        events = []
        cutoff_time = datetime.now(timezone.utc).timestamp() - (hours * 3600)
        
        try:
            with open(self.audit_log, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_time = datetime.fromisoformat(
                            entry.get("timestamp", "0")
                        ).timestamp()
                        
                        if entry_time >= cutoff_time:
                            if event_type is None or entry.get("event_type") == event_type:
                                events.append(entry)
                                if len(events) >= limit:
                                    break
                    except (json.JSONDecodeError, ValueError):
                        continue
        except IOError as e:
            logger.error(f"Failed to read security audit log: {e}")
        
        return events


# Global security audit logger instance
security_audit_logger = SecurityAuditLogger()
