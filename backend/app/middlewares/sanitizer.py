"""
Input sanitization middleware for WAF Dashboard.
Sanitizes user-supplied data to prevent XSS, SQL injection, and command injection attacks.
"""
import re
import html
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import Request, Response, Depends
from fastapi.routing import APIRoute
from starlette.datastructures import Headers

from app.utils.security import (
    sanitize_string,
    detect_sql_injection,
    detect_command_injection,
    detect_xss,
    detect_path_traversal,
    get_client_ip,
    security_audit_logger
)

logger = logging.getLogger(__name__)

# Maximum payload size (10MB)
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024

# Allowed content types for POST/PUT requests
ALLOWED_CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
]


class SanitizationMiddleware:
    """
    Middleware to sanitize user input and validate payloads.
    """
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Create mutable receive function for payload inspection
        request = Request(scope)
        
        # Check Content-Type and size for state-changing methods
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            await self._validate_request(request)
        
        # Continue with the request
        await self.app(scope, receive, send)
    
    async def _validate_request(self, request: Request):
        """Validate content type and size for state-changing requests."""
        content_length = request.headers.get("content-length")
        content_type = request.headers.get("content-type", "").lower()
        
        # Check content type
        if content_type and not any(
            allowed in content_type 
            for allowed in ALLOWED_CONTENT_TYPES
        ):
            logger.warning(f"Unsupported Content-Type: {content_type}")
            # Don't block, but log it
        
        # Check content length
        if content_length:
            try:
                length = int(content_length)
                if length > MAX_PAYLOAD_SIZE:
                    raise Exception(f"Payload too large: {length} bytes")
            except ValueError:
                pass  # Content-Length header invalid, skip check


def sanitize_request_data(data: Any) -> Any:
    """
    Recursively sanitize request data (body, query params, headers).
    """
    if isinstance(data, str):
        return sanitize_string(data)
    elif isinstance(data, dict):
        return {k: sanitize_request_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_request_data(item) for item in data]
    return data


def detect_xss_in_request(request: Request) -> Optional[Dict[str, Any]]:
    """
    Check request data for XSS patterns.
    Returns info dict if XSS detected, None otherwise.
    """
    # Check query parameters
    for key, value in request.query_params.items():
        if detect_xss(value):
            return {
                "field": f"query.{key}",
                "value": value[:100],
                "type": "XSS"
            }
    
    # Check headers (except standard headers)
    suspicious_headers = ["user-agent", "referer", "cookie", "x-forwarded-for"]
    for key, value in request.headers.items():
        if key.lower() in suspicious_headers and detect_xss(value):
            return {
                "field": f"header.{key}",
                "value": value[:100],
                "type": "XSS"
            }
    
    return None


def detect_injection_in_request(request: Request) -> Optional[Dict[str, Any]]:
    """
    Check request data for injection patterns.
    Returns info dict if injection detected, None otherwise.
    """
    all_data = {}
    
    # Collect all data from query params and body
    for key, value in request.query_params.items():
        all_data[key] = value
    
    # Try to read body
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    
    async def send(message):
        pass
    
    # Note: Body access would require more complex implementation
    # For now, focus on query parameters and headers
    
    # Check for injection patterns
    for key, value in all_data.items():
        if detect_sql_injection(value):
            return {
                "field": f"query.{key}",
                "value": value[:100],
                "type": "SQL_INJECTION"
            }
        
        if detect_command_injection(value):
            return {
                "field": f"query.{key}",
                "value": value[:100],
                "type": "COMMAND_INJECTION"
            }
        
        if detect_path_traversal(value):
            return {
                "field": f"query.{key}",
                "value": value[:100],
                "type": "PATH_TRAVERSAL"
            }
    
    return None


# Dependency for route-level sanitization
def require_sanitized_params(request: Request):
    """
    Dependency to sanitize and validate request parameters.
    Raises HTTPException on injection detection.
    """
    # Check for XSS
    xss_info = detect_xss_in_request(request)
    if xss_info:
        client_ip = get_client_ip(request)
        security_audit_logger.log_input_validation_failure(
            client_ip=client_ip,
            field=xss_info["field"],
            value=xss_info["value"],
            violation_type=xss_info["type"],
            action_taken="Request blocked"
        )
        raise Exception(f"Potential {xss_info['type']} detected in {xss_info['field']}")
    
    # Check for injection
    injection_info = detect_injection_in_request(request)
    if injection_info:
        client_ip = get_client_ip(request)
        security_audit_logger.log_input_validation_failure(
            client_ip=client_ip,
            field=injection_info["field"],
            value=injection_info["value"],
            violation_type=injection_info["type"],
            action_taken="Request blocked"
        )
        raise Exception(f"Potential {injection_info['type']} detected in {injection_info['field']}")
    
    return request


def sanitize_response(response: Response) -> Response:
    """
    Sanitize response headers to remove sensitive information.
    """
    sensitive_headers = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
    ]
    
    for header in sensitive_headers:
        if header in response.headers:
            del response.headers[header]
    
    return response
