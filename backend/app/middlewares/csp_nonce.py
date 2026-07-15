"""
CSP Nonce Middleware for FastAPI
Generates a unique CSP nonce for each request and injects it into HTML responses.
"""
import secrets
import logging
from typing import Optional
from fastapi import Request, Response
from fastapi.responses import HTMLResponse
from starlette.datastructures import MutableHeaders

logger = logging.getLogger(__name__)

NONCE_HEADER_NAME = "X-Nonce"
CSP_NONCE_PLACEHOLDER = "${cspNonce}"


def generate_nonce() -> str:
    """Generate a cryptographically secure CSP nonce."""
    return secrets.token_urlsafe(16)


def add_nonce_to_csp_policy(policy: str, nonce: str) -> str:
    """Add nonce to script-src in CSP policy."""
    if not policy:
        return policy
    
    # Find script-src and add nonce
    import re
    
    # Check if script-src already exists
    script_src_match = re.search(r"script-src\s+([^;]+);", policy)
    if script_src_match:
        # Add nonce to existing script-src
        old_value = script_src_match.group(1)
        if f"'nonce-{nonce}'" not in old_value:
            new_value = old_value.strip() + f" 'nonce-{nonce}'"
            policy = policy.replace(script_src_match.group(0), f"script-src {new_value};")
    else:
        # Add script-src with nonce
        policy = policy.replace("default-src", f"script-src 'nonce-{nonce}' 'self'; default-src")
    
    return policy


class CSPNonceMiddleware:
    """
    Middleware that generates a CSP nonce for each request and injects it into HTML responses.
    """
    
    def __init__(self, app, csp_policy: Optional[str] = None):
        self.app = app
        self.default_csp = csp_policy or (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' https://*.cybersentinel.io https://*.geoipify.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "upgrade-insecure-requests;"
        )
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Generate nonce for this request
        nonce = generate_nonce()
        
        async def send_with_nonce(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                
                # Store nonce in headers for later use
                headers.append(NONCE_HEADER_NAME, nonce)
                
                # Update CSP header with nonce
                csp_header = headers.get("content-security-policy")
                if csp_header:
                    updated_csp = add_nonce_to_csp_policy(csp_header, nonce)
                    headers["Content-Security-Policy"] = updated_csp
                else:
                    headers["Content-Security-Policy"] = add_nonce_to_csp_policy(
                        self.default_csp, nonce
                    )
            
            await send(message)
        
        await self.app(scope, receive, send_with_nonce)


def inject_nonce_into_html(html: str, nonce: str) -> str:
    """
    Inject CSP nonce into HTML content.
    Replaces ${cspNonce} placeholder with actual nonce value.
    """
    return html.replace(CSP_NONCE_PLACEHOLDER, nonce)


def get_nonce_from_headers(headers) -> Optional[str]:
    """Extract nonce from response headers."""
    return headers.get(NONCE_HEADER_NAME)
