import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.config.settings import settings
from app.routes import (
    logs,
    stats,
    health,
    rules,
    auth,
    settings as settings_route,
    false_positives,
    exclusions,
    api_protection,
    ddos,
    ml,
    security_audit,
    apps,
    alerts,
)
from app.services.log_reader import scan_log_directory
from app.websocket.connection_manager import start_log_watcher
from app.services.log_retention_service import start_log_retention_service

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

observer = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup event
    logger.info("Starting WAF Dashboard API...")

    # Initialize SQLite Database
    from app.services.db_service import init_db

    init_db()

    # Sync protected apps to Nginx configuration on startup
    try:
        from app.services.nginx_manager import sync_protected_apps_to_nginx
        sync_protected_apps_to_nginx()
    except Exception as e:
        logger.error(f"Failed to sync protected apps to NGINX on startup: {e}")

    # Initial scan of the log directory
    scan_log_directory()

    # Start the background file watcher
    global observer
    loop = asyncio.get_running_loop()
    observer = start_log_watcher(loop)

    # Start the anti-defacement monitor background task
    from app.services.anti_defacement import start_defacement_monitor

    defacement_task = asyncio.create_task(start_defacement_monitor())

    # Start the log retention enforcement background task
    retention_task = asyncio.create_task(start_log_retention_service())

    yield

    # Shutdown event
    logger.info("Shutting down WAF Dashboard API...")
    if observer:
        observer.stop()
        observer.join()

    # Cancel the anti-defacement task
    defacement_task.cancel()
    try:
        await defacement_task
    except asyncio.CancelledError:
        pass

    # Cancel the log retention task
    retention_task.cancel()
    try:
        await retention_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

from fastapi.responses import HTMLResponse
from app.services.settings_manager import settings_manager


@app.get("/")
async def root():
    return {"message": "Welcome to WAF Dashboard API. Visit /docs for documentation."}


@app.get("/test-block-page", response_class=HTMLResponse)
async def test_block_page():
    custom_res = settings_manager.get_custom_response()
    html_content = custom_res.get("html_content", "<h1>403 Forbidden</h1>")

    # Inject a dummy transaction ID for demonstration
    dummy_tx_id = str(uuid.uuid4())
    html_content = html_content.replace("{{transaction_id}}", dummy_tx_id)

    return HTMLResponse(content=html_content, status_code=403)


from fastapi import Depends
from app.utils.csrf import verify_csrf_token

# Set up CORS with secure defaults
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# CSP Nonce middleware
@app.middleware("http")
async def add_csp_nonce(request: Request, call_next):
    nonce = request.headers.get("X-Nonce")
    
    response = await call_next(request)
    
    # Store nonce in response headers for frontend access
    response.headers["X-Nonce"] = nonce or "none"
    
    return response


# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    
    # Basic CSP - will be enhanced by CSP nonce middleware
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none';"
    )

    # Dynamic Infrastructure Hardening & Server Cloaking
    try:
        from app.services.settings_manager import settings_manager

        hardening = settings_manager.get_hardening()

        # 1. HSTS Header
        if hardening.get("hsts_enabled", True):
            max_age = hardening.get("hsts_max_age", 31536000)
            response.headers["Strict-Transport-Security"] = (
                f"max-age={max_age}; includeSubDomains; preload"
            )

        # 2. Server Cloaking (stripping server disclosures)
        if hardening.get("server_cloaking", True):
            if "Server" in response.headers:
                del response.headers["Server"]
            if "X-Powered-By" in response.headers:
                del response.headers["X-Powered-By"]
    except Exception as e:
        logger.error(f"Error executing security headers middleware: {e}")

    return response


# Request ID middleware for log correlation
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    # Generate unique request ID
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    response = await call_next(request)
    
    # Add X-Request-Id header to response
    response.headers["X-Request-Id"] = request_id
    
    return response


# Include routers without global prefixes to match exactly: /logs, /stats, /health, /top-ips, etc.
csrf_deps = [Depends(verify_csrf_token)]

app.include_router(logs.router, tags=["Logs"], dependencies=csrf_deps)
app.include_router(stats.router, tags=["Stats"], dependencies=csrf_deps)
app.include_router(health.router, tags=["Health"])  # Health is usually open/GET only
app.include_router(rules.router, tags=["Rules"], dependencies=csrf_deps)
app.include_router(auth.router, prefix="/auth", tags=["Auth"]) # Logout is protected inside auth.py
app.include_router(settings_route.router, tags=["Settings"], dependencies=csrf_deps)
app.include_router(false_positives.router, tags=["False Positives"], dependencies=csrf_deps)
app.include_router(exclusions.router, tags=["Exclusions"], dependencies=csrf_deps)
app.include_router(api_protection.router, tags=["API Protection"], dependencies=csrf_deps)
app.include_router(ddos.router, tags=["DDoS Protection"], dependencies=csrf_deps)
app.include_router(ml.router, tags=["ML Engine"], dependencies=csrf_deps)
app.include_router(security_audit.router, prefix="/security", tags=["Security Audit"])
app.include_router(apps.router, tags=["Protected Apps"], dependencies=csrf_deps)
app.include_router(alerts.router, tags=["Alerts"], dependencies=csrf_deps)
app.include_router(alerts.trigger_router, tags=["Alerts"])

if __name__ == "__main__":
    import uvicorn

    # Triggering reload
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
