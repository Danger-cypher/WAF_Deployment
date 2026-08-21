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
    sso,
    settings as settings_route,
    false_positives,
    exclusions,
    api_protection,
    ddos,
    ml,
    security_audit,
    apps,
    alerts,
    system,
    users,
    ws,
    auto_learning as auto_learning_route,
)
from app.services.log_reader import scan_log_directory
from app.services.log_ingestor import backfill_logs, start_ingestor, start_ingestor_tasks
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

    # Initialize ClickHouse connection (log availability — non-fatal if unavailable)
    from app.services import clickhouse_service
    if clickhouse_service.is_available():
        logger.info("ClickHouse is available — using as primary log store")
        clickhouse_service.reset_fabricated_api_discovery_fields()
        clickhouse_service.ensure_api_discovery_param_names_column()
    else:
        logger.warning(
            "ClickHouse is NOT available at startup. "
            "Dashboard will show empty logs until ClickHouse is reachable."
        )

    # Ensure the Custom Response block page file exists before any protected
    # app's generated server{} block references it — every such block has an
    # `error_page 403 -> internal location -> alias <this file>`
    # unconditionally (see nginx_manager.sync_protected_apps_to_nginx()), so
    # if the file is missing (fresh install, nobody has saved a custom page
    # via Settings yet) nginx's own "can't open file" 404 masks ModSecurity's
    # real 403 on every single WAF block — confirmed live: ModSecurity logged
    # http_code 403 for a blocked request, but the client received 404.
    # Only writes when missing so an admin's saved customization is never
    # overwritten by a restart.
    try:
        import os
        from app.services.nginx_manager import CUSTOM_RESPONSE_PAGE_PATH, apply_custom_response_page
        if not os.path.exists(CUSTOM_RESPONSE_PAGE_PATH):
            default_html = settings_manager.get_custom_response().get("html_content", "")
            ok, err = apply_custom_response_page(default_html)
            if not ok:
                logger.error(f"Failed to seed default Custom Response block page on startup: {err}")
    except Exception as e:
        logger.error(f"Failed to seed default Custom Response block page on startup: {e}")

    # Sync protected apps to Nginx configuration on startup
    try:
        from app.services.nginx_manager import sync_protected_apps_to_nginx
        synced, sync_err = sync_protected_apps_to_nginx()
        if not synced:
            logger.error(f"Failed to sync protected apps to NGINX on startup: {sync_err}")
    except Exception as e:
        logger.error(f"Failed to sync protected apps to NGINX on startup: {e}")

    # Sync ModSecurity rules and exclusions on startup
    try:
        from app.services.rule_manager import sync_rules_and_exclusions
        sync_rules_and_exclusions()
    except Exception as e:
        logger.error(f"Failed to sync ModSecurity rules to NGINX on startup: {e}")

    # Start watchdog file observer for new audit JSON files
    global observer
    loop = asyncio.get_running_loop()
    observer = start_ingestor(loop)

    # Start async flush loop + nginx poller (non-blocking background tasks)
    await start_ingestor_tasks()

    # Backfill: ingest existing audit files not yet in ClickHouse (async, yields to event loop)
    asyncio.ensure_future(backfill_logs())

    # Start the anti-defacement monitor background task
    from app.services.anti_defacement import start_defacement_monitor
    defacement_task = asyncio.create_task(start_defacement_monitor())

    # Start the log retention enforcement background task
    retention_task = asyncio.create_task(start_log_retention_service())

    # Start the API discovery background task — was previously run inline
    # on every API Protection GET request, adding a full log-tail scan to
    # each dashboard poll's latency.
    from app.services.api_discovery import start_api_discovery_service
    api_discovery_task = asyncio.create_task(start_api_discovery_service())

    # Start the SSL renewal directory watcher background task
    from app.services.ssl_monitor import start_ssl_monitor
    ssl_monitor_task = asyncio.create_task(start_ssl_monitor())

    # Start the Auto-Learning suggestion scheduler background task
    from app.services.auto_learning import start_auto_learning_scheduler
    auto_learning_task = asyncio.create_task(start_auto_learning_scheduler())

    # Start the heartbeat watchdog — checks whether the background tasks
    # above are actually still cycling, and alerts on the transition into
    # "stale" instead of relying on someone noticing a silent outage.
    from app.services.heartbeat_registry import start_heartbeat_watchdog
    heartbeat_watchdog_task = asyncio.create_task(start_heartbeat_watchdog())

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

    # Cancel the SSL monitor task
    ssl_monitor_task.cancel()
    try:
        await ssl_monitor_task
    except asyncio.CancelledError:
        pass

    # Cancel the Auto-Learning scheduler task
    auto_learning_task.cancel()
    try:
        await auto_learning_task
    except asyncio.CancelledError:
        pass

    # Cancel the API discovery task
    api_discovery_task.cancel()
    try:
        await api_discovery_task
    except asyncio.CancelledError:
        pass

    # Cancel the heartbeat watchdog task
    heartbeat_watchdog_task.cancel()
    try:
        await heartbeat_watchdog_task
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


from fastapi.responses import JSONResponse


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Only fires for genuinely unhandled exceptions — FastAPI/Starlette
    already routes HTTPException (404/401/403/etc, raised deliberately
    throughout the routes) through its own default handler before this
    one is ever considered, so a normal 404 never trips a "system_error"
    alert here.

    "system_error" was previously a real dropdown option on the Alerts &
    Integrations rule-creation form that could never actually fire —
    nothing in the codebase ever called trigger_event("system_error", ...).
    An admin could build a whole rule + channel around it and it would
    silently never notify, forever. This is the first real trigger for it.
    """
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)

    from app.services.alert_manager import alert_manager
    asyncio.create_task(alert_manager.trigger_event(
        event_type="system_error",
        event_data={
            "path": request.url.path,
            "method": request.method,
            "error": str(exc),
            "error_type": type(exc).__name__,
        },
        custom_message=f"Unhandled {type(exc).__name__} on {request.method} {request.url.path}: {exc}",
    ))

    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


# Cache hardening config at module level — refreshed every 30 s.
# This avoids a settings file read + deep merge on EVERY HTTP request.
import time as _time_module
_hardening_cache: dict = {}
_hardening_cache_ts: float = 0.0
_HARDENING_CACHE_TTL: float = 30.0  # seconds


def _get_hardening_cached() -> dict:
    global _hardening_cache, _hardening_cache_ts
    now = _time_module.monotonic()
    if now - _hardening_cache_ts > _HARDENING_CACHE_TTL:
        try:
            from app.services.settings_manager import settings_manager
            _hardening_cache = settings_manager.get_hardening()
            _hardening_cache_ts = now
        except Exception as e:
            logger.error(f"Failed to refresh hardening cache: {e}")
    return _hardening_cache


# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none';"
    )

    # Dynamic Infrastructure Hardening & Server Cloaking (cached — no disk I/O per request)
    try:
        hardening = _get_hardening_cached()

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
app.include_router(sso.router, prefix="/auth", tags=["Auth", "SSO"])  # No CSRF dep, same reasoning as /auth/login
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
app.include_router(system.router, tags=["System"], prefix="/system", dependencies=csrf_deps)
app.include_router(users.router, tags=["Users"], dependencies=csrf_deps)
app.include_router(auto_learning_route.router, tags=["Auto-Learning"], dependencies=csrf_deps)
# No csrf_deps: the WebSocket handshake has no Request object for the
# double-submit CSRF check to inspect. Auth is instead done inside the
# handler itself by reading the session cookie directly (see routes/ws.py).
app.include_router(ws.router, tags=["WebSocket"])

if __name__ == "__main__":
    import uvicorn

    # Triggering reload
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
