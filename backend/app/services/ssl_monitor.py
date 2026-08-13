import os
import time
import logging
import asyncio
from app.services.nginx_manager import reload_nginx, test_nginx_config

logger = logging.getLogger(__name__)

LE_SSL_DIR = "/etc/nginx/ssl/letsencrypt"
_last_check_times = {}

def get_cert_files_mtime():
    """
    Scans the letsencrypt SSL directory and returns a dictionary of file path -> mtime.
    Only tracks .pem and .crt files.
    """
    mtimes = {}
    if not os.path.exists(LE_SSL_DIR):
        return mtimes

    for root, dirs, files in os.walk(LE_SSL_DIR):
        for file in files:
            if file.endswith((".pem", ".crt")):
                path = os.path.join(root, file)
                try:
                    mtimes[path] = os.path.getmtime(path)
                except OSError:
                    pass
    return mtimes


async def start_ssl_monitor():
    """
    Background loop that runs periodically to detect Let's Encrypt certificate renewals.
    When a change is detected, it triggers a graceful Nginx reload.
    """
    global _last_check_times
    logger.info("Initializing SSL Auto-Reload Certificate Monitor...")
    
    # Initial scan to establish baseline
    _last_check_times = get_cert_files_mtime()
    
    # Scan intervals (check every 60 seconds)
    SCAN_INTERVAL = 60
    
    try:
        while True:
            await asyncio.sleep(SCAN_INTERVAL)
            
            if not os.path.exists(LE_SSL_DIR):
                continue
                
            current_mtimes = get_cert_files_mtime()
            changed = False
            
            for path, mtime in current_mtimes.items():
                # If file is new or modified
                if path not in _last_check_times or mtime > _last_check_times[path]:
                    logger.info(f"SSL Monitor: Detected updated certificate file: {path}")
                    changed = True
            
            if changed:
                # reload_nginx()/test_nginx_config() shell out via subprocess.run
                # with per-candidate timeouts up to 10s each — run directly on
                # this background task's event loop (shared with every HTTP
                # request in the process), that call would stall the entire
                # dashboard for other users while the SSL monitor reloads.
                logger.info("SSL Monitor: Validating Nginx configuration before reload...")
                valid, err_msg = await asyncio.to_thread(test_nginx_config)
                if not valid:
                    logger.error(
                        f"SSL Monitor: Skipping reload — Nginx configuration is currently "
                        f"invalid, applying it now would take the WAF down: {err_msg}"
                    )
                else:
                    logger.info("SSL Monitor: Triggering graceful Nginx configuration reload to load new certificates...")
                    success = await asyncio.to_thread(reload_nginx)
                    if success:
                        logger.info("SSL Monitor: Nginx reload completed successfully.")
                    else:
                        logger.error("SSL Monitor: Nginx reload failed. Check Nginx error logs.")

                # Update baseline
                _last_check_times = current_mtimes
            else:
                # Update baseline in case files were deleted
                _last_check_times = current_mtimes
                
    except asyncio.CancelledError:
        logger.info("SSL Auto-Reload Certificate Monitor task cancelled.")
    except Exception as e:
        logger.error(f"SSL Auto-Reload Certificate Monitor encountered an error: {e}")
