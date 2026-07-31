"""
log_ingestor.py — CyberSentinel WAF
=====================================
Async log ingestor that watches for new ModSecurity audit JSON files and
nginx error log entries, then batch-inserts them into ClickHouse.

Design:
- File watcher (watchdog) triggers on new file creation in the audit log dir
- New events are placed into an asyncio.Queue
- A flush loop drains the queue every FLUSH_INTERVAL seconds or when the
  batch reaches BATCH_SIZE, whichever comes first
- On startup, backfill_logs() scans existing files and ingests any that are
  not already in ClickHouse (checks by transaction ID)
- Fully non-blocking — never holds up FastAPI request handlers
"""

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import List

from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.config.settings import settings
from app.parsers.modsec_parser import parse_modsec_audit_json
from app.parsers.nginx_errorlog_parser import parse_nginx_error_log
from app.services import clickhouse_service

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
BATCH_SIZE: int = 100           # Insert when buffer reaches this many events
FLUSH_INTERVAL: float = 5.0     # Insert at least every N seconds even if batch is not full
BACKFILL_CHUNK: int = 500       # IDs to check per ClickHouse existence query during backfill

NGINX_ERROR_LOG = "/var/log/nginx/error.log"
NGINX_ERROR_LOG_ROTATED = "/var/log/nginx/error.log.1"

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------
_event_queue: asyncio.Queue = asyncio.Queue(maxsize=50_000)
_ingestor_running: bool = False


# ---------------------------------------------------------------------------
# Watchdog file event handler
# ---------------------------------------------------------------------------
class _AuditLogHandler(FileSystemEventHandler):
    """Watches the ModSecurity audit directory for new JSON files."""

    def __init__(self, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self._loop = loop

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        if not path.endswith(".json"):
            return
        # Schedule parsing in the event loop thread-safely
        self._loop.call_soon_threadsafe(
            asyncio.ensure_future,
            _parse_and_enqueue(path),
        )


async def _parse_and_enqueue(file_path: str):
    """Parse a single ModSecurity audit JSON file and push to the queue."""
    entry = parse_modsec_audit_json(file_path, settings.LOG_DIR)
    if entry is None:
        return
    try:
        _event_queue.put_nowait(entry)
    except asyncio.QueueFull:
        logger.warning("Ingestor queue full — dropping event from %s", file_path)


# ---------------------------------------------------------------------------
# Flush loop
# ---------------------------------------------------------------------------
async def _flush_loop():
    """
    Background coroutine: collects events from the queue and batch-inserts
    them into ClickHouse every FLUSH_INTERVAL seconds or at BATCH_SIZE.
    """
    global _ingestor_running
    _ingestor_running = True
    logger.info("ClickHouse ingestor flush loop started")

    buffer: list = []
    last_flush = time.monotonic()

    while True:
        # Drain as many items as available without blocking longer than 1s
        try:
            while len(buffer) < BATCH_SIZE:
                entry = await asyncio.wait_for(_event_queue.get(), timeout=1.0)
                buffer.append(entry)
        except asyncio.TimeoutError:
            pass

        now = time.monotonic()
        if buffer and (len(buffer) >= BATCH_SIZE or now - last_flush >= FLUSH_INTERVAL):
            _flush_to_clickhouse(buffer)
            buffer = []
            last_flush = now


def _flush_to_clickhouse(entries: list):
    """Convert LogEntry objects to dicts and batch-insert into ClickHouse."""
    if not entries:
        return

    rows = []
    for entry in entries:
        try:
            d = entry.dict() if hasattr(entry, "dict") else dict(entry)
            d["log_source"] = "modsec_audit"
            rows.append(d)
        except Exception as ex:
            logger.warning("Failed to serialize log entry: %s", ex)

    if rows:
        inserted = clickhouse_service.insert_waf_events(rows)
        if inserted:
            logger.debug("Flushed %d WAF events to ClickHouse", inserted)


# ---------------------------------------------------------------------------
# Nginx error log polling (supplemental source)
# ---------------------------------------------------------------------------
_last_nginx_parse_time: float = 0.0
_NGINX_POLL_INTERVAL: float = 30.0   # seconds

_seen_nginx_ids: set = set()          # track IDs already enqueued from nginx


async def _nginx_poll_loop():
    """
    Periodically parse the nginx error log for ModSecurity block entries
    that may not have an audit JSON file (e.g., very old entries or permission issues).
    """
    global _last_nginx_parse_time

    while True:
        await asyncio.sleep(_NGINX_POLL_INTERVAL)
        try:
            entries = []
            for path in (NGINX_ERROR_LOG, NGINX_ERROR_LOG_ROTATED):
                if os.path.isfile(path):
                    entries.extend(parse_nginx_error_log(path))

            new_entries = [e for e in entries if e.id not in _seen_nginx_ids]
            if new_entries:
                logger.debug("Nginx poll found %d new error-log entries", len(new_entries))
                for entry in new_entries:
                    _seen_nginx_ids.add(entry.id)
                    try:
                        _event_queue.put_nowait(entry)
                    except asyncio.QueueFull:
                        break
        except Exception as e:
            logger.warning("Nginx poll error: %s", e)


# ---------------------------------------------------------------------------
# Backfill (run once on startup)
# ---------------------------------------------------------------------------
async def backfill_logs():
    """
    Scan the audit log directory for existing JSON files and ingest any
    that are not already stored in ClickHouse.
    Only runs if ClickHouse is reachable; otherwise skips gracefully.
    """
    if not clickhouse_service.is_available():
        logger.warning("ClickHouse unavailable — skipping startup backfill")
        return

    logger.info("Starting ClickHouse backfill from %s …", settings.LOG_DIR)

    from app.services.log_reader import list_newest_log_files

    all_files = list_newest_log_files(limit=100_000)
    logger.info("Backfill: %d audit files found on disk", len(all_files))

    # Check which IDs are already in ClickHouse in chunks to avoid huge IN clauses
    already_stored: set = set()
    # We can't easily get IDs without parsing — so we parse and then dedup by ID
    # Strategy: parse in chunks, batch-check IDs, insert missing ones

    ingested = 0
    skipped = 0
    batch: list = []
    batch_ids: list = []

    for i, file_path in enumerate(all_files):
        if i % 1000 == 0 and i > 0:
            logger.info("Backfill progress: %d/%d files processed", i, len(all_files))

        entry = parse_modsec_audit_json(file_path, settings.LOG_DIR)
        if entry is None:
            continue

        batch.append(entry)
        batch_ids.append(entry.id)

        if len(batch) >= BACKFILL_CHUNK:
            existing_ids = clickhouse_service.event_ids_exist(batch_ids)
            new_entries = [e for e, eid in zip(batch, batch_ids) if eid not in existing_ids]
            if new_entries:
                rows = [e.dict() for e in new_entries]
                for r in rows:
                    r["log_source"] = "modsec_audit"
                n = clickhouse_service.insert_waf_events(rows)
                ingested += n
            skipped += len(existing_ids)
            batch = []
            batch_ids = []
            # Brief yield so we don't starve the event loop
            await asyncio.sleep(0)

    # Flush remaining
    if batch:
        existing_ids = clickhouse_service.event_ids_exist(batch_ids)
        new_entries = [e for e, eid in zip(batch, batch_ids) if eid not in existing_ids]
        if new_entries:
            rows = [e.dict() for e in new_entries]
            for r in rows:
                r["log_source"] = "modsec_audit"
            n = clickhouse_service.insert_waf_events(rows)
            ingested += n
        skipped += len(existing_ids)

    logger.info(
        "Backfill complete: %d new events ingested, %d already existed in ClickHouse",
        ingested, skipped,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def start_ingestor(loop: asyncio.AbstractEventLoop) -> Observer:
    """
    Start the watchdog file observer for new audit JSON files.
    Returns the Observer so the caller can stop() it on shutdown.
    Call this from main.py lifespan startup.
    """
    handler = _AuditLogHandler(loop)
    observer = Observer()
    observer.schedule(handler, path=settings.LOG_DIR, recursive=True)
    observer.start()
    logger.info("Watchdog observer started on %s", settings.LOG_DIR)
    return observer


async def start_ingestor_tasks():
    """
    Launch the flush loop and nginx poll loop as background asyncio tasks.
    Call this from main.py lifespan startup (after start_ingestor).
    """
    asyncio.ensure_future(_flush_loop())
    asyncio.ensure_future(_nginx_poll_loop())
    logger.info("Ingestor background tasks started")
