import os
import hashlib
import logging
import asyncio
import time
import uuid
from typing import Dict

from app.services.settings_manager import settings_manager
from app.models.log_model import LogEntry
from app.services.log_reader import parsed_entries

logger = logging.getLogger(__name__)


class AntiDefacementService:
    def __init__(self):
        # Maps file path -> file content (bytes)
        self.cached_contents: Dict[str, bytes] = {}
        # Maps file path -> SHA256 hex digest
        self.cached_hashes: Dict[str, str] = {}
        # Thread lock for file operations
        self.lock = asyncio.Lock()

    def calculate_sha256(self, filepath: str) -> str:
        """Calculates SHA-256 hash of a file on disk."""
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing file {filepath}: {e}")
            return ""

    def load_monitored_files(self):
        """
        Prefetches content and hashes of files specified in WAF settings.
        This runs at startup and whenever settings are updated.
        """
        settings = settings_manager.get_anti_defacement()
        monitored_files = settings.get("monitored_files", [])

        # Clear existing caches first
        self.cached_contents.clear()
        self.cached_hashes.clear()

        for filepath in monitored_files:
            filepath = os.path.abspath(filepath.strip())
            if not os.path.exists(filepath):
                logger.warning(
                    f"Anti-Defacement target file does not exist: {filepath}"
                )
                continue

            try:
                with open(filepath, "rb") as f:
                    content = f.read()

                hasher = hashlib.sha256()
                hasher.update(content)
                file_hash = hasher.hexdigest()

                self.cached_contents[filepath] = content
                self.cached_hashes[filepath] = file_hash
                logger.info(
                    f"Prefetched and hashed file for defacement protection: {filepath} (SHA: {file_hash[:10]}...)"
                )
            except Exception as e:
                logger.error(f"Failed to prefetch file {filepath}: {e}")

    def trigger_defacement_alert(self, filepath: str):
        """Injects a critical WAF log entry alerting about the defacement attempt."""
        try:
            alert_id = str(uuid.uuid4())
            timestamp = time.strftime("%a %b %d %H:%M:%S %Y")

            # Create a custom log entry representing the defacement event
            entry = LogEntry(
                id=alert_id,
                timestamp=timestamp,
                client_ip="127.0.0.1",
                uri=filepath,
                method="SYSTEM",
                http_code="200",
                rule_id="999999",
                message=f"Defacement attempt detected! Reverted unauthorized changes to: {filepath}",
                severity="Critical",
                attack_type="Web Anti-Defacement",
                hostname="localhost",
                country="Internal",
                raw_log={
                    "source": "waf_anti_defacement",
                    "timestamp": timestamp,
                    "event_type": "file_integrity_compromised",
                    "severity": "Critical",
                    "attack_type": "Web Anti-Defacement",
                    "target_file": filepath,
                    "action_taken": "automatic_restoration",
                },
            )

            # Inject directly into the parsed entries dictionary
            parsed_entries[alert_id] = entry
            logger.warning(
                f"WAF ALERT: Defacement attempt detected and reverted on {filepath}!"
            )
        except Exception as e:
            logger.error(f"Error logging defacement alert: {e}")

    async def check_integrity(self):
        """Checks hashes of monitored files and restores them if defaced."""
        settings = settings_manager.get_anti_defacement()
        if not settings.get("enabled", True):
            return

        async with self.lock:
            for filepath, expected_hash in list(self.cached_hashes.items()):
                if not os.path.exists(filepath):
                    # File was deleted or moved! We count this as a defacement/tampering attempt.
                    logger.warning(
                        f"Protected file missing: {filepath}. Restoring from prefetch cache..."
                    )
                    self.restore_file(filepath)
                    self.trigger_defacement_alert(filepath)
                    continue

                current_hash = self.calculate_sha256(filepath)
                if current_hash != expected_hash:
                    logger.warning(
                        f"Hash mismatch detected on {filepath}! Expected: {expected_hash[:10]}, Found: {current_hash[:10]}. Restoring..."
                    )
                    self.restore_file(filepath)
                    self.trigger_defacement_alert(filepath)

    def restore_file(self, filepath: str):
        """Restores a file using cached content."""
        clean_content = self.cached_contents.get(filepath)
        if clean_content is None:
            logger.error(f"No cached copy available to restore {filepath}")
            return

        try:
            # Re-create parent dirs if they were deleted
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "wb") as f:
                f.write(clean_content)
            logger.info(
                f"Successfully restored protected file to clean state: {filepath}"
            )
        except Exception as e:
            logger.error(f"Failed to restore file {filepath}: {e}")


async def start_defacement_monitor():
    """Background task runner for periodic file-integrity audits."""
    from app.services import heartbeat_registry

    logger.info("Initializing WAF Web Anti-Defacement integrity monitor...")

    # Load initial list of files
    anti_defacement_service.load_monitored_files()

    while True:
        try:
            # Read current check interval from settings
            settings = settings_manager.get_anti_defacement()
            interval = settings.get("check_interval_seconds", 5)

            if settings.get("enabled", True):
                await anti_defacement_service.check_integrity()

            heartbeat_registry.record_heartbeat("anti_defacement_monitor", interval, status="ok")
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            logger.info("Stopping anti-defacement background monitor.")
            break
        except Exception as e:
            logger.error(f"Error in anti-defacement background loop: {e}")
            heartbeat_registry.record_heartbeat(
                "anti_defacement_monitor", 5.0, status="error", detail=str(e)
            )
            await asyncio.sleep(5)


# Singleton instance
anti_defacement_service = AntiDefacementService()
