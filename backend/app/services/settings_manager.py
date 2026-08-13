import os
import json
import logging
import tempfile
import threading
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

SETTINGS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "settings.json"
)

DEFAULT_SETTINGS = {
    "general": {"refreshInterval": "5s", "logsPerPage": "15", "liveUpdates": True},
    "waf": {"secRuleEngine": "On", "detectionMode": "Blocking", "paranoiaLevel": 1},
    "logs": {
        "auditEnabled": True,
        "logFormat": "JSON",
        "concurrentLogging": True,
        "retention": "30 Days",
    },
    "auth": {
        "password_hash": "",  # nosec B105
        "analyst_password_hash": ""  # nosec B105
    },
    "auto_learning": {
        "enabled": False,
        "learning_period": "7 Days",
        "confidence_threshold": 90,
    },
    "custom_response": {
        "html_content": '<!DOCTYPE html>\n<html>\n<head>\n<title>403 Forbidden</title>\n<style>\nbody { font-family: sans-serif; text-align: center; padding: 50px; background-color: #f4f4f5; }\nh1 { color: #ef4444; }\n.incident-id { font-family: monospace; background: #e4e4e7; padding: 5px; border-radius: 4px; }\n</style>\n</head>\n<body>\n<h1>Access Denied</h1>\n<p>Your request was blocked by the Web Application Firewall due to security policies.</p>\n<p>If you believe this is an error, please contact support and provide the following transaction ID:</p>\n<p>Transaction ID: <span class="incident-id">{{transaction_id}}</span></p>\n</body>\n</html>'
    },
    "positive_security": {
        "enabled": False,
        "allowed_methods": ["GET", "POST", "HEAD"],
        "allowed_content_types": [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ],
        "restricted_extensions": [".bak", ".config", ".env", ".log", ".sql", ".ini"],
    },
    "ddos_bot_mitigation": {
        "rate_limit_rps": 50,
        "burst_tolerance": 100,
        "trusted_ips": [],
        "bot_mitigation_action": "Silent Drop",
        "advanced_rules": [],
    },
    "hardening": {
        "hsts_enabled": True,
        "hsts_max_age": 31536000,
        "server_cloaking": True,
        "ip_blacklist": [],
        "ip_whitelist": [],
    },
    "anti_defacement": {
        "enabled": False,
        # Default is empty — client configures their own files via the dashboard UI.
        # The demo server's actual monitored files are stored in settings.json and
        # take precedence over this default via _deep_merge on load.
        "monitored_files": [],
        "check_interval_seconds": 5,
    },
}


class SettingsManager:
    def __init__(self):
        # We will load dynamically. We do not call auth.get_password_hash at root to prevent circular import.
        self._settings = None
        # Cache password hashes to avoid file I/O on login
        self._cached_admin_hash: Optional[str] = None
        self._cached_analyst_hash: Optional[str] = None
        # Two admins saving different settings sections at once both read-modify-
        # write the same self._settings dict and the same settings.json file;
        # without a lock the second writer's file write can race the first's
        # and one section's changes get clobbered by the other's stale copy.
        self._lock = threading.Lock()

    @property
    def settings(self) -> Dict[str, Any]:
        if self._settings is None:
            self._settings = self.load_settings()
        return self._settings

    def load_settings(self) -> Dict[str, Any]:
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Merge with default settings to ensure all fields exist
                    merged = self._deep_merge(DEFAULT_SETTINGS, data)
                    return merged
        except Exception as e:
            logger.error(f"Error loading settings file: {e}")

        # If file doesn't exist or has error, initialize it
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        default_data = json.loads(json.dumps(DEFAULT_SETTINGS))  # deep copy

        # Import get_password_hash here to avoid circular imports during startup
        from app.services.auth import get_password_hash

        default_data["auth"]["password_hash"] = get_password_hash("admin123")
        self.save_settings(default_data)
        return default_data

    def save_settings(self, data: Dict[str, Any]) -> None:
        """
        Writes settings.json atomically (temp file + rename) and raises on
        failure. Previously this swallowed every exception and logged it —
        every update_* method below returns the in-memory `data` right after
        calling this, so callers (and the API response) claimed success even
        when the write never reached disk, silently losing the change on the
        next restart.
        """
        settings_dir = os.path.dirname(SETTINGS_FILE)
        os.makedirs(settings_dir, exist_ok=True)
        with self._lock:
            fd, tmp_path = tempfile.mkstemp(
                dir=settings_dir, prefix=".settings-", suffix=".json.tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                os.replace(tmp_path, SETTINGS_FILE)
            except Exception as e:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                logger.error(f"Error saving settings file: {e}")
                raise

    def _deep_merge(self, default: dict, user: dict) -> dict:
        result = default.copy()
        for key, value in user.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def get_general_settings(self) -> Dict[str, Any]:
        return self.settings.get("general", DEFAULT_SETTINGS["general"])

    def update_general_settings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.settings["general"] = data
        self.save_settings(self.settings)
        return self.settings["general"]

    def get_waf_settings(self) -> Dict[str, Any]:
        # Synced with the rule_manager paranoia level
        try:
            from app.services.rule_manager import get_rules_stats

            stats = get_rules_stats()
            if stats and hasattr(stats, "paranoia_level"):
                self.settings["waf"]["paranoiaLevel"] = stats.paranoia_level
            elif isinstance(stats, dict) and "paranoia_level" in stats:
                self.settings["waf"]["paranoiaLevel"] = stats["paranoia_level"]
        except Exception as e:
            logger.error(f"Error reading paranoia level from rule_manager: {e}")
        return self.settings.get("waf", DEFAULT_SETTINGS["waf"])

    def update_waf_settings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.settings["waf"] = data
        # Sync paranoia level with rule_manager if modified
        level = data.get("paranoiaLevel")
        if level is not None:
            try:
                from app.services.rule_manager import set_paranoia_level

                set_paranoia_level(level)
            except Exception as e:
                logger.error(f"Error syncing paranoia level to rule_manager: {e}")
        self.save_settings(self.settings)
        return self.settings["waf"]

    def get_log_settings(self) -> Dict[str, Any]:
        return self.settings.get("logs", DEFAULT_SETTINGS["logs"])

    def update_log_settings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.settings["logs"] = data
        self.save_settings(self.settings)
        return self.settings["logs"]

    def get_password_hash(self) -> str:
        # Return cached hash if available (no file I/O)
        if self._cached_admin_hash:
            return self._cached_admin_hash
        
        # Otherwise load from settings file
        hash_val = self.settings.get("auth", {}).get("password_hash")
        if not hash_val:
            from app.services.auth import get_password_hash

            hash_val = get_password_hash("admin123")
            self.settings.setdefault("auth", {})["password_hash"] = hash_val
            self.save_settings(self.settings)
        
        # Cache for future calls
        self._cached_admin_hash = hash_val
        return hash_val

    def get_analyst_password_hash(self) -> str:
        # Return cached hash if available (no file I/O)
        if self._cached_analyst_hash:
            return self._cached_analyst_hash
        
        # Otherwise load from settings file
        hash_val = self.settings.get("auth", {}).get("analyst_password_hash")
        if not hash_val:
            from app.services.auth import get_password_hash

            hash_val = get_password_hash("analyst123")
            self.settings.setdefault("auth", {})["analyst_password_hash"] = hash_val
            self.save_settings(self.settings)
        
        # Cache for future calls
        self._cached_analyst_hash = hash_val
        return hash_val

    def update_password(self, new_password: str) -> None:
        from app.services.auth import get_password_hash

        self.settings.setdefault("auth", {})["password_hash"] = get_password_hash(
            new_password
        )
        self.save_settings(self.settings)
        # Clear cache on password change
        self._cached_admin_hash = None



    def get_auto_learning(self) -> Dict[str, Any]:
        return self.settings.get("auto_learning", DEFAULT_SETTINGS["auto_learning"])

    def update_auto_learning(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.settings["auto_learning"] = data
        self.save_settings(self.settings)
        return self.settings["auto_learning"]

    def get_custom_response(self) -> Dict[str, Any]:
        return self.settings.get("custom_response", DEFAULT_SETTINGS["custom_response"])

    def update_custom_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.settings["custom_response"] = data
        self.save_settings(self.settings)
        return self.settings["custom_response"]

    def get_positive_security(self) -> Dict[str, Any]:
        return self.settings.get(
            "positive_security", DEFAULT_SETTINGS["positive_security"]
        )

    def update_positive_security(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.settings["positive_security"] = data
        self.save_settings(self.settings)
        return self.settings["positive_security"]

    def get_ddos_bot_mitigation(self) -> Dict[str, Any]:
        return self.settings.get(
            "ddos_bot_mitigation", DEFAULT_SETTINGS["ddos_bot_mitigation"]
        )

    def update_ddos_bot_mitigation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.settings["ddos_bot_mitigation"] = data
        self.save_settings(self.settings)
        return self.settings["ddos_bot_mitigation"]

    def get_hardening(self) -> Dict[str, Any]:
        return self.settings.get("hardening", DEFAULT_SETTINGS["hardening"])

    def update_hardening(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.settings["hardening"] = data
        self.save_settings(self.settings)
        return self.settings["hardening"]

    def get_anti_defacement(self) -> Dict[str, Any]:
        return self.settings.get("anti_defacement", DEFAULT_SETTINGS["anti_defacement"])

    def update_anti_defacement(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.settings["anti_defacement"] = data
        self.save_settings(self.settings)

        # Trigger dynamic re-initialization of anti-defacement service
        try:
            from app.services.anti_defacement import anti_defacement_service

            anti_defacement_service.load_monitored_files()
        except Exception as e:
            logger.error(
                f"Failed to reload monitored files in anti-defacement service: {e}"
            )

        return self.settings["anti_defacement"]


settings_manager = SettingsManager()
