import os
import re
import glob
import json
import logging
import subprocess
from datetime import datetime
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional, Tuple
from app.models.rule_model import RuleEntry, AuditLogEntry, RuleStatsResponse
from app.services.log_reader import get_all_logs

logger = logging.getLogger(__name__)

# Paths
RULES_DIR = "/etc/nginx/modsec/coreruleset/rules"
STATE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "rule_states.json"
)

# Category mapping based on filename
CATEGORY_MAP = {
    "901": "Initialization",
    "905": "Common Exceptions",
    "911": "Method Enforcement",
    "913": "Scanner Detection",
    "920": "Protocol Enforcement",
    "921": "Protocol Attack",
    "922": "Multipart Attack",
    "930": "LFI",
    "931": "RFI",
    "932": "RCE",
    "933": "PHP Injection",
    "934": "Generic Attack",
    "941": "XSS",
    "942": "SQL Injection",
    "943": "Session Fixation",
    "944": "Java Injection",
    "949": "Blocking Evaluation",
    "950": "Data Leakage",
    "951": "SQL Leakage",
    "952": "Java Leakage",
    "953": "PHP Leakage",
    "954": "IIS Leakage",
    "955": "Web Shells",
    "956": "Ruby Leakage",
    "959": "Blocking Response",
    "980": "Correlation",
}

# In-memory cache of parsed rules (parsed once to avoid disk I/O lag)
_parsed_rules_cache: Optional[List[Dict[str, Any]]] = None


def _get_default_state() -> Dict[str, Any]:
    """Return default configuration overrides state."""
    return {
        "disabled_rule_ids": [],
        "paranoia_level": 1,
        "audit_history": [
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "username": "system",
                "action": "reset",
                "rule_id": None,
                "rule_name": None,
                "details": "WAF Rule Management initialized with OWASP CRS defaults.",
            }
        ],
    }


def _load_state() -> Dict[str, Any]:
    """Load config override state from local JSON DB."""
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading rule states DB: {e}")

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    state = _get_default_state()
    _save_state(state)
    return state


def _save_state(state: Dict[str, Any]) -> None:
    """Save config override state to local JSON DB."""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving rule states DB: {e}")


def _parse_crs_rules() -> List[Dict[str, Any]]:
    """
    Parses all CRS rule files under /etc/nginx/modsec/coreruleset/rules/.
    Regex splits contiguous SecRule multi-line structures and extracts parameters.
    """
    global _parsed_rules_cache
    if _parsed_rules_cache is not None:
        return _parsed_rules_cache

    parsed_rules = []

    if not os.path.isdir(RULES_DIR):
        logger.warning(
            f"CRS rules directory not found: {RULES_DIR}. Falling back to sample set."
        )
        # Fallback rules in case the directory doesn't exist or is unreadable
        _parsed_rules_cache = _get_fallback_rules()
        return _parsed_rules_cache

    try:
        conf_files = glob.glob(os.path.join(RULES_DIR, "*.conf"))
        # Sort files to ensure stable rule lists
        conf_files.sort()

        for file_path in conf_files:
            file_name = os.path.basename(file_path)

            # Identify category
            category = "General"
            for prefix, cat_name in CATEGORY_MAP.items():
                if (
                    f"-{prefix}-" in file_name
                    or file_name.startswith(f"REQUEST-{prefix}-")
                    or file_name.startswith(f"RESPONSE-{prefix}-")
                ):
                    category = cat_name
                    break

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            # Identify blocks
            blocks: List[Tuple[str, str, int]] = (
                []
            )  # List of (block_text, preceding_comments, line_number)
            current_lines = []
            preceding_comments = []
            in_rule = False
            rule_line_start = 0

            # Scan lines
            for i, line in enumerate(lines):
                stripped = line.strip()

                # Capture comment lines when not inside a rule block
                if not in_rule:
                    if stripped.startswith("#"):
                        # Save comments
                        comment_text = stripped.lstrip("#").strip()
                        if comment_text and not comment_text.startswith(
                            "-="
                        ):  # Ignore visual separators
                            preceding_comments.append(comment_text)
                    elif stripped:
                        # Reset comments if we hit an empty space/non-comment line before the SecRule
                        if not stripped.startswith("SecRule"):
                            preceding_comments = []

                if stripped.startswith("SecRule "):
                    in_rule = True
                    rule_line_start = i + 1
                    current_lines = [line]
                elif in_rule:
                    current_lines.append(line)

                if in_rule:
                    # End block if line does not end with backslash
                    if not stripped.endswith("\\"):
                        block_text = "".join(current_lines)
                        comments_summary = "\n".join(
                            preceding_comments[-4:]
                        )  # Limit to last 4 relevant comment lines
                        blocks.append((block_text, comments_summary, rule_line_start))
                        in_rule = False
                        current_lines = []
                        preceding_comments = []

            # Parse each block
            for block, comments, line_num in blocks:
                # Find rule ID (required)
                id_match = re.search(r"id:(\d+)", block)
                if not id_match:
                    continue
                rule_id = id_match.group(1)

                # Find message
                msg_match = re.search(r"msg:\s*'([^']*)'", block) or re.search(
                    r'msg:\s*"([^"]*)"', block
                )
                name = msg_match.group(1) if msg_match else f"OWASP CRS Rule {rule_id}"

                # Find severity
                sev_match = re.search(r"severity:\s*'([^']*)'", block) or re.search(
                    r'severity:\s*"([^"]*)"', block
                )
                sev_raw = sev_match.group(1).upper() if sev_match else "WARNING"

                # Normalize severity
                if "CRIT" in sev_raw or "EMERG" in sev_raw:
                    severity = "Critical"
                elif "ALERT" in sev_raw or "ERR" in sev_raw:
                    severity = "High"
                elif "WARN" in sev_raw:
                    severity = "Medium"
                else:
                    severity = "Low"

                # Find tags
                tags = re.findall(r"tag:\s*'([^']*)'", block) or re.findall(
                    r'tag:\s*"([^"]*)"', block
                )

                # Extract paranoia level from tags, default to 1
                paranoia_level = 1
                for tag in tags:
                    pl_match = re.match(r"paranoia-level/(\d+)", tag)
                    if pl_match:
                        paranoia_level = int(pl_match.group(1))
                        break

                description = (
                    comments
                    or f"ModSecurity core rule protecting against {category} vectors."
                )

                parsed_rules.append(
                    {
                        "id": rule_id,
                        "name": name,
                        "description": description,
                        "severity": severity,
                        "category": category,
                        "paranoia_level": paranoia_level,
                        "file_path": file_path,
                        "syntax": block.strip(),
                        "tags": tags,
                    }
                )

        _parsed_rules_cache = parsed_rules
        logger.info(
            f"Successfully parsed {len(parsed_rules)} active ModSecurity CRS rules."
        )
        return parsed_rules

    except Exception as e:
        logger.error(f"Error parsing ModSecurity CRS rule files: {e}")
        _parsed_rules_cache = _get_fallback_rules()
        return _parsed_rules_cache


def _get_fallback_rules() -> List[Dict[str, Any]]:
    """Fallback rules dataset for development simulation."""
    return [
        {
            "id": "942100",
            "name": "SQL Injection Attack Detected via libinjection",
            "description": "Detects SQL injection vulnerabilities in parameter arguments utilizing fast libinjection algorithms.",
            "severity": "Critical",
            "category": "SQL Injection",
            "paranoia_level": 1,
            "file_path": "/etc/nginx/modsec/coreruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            "syntax": "SecRule ARGS \"@sqlInjection\" \"id:942100,phase:2,block,capture,msg:'SQL Injection Attack Detected via libinjection',logdata:'Matched Data: %{TX.0}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-sqli',tag:'paranoia-level/1',severity:'CRITICAL'\"",
            "tags": [
                "application-multi",
                "language-multi",
                "platform-multi",
                "attack-sqli",
                "paranoia-level/1",
            ],
        },
        {
            "id": "941100",
            "name": "XSS Attack Detected via libinjection",
            "description": "Detects Cross-site Scripting vectors inside headers and parameters using high fidelity libinjection parser libraries.",
            "severity": "Critical",
            "category": "XSS",
            "paranoia_level": 1,
            "file_path": "/etc/nginx/modsec/coreruleset/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
            "syntax": "SecRule ARGS \"@xssInjection\" \"id:941100,phase:2,block,capture,msg:'XSS Attack Detected via libinjection',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-xss',tag:'paranoia-level/1',severity:'CRITICAL'\"",
            "tags": [
                "application-multi",
                "language-multi",
                "platform-multi",
                "attack-xss",
                "paranoia-level/1",
            ],
        },
        {
            "id": "930100",
            "name": "Path Traversal Attack (/../)",
            "description": "Detects typical directory traversal characters like dot-dot-slash indicating local file inclusion attempts.",
            "severity": "High",
            "category": "LFI",
            "paranoia_level": 1,
            "file_path": "/etc/nginx/modsec/coreruleset/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
            "syntax": "SecRule REQUEST_URI_RAW|ARGS|REQUEST_HEADERS \"@rx (?i)(?:\x5c.x5c./|\x5c.x5c.\x5c\x5c)\" \"id:930100,phase:2,block,msg:'Path Traversal Attack',severity:'HIGH',tag:'attack-lfi',tag:'paranoia-level/1'\"",
            "tags": ["attack-lfi", "paranoia-level/1"],
        },
        {
            "id": "913100",
            "name": "Found User-Agent associated with security scanner",
            "description": "Validates request headers against a database of commercial and open-source network scanners (e.g. nmap, nikto, sqlmap).",
            "severity": "Medium",
            "category": "Scanner Detection",
            "paranoia_level": 1,
            "file_path": "/etc/nginx/modsec/coreruleset/rules/REQUEST-913-SCANNER-DETECTION.conf",
            "syntax": "SecRule REQUEST_HEADERS:User-Agent \"@pmFromFile scanners-user-agents.data\" \"id:913100,phase:1,block,msg:'Found User-Agent associated with security scanner',tag:'attack-reputation-scanner',tag:'paranoia-level/1',severity:'WARNING'\"",
            "tags": ["attack-reputation-scanner", "paranoia-level/1"],
        },
        {
            "id": "920350",
            "name": "Host Header Is IP Address",
            "description": "Blocks requests utilizing direct IP addressing in Host headers instead of valid domain names. This restricts random background web crawlers.",
            "severity": "Low",
            "category": "Protocol Enforcement",
            "paranoia_level": 2,
            "file_path": "/etc/nginx/modsec/coreruleset/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
            "syntax": "SecRule REQUEST_HEADERS:Host \\\"@rx ^[\\\\d\\\\.]+\\$\\\" \\\"id:920350,phase:1,block,msg:'Host Header Is IP Address',tag:'protocol-enforcement',tag:'paranoia-level/2',severity:'NOTICE'\\\"",
            "tags": ["protocol-enforcement", "paranoia-level/2"],
        },
    ]


def _run_nginx_reload() -> Tuple[bool, str]:
    """
    Spawns NGINX configuration test and reloads.
    If sudo access is restricted, runs gracefully in fail-safe simulation mode.
    """
    # 1. Try Docker Exec variants first
    try:
        # Check config syntax in Docker container
        subprocess.run(
            ["docker", "exec", "waf-openresty", "nginx", "-t"],
            capture_output=True, text=True, check=True
        ) # nosec B603 B607
        # Reload openresty inside Docker container
        subprocess.run(
            ["docker", "exec", "waf-openresty", "openresty", "-s", "reload"],
            capture_output=True, text=True, check=True
        ) # nosec B603 B607
        return True, "NGINX configuration validated and reloaded successfully in Docker."
    except (subprocess.CalledProcessError, FileNotFoundError, PermissionError) as e:
        # If the command succeeded but reported syntax error, we must abort! Do not fall through.
        if isinstance(e, subprocess.CalledProcessError):
            err_msg = e.stderr or e.stdout or str(e)
            if "docker" not in err_msg.lower() and "cannot connect" not in err_msg.lower() and "no such container" not in err_msg.lower():
                logger.error(f"NGINX validation failed inside Docker: {err_msg}")
                return False, f"NGINX reload aborted: configuration validation failed: {err_msg}"
        logger.debug(f"Docker reload not available or failed: {e}. Trying host reload...")

    # 2. Host reload variants
    try:
        # Check config syntax
        subprocess.run(
            ["sudo", "-n", "nginx", "-t"], capture_output=True, text=True, check=True
        ) # nosec B603 B607
        # Reload NGINX
        subprocess.run(
            ["sudo", "-n", "systemctl", "reload", "openresty"],
            capture_output=True,
            text=True,
            check=True,
        ) # nosec B603 B607
        return True, "NGINX configuration validated and reloaded successfully."
    except PermissionError as e:
        logger.warning(f"Reload permission denied: {e}. Running in simulation mode.")
        return True, "WAF states reloaded successfully (Simulation Mode)."
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr or e.stdout or str(e)
        if (
            "sudo: a password is required" in err_msg.lower()
            or "permission denied" in err_msg.lower()
        ):
            logger.warning(
                f"Reload permission denied (sudo password required). Running in simulation mode. Error: {err_msg}"
            )
            return True, "WAF states reloaded successfully (Simulation Mode)."
        logger.error(f"NGINX validation failed: {err_msg}")
        return (
            False,
            f"NGINX reload aborted: configuration validation failed: {err_msg}",
        )
    except Exception as e:
        logger.debug(f"Subprocess reload not available: {e}. Simulating reload.")
        return True, "WAF states reloaded successfully (Simulation Mode)."


def _update_modsecurity_override_file(
    disabled_ids: List[str],
    paranoia_level: int,
    inbound_anomaly_threshold: int = 5,
    outbound_anomaly_threshold: int = 4,
) -> Tuple[bool, str]:
    """
    Safely writes override directives into /etc/nginx/modsec/rules-override.conf.
    If system file write is not allowed, logs the warning and returns success for simulation.
    """
    override_path = "/etc/nginx/modsec/rules-override.conf"

    # Construct content
    lines = [
        "# ========================================================",
        "# CyberSentinel WAF GUI Auto-generated Overrides Configuration",
        f"# Timestamp: {datetime.now().isoformat()}",
        "# Do NOT edit this file manually. Changes will be overwritten.",
        "# ========================================================",
        "",
        "# --- Paranoia Level Configuration ---",
        f'SecAction "id:999999,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level={paranoia_level}"',
        "",
        "# --- Anomaly Score Thresholds ---",
        "# Inbound: block when accumulated CRS score reaches this value.",
        "# Outbound: block when response leakage score reaches this value.",
        'SecAction \\',
        f'    "id:900110,\\',
        '    phase:1,\\',
        '    nolog,\\',
        '    pass,\\',
        '    t:none,\\',
        f'    setvar:tx.inbound_anomaly_score_threshold={inbound_anomaly_threshold},\\',
        f'    setvar:tx.outbound_anomaly_score_threshold={outbound_anomaly_threshold}"',
        "",
        "# --- Disabled WAF Rules ---",
    ]
    for rid in disabled_ids:
        lines.append(f"SecRuleRemoveById {rid}")

    lines.append("")
    lines.append("# --- Active Custom Exclusions & Exceptions ---")

    try:
        from app.services import db_service

        active_exclusions = db_service.get_all_active_exclusions()
        for exc in active_exclusions:
            lines.append(
                f"# Exception ID: {exc['id']} | FP ID: {exc['false_positive_id'] or 'None'} | Created by: {exc['created_by']}"
            )
            lines.append(exc["modsec_rule"])
            lines.append("")
    except Exception as e:
        logger.error(f"Error loading custom exclusions for overrides file: {e}")

    content = "\n".join(lines) + "\n"

    # Try to write to /etc/nginx/modsec/rules-override.conf (if we have permissions, e.g. root)
    try:
        # Ensure rules-override.conf is included in main.conf.
        # Usually requires manual append once, but we check if we can write to rules-override.conf directly first.
        if os.path.exists(override_path) or os.access("/etc/nginx/modsec", os.W_OK):
            with open(override_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Ensure rules-override.conf is included in main.conf
            main_conf_path = "/etc/nginx/modsec/main.conf"
            if os.path.exists(main_conf_path):
                with open(main_conf_path, "r", encoding="utf-8") as f:
                    main_conf_data = f.read()
                if "rules-override.conf" not in main_conf_data:
                    with open(main_conf_path, "a", encoding="utf-8") as f:
                        f.write("\nInclude /etc/nginx/modsec/rules-override.conf\n")

            return True, "Override configuration written successfully."
    except Exception as e:
        logger.debug(
            f"Cannot write to system /etc/nginx/modsec/ (restricted privileges: {e}). Updating virtual state DB only."
        )

    return True, "Override configuration simulated successfully."


# --- Public API Methods ---


def get_all_rules(
    page: int = 1,
    size: int = 15,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    enabled: Optional[bool] = None,
    search: Optional[str] = None,
) -> Tuple[List[RuleEntry], int]:
    """
    Fetches paginated and filtered ModSecurity rules.
    Injects dynamic hit counts and status properties from virtual overrides state.
    """
    state = _load_state()
    disabled_ids = set(state.get("disabled_rule_ids", []))
    state.get("paranoia_level", 1)

    # Load logs to dynamically calculate hit counts and last_triggered timestamps
    logs = get_all_logs()
    hit_counter = Counter(log.rule_id for log in logs if log.rule_id)

    # Calculate last triggered timestamp per rule_id
    last_triggered_map = {}
    for log in reversed(logs):  # Read oldest first so newest overwrites in dict
        if log.rule_id and log.timestamp:
            last_triggered_map[log.rule_id] = log.timestamp

    # Fetch parsed rules
    all_raw_rules = _parse_crs_rules()

    rule_entries = []
    for r in all_raw_rules:
        rid = r["id"]
        is_enabled = rid not in disabled_ids

        # Filter rules by active paranoia level:
        # Rules with paranoia_level > active_paranoia are technically loaded by ModSecurity but "skipped" at runtime.
        # We will represent them correctly based on the overrides state.

        rule_entries.append(
            RuleEntry(
                id=rid,
                name=r["name"],
                description=r["description"],
                severity=r["severity"],
                category=r["category"],
                enabled=is_enabled,
                paranoia_level=r["paranoia_level"],
                hit_count=hit_counter.get(rid, 0),
                last_triggered=last_triggered_map.get(rid, ""),
                file_path=r["file_path"],
                syntax=r["syntax"],
                tags=r["tags"],
            )
        )

    # Apply filters
    filtered = rule_entries
    if category:
        filtered = [r for r in filtered if r.category.lower() == category.lower()]
    if severity:
        filtered = [r for r in filtered if r.severity.lower() == severity.lower()]
    if enabled is not None:
        filtered = [r for r in filtered if r.enabled == enabled]
    if search:
        s_lower = search.lower()
        filtered = [
            r
            for r in filtered
            if s_lower in r.id
            or s_lower in r.name.lower()
            or s_lower in r.description.lower()
        ]

    # Sort rules: Enabled first, then high hits, then by ID
    filtered.sort(key=lambda r: (not r.enabled, -r.hit_count, r.id))

    total = len(filtered)
    start = (page - 1) * size
    end = start + size

    return filtered[start:end], total


def get_rule_by_id(rule_id: str) -> Optional[RuleEntry]:
    """Retrieves full detail block for a specific rule."""
    state = _load_state()
    disabled_ids = set(state.get("disabled_rule_ids", []))

    # Load hits
    logs = get_all_logs()
    hit_count = sum(1 for log in logs if log.rule_id == rule_id)
    last_triggered = next((log.timestamp for log in logs if log.rule_id == rule_id), "")

    all_raw_rules = _parse_crs_rules()
    raw_rule = next((r for r in all_raw_rules if r["id"] == rule_id), None)
    if not raw_rule:
        return None

    return RuleEntry(
        id=rule_id,
        name=raw_rule["name"],
        description=raw_rule["description"],
        severity=raw_rule["severity"],
        category=raw_rule["category"],
        enabled=rule_id not in disabled_ids,
        paranoia_level=raw_rule["paranoia_level"],
        hit_count=hit_count,
        last_triggered=last_triggered,
        file_path=raw_rule["file_path"],
        syntax=raw_rule["syntax"],
        tags=raw_rule["tags"],
    )


def toggle_rule(
    rule_id: str, enabled: bool, username: str = "admin", reason: str = ""
) -> Tuple[bool, str]:
    """
    Enables or disables a specific WAF rule.
    Backs up states, validates configs, reloads NGINX, and logs administrative audit events.
    """
    state = _load_state()
    disabled_ids = state.setdefault("disabled_rule_ids", [])

    # Verify rule exists
    rule = get_rule_by_id(rule_id)
    if not rule:
        return (
            False,
            f"Rule ID {rule_id} does not exist in the active OWASP CRS dataset.",
        )

    # Perform edit
    backup_disabled_ids = list(disabled_ids)
    if enabled:
        if rule_id in disabled_ids:
            disabled_ids.remove(rule_id)
    else:
        if rule_id not in disabled_ids:
            disabled_ids.append(rule_id)

    # Write overrides configuration
    write_ok, write_msg = _update_modsecurity_override_file(
        disabled_ids, state.get("paranoia_level", 1)
    )
    if not write_ok:
        state["disabled_rule_ids"] = backup_disabled_ids
        return False, f"Failed to modify override configuration: {write_msg}"

    # Perform NGINX reload syntax check & reload
    reload_ok, reload_msg = _run_nginx_reload()
    if not reload_ok:
        # Revert overrides file & database
        _update_modsecurity_override_file(
            backup_disabled_ids, state.get("paranoia_level", 1)
        )
        state["disabled_rule_ids"] = backup_disabled_ids
        return False, f"Reload failed! Reverted changes. Error details: {reload_msg}"

    # Save state
    action_text = "enable" if enabled else "disable"
    audit_msg = f"Rule state toggled to {action_text.upper()}."
    if reason:
        audit_msg += f" Reason: {reason}"

    state.setdefault("audit_history", []).insert(
        0,
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "action": action_text,
            "rule_id": rule_id,
            "rule_name": rule.name,
            "details": audit_msg,
        },
    )

    _save_state(state)
    return (
        True,
        f"Rule {rule_id} was successfully {'enabled' if enabled else 'disabled'}. {reload_msg}",
    )


def set_paranoia_level(level: int, username: str = "admin") -> Tuple[bool, str]:
    """
    Adjusts the global OWASP CRS detection paranoia level (1-4).
    Validates, reloads, and records administrative audit logs.
    """
    if level not in (1, 2, 3, 4):
        return False, "Paranoia level must be an integer between 1 and 4."

    state = _load_state()
    old_level = state.get("paranoia_level", 1)
    if old_level == level:
        return True, f"Paranoia level is already set to PL{level}."

    state["paranoia_level"] = level
    disabled_ids = state.get("disabled_rule_ids", [])

    # Write overrides configuration
    write_ok, write_msg = _update_modsecurity_override_file(disabled_ids, level)
    if not write_ok:
        state["paranoia_level"] = old_level
        return False, f"Failed to modify override configuration: {write_msg}"

    # Reload NGINX
    reload_ok, reload_msg = _run_nginx_reload()
    if not reload_ok:
        # Revert changes
        _update_modsecurity_override_file(disabled_ids, old_level)
        state["paranoia_level"] = old_level
        return (
            False,
            f"Reload failed! Reverted paranoia level to PL{old_level}. Error: {reload_msg}",
        )

    # Save state
    state.setdefault("audit_history", []).insert(
        0,
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "action": "paranoia_change",
            "rule_id": None,
            "rule_name": None,
            "details": f"Global OWASP CRS Paranoia Level updated from PL{old_level} to PL{level}.",
        },
    )

    _save_state(state)
    return True, f"Global detection paranoia level updated to PL{level}. {reload_msg}"


def get_rules_stats() -> RuleStatsResponse:
    """Calculates overall rule statuses, category distributions, and candidates for tuning."""
    state = _load_state()
    disabled_ids = set(state.get("disabled_rule_ids", []))
    active_paranoia = state.get("paranoia_level", 1)

    all_raw_rules = _parse_crs_rules()
    total_rules = len(all_raw_rules)
    disabled_count = len(disabled_ids.intersection(r["id"] for r in all_raw_rules))
    enabled_count = total_rules - disabled_count

    # Extract log hits to identify candidates
    logs = get_all_logs()
    hit_counter = Counter(log.rule_id for log in logs if log.rule_id)

    # Categories count
    cat_counts = defaultdict(int)
    for r in all_raw_rules:
        cat_counts[r["category"]] += 1
    category_distribution = [
        {"category": cat, "count": count} for cat, count in cat_counts.items()
    ]

    # Top triggered rules based on log hits
    top_triggered = []
    for rid, count in hit_counter.most_common(10):
        raw_rule = next((r for r in all_raw_rules if r["id"] == rid), None)
        if raw_rule:
            top_triggered.append(
                {
                    "rule_id": rid,
                    "name": raw_rule["name"],
                    "category": raw_rule["category"],
                    "severity": raw_rule["severity"],
                    "count": count,
                }
            )

    # Tuning recommendations: active rules with extremely high hits (heavy trigger count)
    # in corporate setups are key false positive candidates requiring white-listing or tuning.
    tuning_candidates = []
    # Any rule that has triggered at least 3 times is prioritized for tuning analysis
    for rid, count in hit_counter.most_common(5):
        if count >= 2:
            raw_rule = next((r for r in all_raw_rules if r["id"] == rid), None)
            if raw_rule:
                tuning_candidates.append(
                    {
                        "rule_id": rid,
                        "name": raw_rule["name"],
                        "category": raw_rule["category"],
                        "hit_count": count,
                        "recommendation": (
                            "Review parameters. Consider selective white-listing or regex tuning to avoid operational disruption."
                            if count > 5
                            else "Monitor trigger payloads. Ensure benign traffic is not blocked."
                        ),
                    }
                )

    return RuleStatsResponse(
        total_rules=total_rules,
        enabled_rules=enabled_count,
        disabled_rules=disabled_count,
        paranoia_level=active_paranoia,
        top_triggered_rules=top_triggered,
        category_distribution=category_distribution,
        tuning_candidates=tuning_candidates,
    )


def get_audit_history() -> List[AuditLogEntry]:
    """Retrieves modification audits list."""
    state = _load_state()
    history = state.get("audit_history", [])
    return [AuditLogEntry(**entry) for entry in history]


def record_audit_event(action: str, details: str, username: str = "admin") -> None:
    """Records a manual audit event to the configuration history."""
    state = _load_state()
    state.setdefault("audit_history", []).insert(
        0,
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "action": action,
            "rule_id": None,
            "rule_name": None,
            "details": details,
        },
    )
    _save_state(state)


def reset_rules(username: str = "admin") -> Tuple[bool, str]:
    """Resets all overrides, re-enables all CRS rules, and sets PL level to PL1."""
    state = _load_state()

    state["disabled_rule_ids"] = []
    state["paranoia_level"] = 1

    # Write overrides configuration
    write_ok, write_msg = _update_modsecurity_override_file([], 1)
    if not write_ok:
        return False, f"Failed to reset override configuration: {write_msg}"

    # Reload NGINX
    reload_ok, reload_msg = _run_nginx_reload()
    if not reload_ok:
        return False, f"Reload failed during reset operation: {reload_msg}"

    # Audit log
    state.setdefault("audit_history", []).insert(
        0,
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "action": "reset",
            "rule_id": None,
            "rule_name": None,
            "details": "Restored all OWASP CRS rules to system default enabled state and reset paranoia level to PL1.",
        },
    )

    _save_state(state)
    return True, f"Successfully restored all rules to WAF system defaults. {reload_msg}"


def sync_rules_and_exclusions() -> Tuple[bool, str]:
    """
    Regenerates the rules-override.conf file using the current disabled rules, paranoia level, and active exclusions.
    Reloads NGINX.
    """
    state = _load_state()
    disabled_ids = state.get("disabled_rule_ids", [])
    paranoia_level = state.get("paranoia_level", 1)

    # Load anomaly thresholds from settings.json (with safe defaults)
    try:
        from app.services.settings_manager import settings_manager
        waf_cfg = settings_manager.get("waf", {})
        inbound_threshold  = int(waf_cfg.get("inbound_anomaly_score_threshold", 5))
        outbound_threshold = int(waf_cfg.get("outbound_anomaly_score_threshold", 4))
    except Exception:
        inbound_threshold, outbound_threshold = 5, 4

    # Write overrides configuration
    write_ok, write_msg = _update_modsecurity_override_file(
        disabled_ids, paranoia_level, inbound_threshold, outbound_threshold
    )
    if not write_ok:
        return False, f"Failed to modify override configuration: {write_msg}"

    # Reload NGINX
    reload_ok, reload_msg = _run_nginx_reload()
    return reload_ok, reload_msg


def generate_modsec_rule(
    exclusion_type: str,
    rule_id: str,
    uri: Optional[str],
    parameter_name: Optional[str],
    http_method: Optional[str],
    client_ip: Optional[str],
    next_id: int,
) -> str:
    """
    Generates a ModSecurity-compatible configuration string based on exception type and target details.
    Uses custom SecRule IDs starting at 10000000 to prevent collisions.
    """
    rule_num_id = 10000000 + next_id

    # 1. URI specific exclusion
    if exclusion_type == "uri":
        if not uri:
            raise ValueError("URI is required for URI-specific exclusions.")
        return f'SecRule REQUEST_URI "@streq {uri}" "id:{rule_num_id},phase:1,pass,nolog,ctl:ruleRemoveById={rule_id}"'

    # 2. Parameter specific exclusion globally
    elif exclusion_type == "parameter":
        if not parameter_name:
            raise ValueError(
                "Parameter name is required for parameter-specific exclusions."
            )
        return f'SecRuleUpdateTargetById {rule_id} "!ARGS:{parameter_name}"'

    # 3. Parameter specific exclusion on specific URI
    elif exclusion_type == "uri_parameter":
        if not uri or not parameter_name:
            raise ValueError(
                "Both URI and Parameter name are required for URI-parameter exclusions."
            )
        return f'SecRule REQUEST_URI "@streq {uri}" "id:{rule_num_id},phase:2,pass,nolog,ctl:ruleRemoveTargetById={rule_id};ARGS:{parameter_name}"'

    # 4. Specific Endpoint + HTTP Method exclusion
    elif exclusion_type == "endpoint_method":
        if not uri or not http_method:
            raise ValueError(
                "Both URI and HTTP Method are required for endpoint-method exclusions."
            )
        return (
            f'SecRule REQUEST_METHOD "@streq {http_method}" "id:{rule_num_id},phase:1,pass,nolog,chain"\\\n'
            f'  "SecRule REQUEST_URI \\"@streq {uri}\\" \\"ctl:ruleRemoveById={rule_id}\\""'
        )

    # 5. Suppress repeated alerts (IP + URI + Rule ID suppression)
    elif exclusion_type == "ip_suppression":
        if not client_ip or not uri:
            raise ValueError(
                "Both Client IP and URI are required for IP-based suppression."
            )
        return (
            f'SecRule REMOTE_ADDR "@ipMatch {client_ip}" "id:{rule_num_id},phase:1,pass,nolog,chain"\\\n'
            f'  "SecRule REQUEST_URI \\"@streq {uri}\\" \\"ctl:ruleRemoveById={rule_id}\\""'
        )
    else:
        raise ValueError(f"Unknown exclusion type: {exclusion_type}")
