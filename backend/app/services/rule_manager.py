import os
import re
import glob
import json
import asyncio
import logging
import subprocess
import tempfile
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional, Tuple
from app.models.rule_model import RuleEntry, AuditLogEntry, RuleStatsResponse
from app.services.log_reader import get_all_logs

logger = logging.getLogger(__name__)

# Default bounded-window auto-rollout settings (see evaluate_canary_rollout).
# Conservative on purpose: auto-rollback defaults ON (it can only ever
# *disable* a rule that real traffic evidence says is FP-prone, using the
# same toggle_rule() path a human would use — a safety net, not a risk).
# auto-promote defaults OFF (it only clears bookkeeping, never touches
# enforcement, but per the architecture review's own recommendation this
# should stay opt-in "only once the FP-proxy metric is trusted").
DEFAULT_CANARY_SETTINGS = {
    "auto_promote_enabled": False,
    "auto_rollback_enabled": True,
    "window_hours": 72,
    "min_sample_size": 20,
    # sole_match_count / total_matches over the window. Low = well-
    # corroborated by other rules on the same requests (looks like real
    # attack traffic); high = this rule is often the SOLE reason a request
    # got blocked, with no corroboration — the FP-proxy signal.
    "promote_max_sole_match_rate": 0.30,
    "rollback_min_sole_match_rate": 0.70,
}

CANARY_ROLLOUT_CHECK_INTERVAL_SECONDS = 6 * 3600

# Paths
# CRS_RULES_DIR override exists for CI/bare-checkout test runs: in a real
# deployment this is always /etc/nginx/... (the container's bind-mounted
# path — see docker-compose.yml), but a GitHub Actions runner has no such
# path at all, only whatever actions/checkout put at $GITHUB_WORKSPACE.
# Without this, test_rule_canary.py's real-CRS-rule-id tests silently fall
# back to the small hardcoded sample set (see _parse_crs_rules below) and
# fail on "Rule ID ... does not exist in the active OWASP CRS dataset."
RULES_DIR = os.environ.get("CRS_RULES_DIR", "/etc/nginx/modsec/coreruleset/rules")
STATE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "rule_states.json"
)

# CyberSentinel policy: REST method enforcement (911100) is permanently
# removed so DELETE/PUT/PATCH requests to REST APIs aren't blocked by
# default. This is baked into every generated override file regardless of
# the DB's disabled_rule_ids, so get_all_rules/get_rule_by_id/toggle_rule
# must report it consistently — otherwise the dashboard can show "Enabled"
# (and even report a successful "enable" toggle) for a rule that is never
# actually enforced.
PERMANENTLY_DISABLED_RULE_IDS = {"911100"}

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
        "canary_rule_ids": [],
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
            ["docker", "exec", "waf-openresty", "nginx", "-c", "/etc/nginx/nginx.conf", "-t"],
            capture_output=True, text=True, check=True
        ) # nosec B603 B607
        # Reload openresty inside Docker container
        subprocess.run(
            ["docker", "exec", "waf-openresty", "openresty", "-c", "/etc/nginx/nginx.conf", "-s", "reload"],
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
            ["sudo", "-n", "nginx", "-c", "/etc/nginx/nginx.conf", "-t"], capture_output=True, text=True, check=True
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
        logger.error(f"Reload permission denied: {e}. Neither Docker exec nor host reload succeeded.")
        return False, (
            "NGINX reload failed: no working reload path available "
            f"(Docker exec unavailable, host reload permission denied: {e})."
        )
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr or e.stdout or str(e)
        if (
            "sudo: a password is required" in err_msg.lower()
            or "permission denied" in err_msg.lower()
        ):
            logger.error(
                f"Reload permission denied (sudo password required) and Docker exec unavailable. Error: {err_msg}"
            )
            return False, (
                "NGINX reload failed: no working reload path available "
                f"(Docker exec unavailable, host reload requires a password: {err_msg})."
            )
        logger.error(f"NGINX validation failed: {err_msg}")
        return (
            False,
            f"NGINX reload aborted: configuration validation failed: {err_msg}",
        )
    except Exception as e:
        logger.error(f"Subprocess reload not available: {e}. No reload was performed.")
        return False, f"NGINX reload failed: no working reload path available ({e})."


def _update_modsecurity_override_file(
    disabled_ids: List[str],
    paranoia_level: int,
    inbound_anomaly_threshold: int = 5,
    outbound_anomaly_threshold: int = 4,
) -> Tuple[bool, str]:
    """
    Writes override directives into /etc/nginx/modsec/rules-override.conf.
    Returns (False, reason) whenever the write genuinely fails — callers rely on
    this to decide whether to roll back and whether to tell the admin their
    change was NOT applied, so this must never report success on a failed write.
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
    lines.append("# --- Always allow REST HTTP methods (DELETE, PUT, PATCH) ---")
    lines.append("SecRuleRemoveById 911100")
    lines.append("")

    for rid in disabled_ids:
        # Prevent duplicate rules
        if str(rid) != "911100":
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

    # Write atomically (temp file + rename on the same filesystem) so a crash
    # mid-write can never leave a truncated/corrupt override file on disk.
    try:
        override_dir = os.path.dirname(override_path)
        os.makedirs(override_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=override_dir, prefix=".rules-override-", suffix=".tmp")
        try:
            # mkstemp() defaults to mode 0600; restore the normal world-readable
            # mode before the rename so OpenResty/other tooling can still read
            # this file same as any other config in the directory.
            os.chmod(tmp_path, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp_path, override_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

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
        # This must NOT report success — callers (toggle_rule, set_paranoia_level,
        # reset_rules, sync_rules_and_exclusions) trust this return value as proof
        # the WAF was actually updated, and revert their in-memory/DB state when
        # it's False. Silently returning True here (as this used to do) meant a
        # permission error or read-only mount could make the dashboard report a
        # rule as toggled while ModSecurity kept enforcing the old state.
        logger.error(
            f"Failed to write ModSecurity override file at {override_path}: {e}"
        )
        return False, f"Could not write WAF override configuration to disk: {e}"


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
    canary_ids = set(state.get("canary_rule_ids", []))
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
        is_enabled = rid not in disabled_ids and rid not in PERMANENTLY_DISABLED_RULE_IDS

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
                is_canary=rid in canary_ids,
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
    canary_ids = set(state.get("canary_rule_ids", []))

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
        enabled=rule_id not in disabled_ids and rule_id not in PERMANENTLY_DISABLED_RULE_IDS,
        paranoia_level=raw_rule["paranoia_level"],
        hit_count=hit_count,
        last_triggered=last_triggered,
        file_path=raw_rule["file_path"],
        syntax=raw_rule["syntax"],
        tags=raw_rule["tags"],
        is_canary=rule_id in canary_ids,
    )


def mark_rule_canary(rule_id: str, canary: bool, username: str = "admin") -> Tuple[bool, str]:
    """
    Flags/unflags a rule as under canary review. Pure bookkeeping — no
    override-file write or NGINX reload — because it doesn't change
    enforcement at all.

    Why not a real live shadow/log-only mode per rule: this deployment runs
    CRS in standard anomaly-scoring mode (SecDefaultAction "phase:1/2,log,
    auditlog,pass" — see modsecurity.conf), so individual CRS rules already
    never block by themselves; only the cumulative-score check in
    REQUEST-949-BLOCKING-EVALUATION.conf does. There's no safe way to make
    one rule ID "log-only" without either hacking a per-rule score-exclusion
    into that hot-path scoring chain (exactly the kind of ModSecurity-core
    change this project treats as highest-risk, see project memory on the
    crs_score fix) or just fully disabling it (which is the existing
    enable/disable feature, not this one).

    So "canary" here means "flagged for review" — see get_rule_canary_report
    for the actual measurement, built from already-collected historical
    waf_events instead of a live experiment: for each of this rule's past
    matches, was it the ONLY rule that fired (disabling it would have let
    that request through unblocked) or did another rule also fire (still
    safe if this one goes away)? That's a direct, real-traffic answer to
    "would disabling this rule open a hole", without touching the hot path.

    Flagging also starts a bounded monitoring window (canary_meta.started_at)
    — see evaluate_canary_rollout(), which periodically re-runs this same
    sole-match measurement over that window and can auto-promote (clear this
    flag) or auto-rollback (toggle_rule to actually disable, real traffic
    evidence permitting) instead of leaving the report purely human-read.
    """
    state = _load_state()
    canary_ids = state.setdefault("canary_rule_ids", [])
    canary_meta = state.setdefault("canary_meta", {})

    rule = get_rule_by_id(rule_id)
    if not rule:
        return False, f"Rule ID {rule_id} does not exist in the active OWASP CRS dataset."

    if canary:
        if rule_id not in canary_ids:
            canary_ids.append(rule_id)
        # Preserve an existing window start if this rule was already
        # flagged (e.g. re-flagging after a "needs_review" outcome) rather
        # than resetting the clock every time.
        if rule_id not in canary_meta:
            canary_meta[rule_id] = {
                "started_at": datetime.now().isoformat(),
                "needs_review": False,
            }
    else:
        if rule_id in canary_ids:
            canary_ids.remove(rule_id)
        canary_meta.pop(rule_id, None)

    action_text = "canary_flag" if canary else "canary_unflag"
    state.setdefault("audit_history", []).insert(
        0,
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "action": action_text,
            "rule_id": rule_id,
            "rule_name": rule.name,
            "details": f"Rule {'flagged for' if canary else 'removed from'} canary review.",
        },
    )
    _save_state(state)
    return True, f"Rule {rule_id} {'flagged for' if canary else 'removed from'} canary review."


def get_canary_status(rule_id: str) -> Optional[Dict[str, Any]]:
    """Monitoring-window bookkeeping for a canary-flagged rule (started_at,
    elapsed/remaining hours, needs_review). Returns None if the rule isn't
    currently flagged."""
    state = _load_state()
    if rule_id not in state.get("canary_rule_ids", []):
        return None
    meta = state.get("canary_meta", {}).get(rule_id, {})
    started_at = meta.get("started_at")
    settings = get_canary_rollout_settings()
    elapsed_hours = None
    if started_at:
        try:
            elapsed_hours = (
                datetime.now() - datetime.fromisoformat(started_at)
            ).total_seconds() / 3600.0
        except ValueError:
            elapsed_hours = None
    return {
        "rule_id": rule_id,
        "started_at": started_at,
        "elapsed_hours": elapsed_hours,
        "window_hours": settings["window_hours"],
        "needs_review": bool(meta.get("needs_review", False)),
    }


def get_canary_rollout_settings() -> Dict[str, Any]:
    state = _load_state()
    saved = state.get("canary_rollout_settings", {})
    # Merge over defaults rather than replace outright, so a settings file
    # saved before a new field was added doesn't end up missing it.
    return {**DEFAULT_CANARY_SETTINGS, **saved}


def save_canary_rollout_settings(settings: Dict[str, Any], username: str = "admin") -> Tuple[bool, str]:
    state = _load_state()
    current = get_canary_rollout_settings()
    current.update({k: v for k, v in settings.items() if k in DEFAULT_CANARY_SETTINGS})
    state["canary_rollout_settings"] = current
    state.setdefault("audit_history", []).insert(
        0,
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "action": "canary_settings_update",
            "rule_id": None,
            "rule_name": None,
            "details": f"Canary auto-rollout settings updated: {current}",
        },
    )
    _save_state(state)
    return True, "Canary auto-rollout settings saved."


def evaluate_canary_rollout() -> Dict[str, List[str]]:
    """
    The scheduled job body (see start_canary_rollout_scheduler): re-measures
    every canary-flagged rule's sole-match rate over its bounded monitoring
    window (get_rule_canary_report — same query the human-read "Load 7-Day
    Impact Report" button already uses) and, per get_canary_rollout_settings,
    either:
      - auto-promotes it (clears the canary flag — bookkeeping only, CRS was
        never actually running it log-only, see mark_rule_canary's docstring
        for why there's no separate enforcement state to restore here);
      - auto-rolls it back (toggle_rule to really disable it — the one case
        this touches enforcement, using the exact same config-write/reload/
        rollback-on-failure path a human clicking "Disable" already goes
        through); or
      - leaves it monitoring, flagging needs_review once its window has
        fully elapsed without enough evidence either way.
    Insufficient sample size (min_sample_size) blocks any automated action
    regardless of settings — a handful of matches isn't enough evidence.
    """
    from app.services import clickhouse_service

    state = _load_state()
    canary_ids = list(state.get("canary_rule_ids", []))
    canary_meta = state.setdefault("canary_meta", {})
    settings = get_canary_rollout_settings()

    result = {"promoted": [], "rolled_back": [], "needs_review": [], "still_monitoring": []}

    for rule_id in canary_ids:
        meta = canary_meta.setdefault(
            rule_id, {"started_at": datetime.now().isoformat(), "needs_review": False}
        )
        started_at = meta.get("started_at")
        try:
            elapsed_hours = (
                (datetime.now() - datetime.fromisoformat(started_at)).total_seconds() / 3600.0
                if started_at else 0.0
            )
        except ValueError:
            elapsed_hours = 0.0

        report = clickhouse_service.get_rule_canary_report(rule_id, hours=settings["window_hours"])
        total = report["total_matches"]
        rate = (report["sole_match_count"] / total) if total else None

        if total < settings["min_sample_size"]:
            if elapsed_hours >= settings["window_hours"] and not meta.get("needs_review"):
                meta["needs_review"] = True
                _log_canary_audit(state, rule_id, "canary_needs_review",
                                   f"Monitoring window elapsed with insufficient traffic "
                                   f"({total} matches, need {settings['min_sample_size']}) to auto-decide.")
                result["needs_review"].append(rule_id)
            else:
                result["still_monitoring"].append(rule_id)
            continue

        if settings["auto_promote_enabled"] and rate <= settings["promote_max_sole_match_rate"]:
            rule = get_rule_by_id(rule_id)
            canary_ids_live = state.setdefault("canary_rule_ids", [])
            if rule_id in canary_ids_live:
                canary_ids_live.remove(rule_id)
            canary_meta.pop(rule_id, None)
            _log_canary_audit(
                state, rule_id, "canary_auto_promote",
                f"Auto-promoted: sole-match rate {rate:.0%} over {total} matches "
                f"(<= {settings['promote_max_sole_match_rate']:.0%} threshold).",
                rule_name=rule.name if rule else None,
            )
            result["promoted"].append(rule_id)
        elif settings["auto_rollback_enabled"] and rate >= settings["rollback_min_sole_match_rate"]:
            canary_ids_live = state.setdefault("canary_rule_ids", [])
            if rule_id in canary_ids_live:
                canary_ids_live.remove(rule_id)
            canary_meta.pop(rule_id, None)
            _save_state(state)  # persist canary-tracking removal before toggle_rule's own load/save cycle
            toggle_rule(
                rule_id, enabled=False, username="system (canary auto-rollback)",
                reason=f"Auto-rollback: sole-match rate {rate:.0%} over {total} matches "
                       f"(>= {settings['rollback_min_sole_match_rate']:.0%} threshold) — "
                       f"likely a false-positive-prone rule."
            )
            state = _load_state()  # toggle_rule already saved; re-read before the next loop iteration
            canary_meta = state.setdefault("canary_meta", {})
            result["rolled_back"].append(rule_id)
            continue
        elif elapsed_hours >= settings["window_hours"] and not meta.get("needs_review"):
            meta["needs_review"] = True
            _log_canary_audit(state, rule_id, "canary_needs_review",
                               f"Monitoring window elapsed: sole-match rate {rate:.0%} over {total} matches "
                               f"is in the ambiguous zone — needs human review.")
            result["needs_review"].append(rule_id)
        else:
            result["still_monitoring"].append(rule_id)

    _save_state(state)
    return result


def _log_canary_audit(state: dict, rule_id: str, action: str, details: str, rule_name: str = None) -> None:
    state.setdefault("audit_history", []).insert(
        0,
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": "system",
            "action": action,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "details": details,
        },
    )


async def start_canary_rollout_scheduler():
    """
    Background loop, same shape as auto_learning's scheduler: an initial
    settle delay, then run-then-sleep every
    CANARY_ROLLOUT_CHECK_INTERVAL_SECONDS. Runs unconditionally — per-rule
    auto_promote/auto_rollback gating happens inside evaluate_canary_rollout
    itself via settings, so toggling those doesn't need a restart to take
    effect on the next cycle.
    """
    logger.info(
        f"Canary auto-rollout scheduler started. Runs every "
        f"{CANARY_ROLLOUT_CHECK_INTERVAL_SECONDS // 3600}h."
    )
    await asyncio.sleep(90)  # Initial delay for app to fully initialize

    from app.services import heartbeat_registry

    while True:
        try:
            result = evaluate_canary_rollout()
            if any(result.values()):
                logger.info(f"Canary auto-rollout cycle result: {result}")
            heartbeat_registry.record_heartbeat(
                "canary_rollout", CANARY_ROLLOUT_CHECK_INTERVAL_SECONDS, status="ok"
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Canary auto-rollout scheduler encountered an error: {e}")
            heartbeat_registry.record_heartbeat(
                "canary_rollout", CANARY_ROLLOUT_CHECK_INTERVAL_SECONDS, status="error", detail=str(e)
            )
        await asyncio.sleep(CANARY_ROLLOUT_CHECK_INTERVAL_SECONDS)


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

    if enabled and rule_id in PERMANENTLY_DISABLED_RULE_IDS:
        return (
            False,
            f"Rule {rule_id} is permanently disabled by CyberSentinel policy "
            "(REST method enforcement is removed so DELETE/PUT/PATCH requests "
            "to REST APIs aren't blocked) and cannot be re-enabled here.",
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


# CRS's audit "match" string looks like:
#   Matched "Operator `Rx' with parameter `...' against variable `ARGS:view' (Value: `...' )"
# and always wraps the matched variable in backticks. This is a stable format
# across CRS versions (it's produced by ModSecurity core's own logging, not
# CRS rule authors), unlike rule messages themselves which vary rule-to-rule.
_MATCHED_VAR_RE = re.compile(r"variable `([A-Za-z_]+)(?::([^`]+))?`")


def suggest_exclusion(raw_log: Optional[Dict[str, Any]], rule_id: str, uri: Optional[str]) -> Dict[str, Any]:
    """
    Best-effort suggestion for which exclusion_type/parameter_name an analyst
    should pick when turning a false positive into an exclusion. Purely a
    prefill for the CreateExceptionModal — never applied automatically, and
    it only ever narrows down among the SAME pass-type exclusion_type choices
    already presented in the UI, so it has zero effect on ModSecurity's
    blocking behavior, the CRS ruleset, or the ML model's scoring/labeling
    pipeline (which don't consult this at all).

    Returns {"exclusion_type", "parameter_name", "confidence", "reasoning"}.
    """
    fallback = {
        "exclusion_type": "uri",
        "parameter_name": None,
        "confidence": "low",
        "reasoning": "No matched-variable detail found in the captured log for this "
                     "rule — defaulting to a URI-scoped exclusion. Review carefully "
                     "before applying.",
    }

    if not raw_log or not uri:
        return fallback

    messages = (
        raw_log.get("transaction", {}).get("messages", [])
        if isinstance(raw_log, dict) else []
    )

    matched_var, matched_name = None, None
    for m in messages:
        details = m.get("details", {}) if isinstance(m, dict) else {}
        if str(details.get("ruleId", "")) != str(rule_id):
            continue
        match_str = details.get("match", "") or details.get("data", "")
        found = _MATCHED_VAR_RE.search(match_str)
        if found:
            matched_var, matched_name = found.group(1), found.group(2)
            break

    if matched_var is None:
        return fallback

    is_root_uri = uri.strip() in ("", "/")

    if matched_var in ("ARGS", "ARGS_GET", "ARGS_POST") and matched_name:
        if not is_root_uri:
            return {
                "exclusion_type": "uri_parameter",
                "parameter_name": matched_name,
                "confidence": "high",
                "reasoning": f"CRS matched rule {rule_id} against parameter "
                             f"'{matched_name}' on this specific URI — scoping the "
                             f"exclusion to this parameter+URI pair is narrower and "
                             f"safer than removing the rule globally.",
            }
        return {
            "exclusion_type": "parameter",
            "parameter_name": matched_name,
            "confidence": "medium",
            "reasoning": f"CRS matched rule {rule_id} against parameter "
                         f"'{matched_name}', but no specific endpoint URI was "
                         f"captured — falling back to a global parameter exclusion. "
                         f"Confirm this parameter is safe on every endpoint.",
        }

    if matched_var == "REQUEST_URI" or (matched_var.startswith("ARGS") and not matched_name):
        return {
            "exclusion_type": "uri",
            "parameter_name": None,
            "confidence": "high",
            "reasoning": f"CRS matched rule {rule_id} against the request URI/path "
                         f"itself rather than a specific parameter — a URI-scoped "
                         f"exclusion is the correct match.",
        }

    # Headers, cookies, request body, etc. have no dedicated exclusion_type in
    # this schema — URI scoping is the closest safe option, but flagged low
    # confidence since it's broader than the actual match.
    return {
        "exclusion_type": "uri",
        "parameter_name": None,
        "confidence": "low",
        "reasoning": f"CRS matched rule {rule_id} against {matched_var}"
                     f"{(':' + matched_name) if matched_name else ''}, which has no "
                     f"dedicated exclusion scope in this system — defaulting to a "
                     f"URI-scoped exclusion. Review carefully before applying.",
    }


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
