import os
import re
import subprocess
import tempfile
import ipaddress
import logging
import redis

logger = logging.getLogger(__name__)

DDOS_CONF_PATH = "/etc/nginx/conf.d/waf_ddos.conf"
HARDENING_CONF_PATH = "/etc/nginx/conf.d/waf_hardening.conf"
# NOT Included globally from modsec/main.conf (that applies to every server
# block, including the WAF GUI's own dashboard on port 3020 — confirmed via
# nginx.conf's `modsecurity_rules_file /etc/nginx/modsec/main.conf;` at the
# http{} level). Instead, sync_protected_apps_to_nginx() references this
# file with a per-server-block `modsecurity_rules_file` directive inside
# each PROTECTED APP's own generated server{} block only — the same scoping
# pattern already used by the dashboard's own vhost
# (configs/nginx/sites-available/cybersentinel) for its CRS exclusions.
# This is what keeps a Positive Security policy from ever applying to the
# dashboard's own admin traffic, without needing any URI-prefix guessing.
POSITIVE_SECURITY_CONF_PATH = "/etc/nginx/modsec/positive-security.conf"

# Per-protected-app require-auth (Phase 3) rule files. One file per app
# (not a shared global one) since each app can configure its own header/
# cookie name — same modsecurity_rules_file-per-server-block scoping as
# POSITIVE_SECURITY_CONF_PATH above, just app-specific instead of shared.
APP_AUTH_CONF_DIR = "/etc/nginx/modsec/app-auth"

# Admin-configurable "WAF blocked you" page (Settings > Custom Response).
# Referenced by an `internal` location added to every protected app's own
# generated server{} block (see sync_protected_apps_to_nginx()) — never the
# dashboard's own vhost, same per-server-block scoping as
# POSITIVE_SECURITY_CONF_PATH/APP_AUTH_CONF_DIR above.
CUSTOM_RESPONSE_PAGE_PATH = "/etc/nginx/custom_pages/waf_block.html"

REDIS_SECRET_FILE = "/etc/cybersentinel/redis.secret"  # nosec B105


def _get_redis_password() -> str:
    """
    Reads the Redis authentication password from a protected secret file.
    Falls back to empty string (no auth) if the file does not exist.
    """
    try:
        with open(REDIS_SECRET_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        logger.warning(
            f"Redis secret file not found at {REDIS_SECRET_FILE}. "
            "Connecting without authentication."
        )
        return ""
    except Exception as e:
        logger.error(f"Failed to read Redis secret file: {e}")
        return ""


def _sanitize_nginx_pattern(value: str) -> str:
    """
    Strips characters that would break NGINX map block structure or allow
    arbitrary directive injection via user-supplied rate limiting patterns.
    Removes: { } ; newlines and carriage returns.
    """
    return re.sub(r'[{};\'"\n\r]', '', value)


def _validate_ip_or_cidr(ip: str) -> bool:
    """
    Validates that a string is a valid IPv4/IPv6 address or CIDR network.
    Returns True if valid, False otherwise.
    """
    try:
        ipaddress.ip_network(ip.strip(), strict=False)
        return True
    except ValueError:
        return False


def _atomic_write(path: str, content: str) -> None:
    """
    Writes `content` to `path` via temp file + os.replace() so a crash or
    power loss mid-write can never leave a truncated/corrupt config file on
    disk — same pattern as rule_manager's override-file writer.
    """
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".nginxcfg-", suffix=".tmp")
    try:
        # mkstemp() creates the file at mode 0600 (owner read/write only) and
        # os.replace() carries that mode over — nginx configs need to stay
        # world-readable like the files they replace, or OpenResty running as
        # a different uid (or any non-root debugging/backup tooling on the
        # host) silently loses the ability to read its own config.
        os.chmod(tmp_path, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def write_and_apply_configs(file_contents: dict) -> tuple[bool, str]:
    """
    Writes one or more generated NGINX config files, validates the *full*
    config syntax with test_nginx_config(), and only reloads if it's valid —
    restoring every file to its prior state (or deleting it, if it didn't
    exist before) on failure.

    This matters because `nginx -s reload`'s exit code only reflects whether
    the running master process could be *signaled*, not whether it accepted
    the new config: nginx re-validates asynchronously inside the master
    after the reload command has already returned, so a caller that trusts
    reload_nginx()'s return value alone can silently believe a bad config
    was applied when nginx actually rejected it and kept running the old
    one. Callers should surface the returned message to the admin instead
    of a generic "failed" — it's the actual nginx config test output.
    """
    backups = {}
    try:
        for path, content in file_contents.items():
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    backups[path] = f.read()
            else:
                backups[path] = None
            _atomic_write(path, content)
    except Exception as e:
        logger.error(f"Failed to write NGINX config file(s): {e}")
        return False, f"Failed to write configuration file(s): {e}"

    valid, err_msg = test_nginx_config()
    if not valid:
        for path, old_content in backups.items():
            try:
                if old_content is None:
                    if os.path.exists(path):
                        os.remove(path)
                else:
                    _atomic_write(path, old_content)
            except Exception as restore_err:
                logger.error(f"Failed to restore {path} after invalid config: {restore_err}")
        logger.error(f"NGINX config validation failed, changes rolled back: {err_msg}")
        return False, f"NGINX configuration validation failed (changes rolled back): {err_msg}"

    if not reload_nginx():
        return False, "NGINX configuration is valid but the reload command failed. Check system permissions and sudoers/docker exec access."

    return True, ""


def apply_ddos_settings(settings: dict) -> tuple[bool, str]:
    """
    Generates NGINX rate-limiting configuration based on the provided settings
    and reloads NGINX to apply them.
    """
    try:
        rate_limit_rps = settings.get("rate_limit_rps", 50)
        burst_tolerance = settings.get("burst_tolerance", 100)
        trusted_ips = settings.get("trusted_ips", [])
        bot_action = settings.get("bot_mitigation_action", "Silent Drop")
        advanced_rules = settings.get("advanced_rules", [])

        # Determine HTTP status code based on bot_action
        # Silent Drop -> 444 (NGINX special code to close connection)
        # Block -> 429 (Too Many Requests) or 503 (Service Unavailable)
        status_code = 444 if bot_action == "Silent Drop" else 429

        config_lines = [
            "# Auto-generated by CyberSentinel WAF GUI",
            "# Do not edit manually",
            "",
        ]

        # Define GeoIP2 databases if they exist on disk AND the geoip2 nginx module is loaded.
        # GEOIP_DATA_DIR env var allows portable deployment on client servers.
        # Falls back to the demo-server absolute path when env var is not set.
        # GEOIP2_MODULE_ENABLED must be set to "true" once OpenResty is rebuilt with the module.
        geoip2_module_enabled = os.environ.get("GEOIP2_MODULE_ENABLED", "false").lower() == "true"

        _geoip_dir = os.environ.get(
            "GEOIP_DATA_DIR",
            os.path.abspath(
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
            )
        )
        COUNTRY_DB = os.path.join(_geoip_dir, "GeoLite2-Country.mmdb")
        ASN_DB = os.path.join(_geoip_dir, "GeoLite2-ASN.mmdb")

        has_country_db = os.path.exists(COUNTRY_DB)
        has_asn_db = os.path.exists(ASN_DB)

        if geoip2_module_enabled and has_country_db:
            config_lines.append(f"geoip2 {COUNTRY_DB} {{")
            config_lines.append(
                "    $geoip2_data_country_code source=$remote_addr country iso_code;"
            )
            config_lines.append("}")
            config_lines.append("")
        elif has_country_db:
            config_lines.append(
                "# geoip2 module not loaded — set GEOIP2_MODULE_ENABLED=true after rebuilding OpenResty"
            )
            config_lines.append("")

        if geoip2_module_enabled and has_asn_db:
            config_lines.append(f"geoip2 {ASN_DB} {{")
            config_lines.append(
                "    $geoip2_data_asn source=$remote_addr autonomous_system_number;"
            )
            config_lines.append(
                "    $geoip2_data_org source=$remote_addr autonomous_system_organization;"
            )
            config_lines.append("}")
            config_lines.append("")

        # --- Bot Mitigation ---
        config_lines.append("# --- Bot Mitigation ---")
        config_lines.append("map $http_user_agent $is_bad_bot {")
        config_lines.append("    default 0;")
        # Malicious crawlers & scrapers
        config_lines.append('    "~*semrush" 1;')
        config_lines.append('    "~*ahrefs" 1;')
        config_lines.append('    "~*mj12bot" 1;')
        config_lines.append('    "~*dotbot" 1;')
        config_lines.append('    "~*rogerbot" 1;')
        config_lines.append('    "~*megaindex" 1;')
        config_lines.append('    "~*zoominfobot" 1;')
        config_lines.append('    "~*yandexbot" 1;')
        config_lines.append('    "~*baiduspider" 1;')
        config_lines.append('    "~*screaming frog" 1;')
        # Vulnerability scanners & tools
        config_lines.append('    "~*sqlmap" 1;')
        config_lines.append('    "~*nmap" 1;')
        config_lines.append('    "~*nikto" 1;')
        config_lines.append('    "~*dirbuster" 1;')
        config_lines.append('    "~*censys" 1;')
        config_lines.append('    "~*shodan" 1;')
        config_lines.append('    "~*netsparker" 1;')
        config_lines.append('    "~*acunetix" 1;')
        # Common HTTP client libraries used for botting
        config_lines.append('    "~*python-requests" 1;')
        config_lines.append('    "~*pycurl" 1;')
        config_lines.append('    "~*urllib" 1;')
        config_lines.append('    "~*wget" 1;')
        # Empty user-agent or standard hyphen
        config_lines.append('    "-" 1;')
        config_lines.append('    "" 1;')
        config_lines.append("}")
        config_lines.append("")
        config_lines.append("map $is_bad_bot $bot_limit_key {")
        config_lines.append('    0 "";')
        config_lines.append('    1 "bad_bot_key";')
        config_lines.append("}")
        config_lines.append("")
        # We define a dedicated rate limiting zone for bad bots.
        # It permits 1 request per minute globally for all bad bots (effectively blocking them completely).
        config_lines.append("limit_req_zone $bot_limit_key zone=waf_bot_req:10m rate=1r/m;")
        config_lines.append("")

        # We always define the $limit_key variable.
        # If trusted_ips exist, it is dynamic. If not, it is equivalent to $binary_remote_addr.
        if trusted_ips:
            config_lines.append("geo $limit {")
            config_lines.append("    default 1;")
            for ip in trusted_ips:
                ip = ip.strip()
                if ip:
                    if not _validate_ip_or_cidr(ip):
                        logger.warning(f"Skipping invalid IP/CIDR in trusted list: '{ip}'")
                        continue
                    config_lines.append(f"    {ip} 0;")
            config_lines.append("}")
            config_lines.append("")
            config_lines.append("map $limit $limit_key {")
            config_lines.append('    0 "";')
            config_lines.append("    1 $binary_remote_addr;")
            config_lines.append("}")
        else:
            config_lines.append("map $host $limit_key {")
            config_lines.append("    default $binary_remote_addr;")
            config_lines.append("}")

        config_lines.append("")
        zone_key = "$limit_key"

        config_lines.append(
            f"limit_req_zone {zone_key} zone=waf_ddos_req:10m rate={rate_limit_rps}r/s;"
        )
        config_lines.append(f"limit_req_status {status_code};")
        config_lines.append("")
        # Apply globally to all traffic in the HTTP context
        config_lines.append(
            f"limit_req zone=waf_ddos_req burst={burst_tolerance} nodelay;"
        )
        # Apply bot mitigation rate-limiting globally
        # burst=1 because nginx requires burst >= 1; bots hit limit=1r/m so burst of 1 is effectively immediate block
        config_lines.append("limit_req zone=waf_bot_req burst=1 nodelay;")
        config_lines.append("")

        # Connection limiting
        config_lines.append(f"limit_conn_zone {zone_key} zone=waf_ddos_conn:10m;")
        config_lines.append(f"limit_conn_status {status_code};")
        config_lines.append(
            "limit_conn waf_ddos_conn 100;"
        )  # Hardcoded max 100 connections per IP for now
        config_lines.append("")

        # --- Advanced Rate Limiting Rules ---
        if advanced_rules:
            config_lines.append("# --- Advanced Rate Limiting Rules ---")
            for rule in advanced_rules:
                if not rule.get("enabled", True):
                    continue
                rule_id = rule.get("id")
                rule_name = rule.get("name", f"Rule {rule_id}")
                param_type = rule.get("parameter_type", "URI")
                param_value = rule.get("parameter_value", "")
                rule_rps = rule.get("rate_limit_rps", 10)
                rule_burst = rule.get("burst_tolerance", 20)

                # Determine NGINX variable to inspect and whether to rate-limit by the value itself
                nginx_var = "$request_uri"
                limit_by_value = False
                if param_type == "URI":
                    nginx_var = "$request_uri"
                elif param_type == "Method":
                    nginx_var = "$request_method"
                elif param_type == "Referrer":
                    nginx_var = "$http_referer"
                elif param_type == "Content-Type":
                    nginx_var = "$http_content_type"
                elif param_type == "IP":
                    nginx_var = "$remote_addr"
                elif param_type == "Session":
                    # cookie_name comes straight from the admin-supplied rule
                    # payload with no character restriction — embedded raw
                    # into an nginx variable-name token, an unsanitized value
                    # containing e.g. a newline or `{` could break out of the
                    # generated map block into arbitrary config injection.
                    cookie_name = param_value.strip() or "session"
                    safe_cookie_name = re.sub(r"[^A-Za-z0-9_-]", "", cookie_name).lower().replace("-", "_")
                    if not safe_cookie_name:
                        logger.warning(f"Skipping rule '{rule_name}': cookie name is empty after sanitization.")
                        continue
                    nginx_var = f"$cookie_{safe_cookie_name}"
                    limit_by_value = True
                elif param_type == "Country":
                    if not geoip2_module_enabled or not has_country_db:
                        logger.warning(
                            f"Skipping Country rate limiting rule '{rule_name}' — geoip2 module not enabled or Country GeoIP DB missing."
                        )
                        continue
                    nginx_var = "$geoip2_data_country_code"
                elif param_type == "ISP/ASN":
                    if not geoip2_module_enabled or not has_asn_db:
                        logger.warning(
                            f"Skipping ISP/ASN rate limiting rule '{rule_name}' — geoip2 module not enabled or ASN GeoIP DB missing."
                        )
                        continue
                    # Match ASN (if numeric) or Org name
                    if param_value.strip().isdigit():
                        nginx_var = "$geoip2_data_asn"
                    else:
                        nginx_var = "$geoip2_data_org"
                elif param_type == "Header":
                    # Custom header parsing (e.g. "X-API-Key: value" or just "X-API-Key")
                    # Same raw-embedding risk as the Session/cookie case above —
                    # header_name is sanitized to a safe variable-name charset
                    # before being spliced into the generated $http_<name> token.
                    if ":" in param_value:
                        parts = param_value.split(":", 1)
                        header_name = parts[0].strip()
                        param_value = parts[1].strip()
                    else:
                        header_name = param_value.strip()
                        limit_by_value = True

                    safe_header_name = re.sub(r"[^A-Za-z0-9_-]", "", header_name).lower().replace("-", "_")
                    if not safe_header_name:
                        logger.warning(f"Skipping rule '{rule_name}': header name is empty after sanitization.")
                        continue
                    nginx_var = "$http_" + safe_header_name

                if limit_by_value:
                    config_lines.append(
                        f"# Rule: {rule_name} (Type: {param_type}, Limit by unique value of {nginx_var})"
                    )
                    config_lines.append(f"map {nginx_var} $limit_key_{rule_id} {{")
                    config_lines.append(f'    "~.+" {nginx_var};')
                    config_lines.append('    default "";')
                    config_lines.append("}")
                else:
                    # Sanitize pattern to prevent NGINX config injection
                    # Strip characters that can break NGINX map block structure
                    clean_value = _sanitize_nginx_pattern(param_value)
                    if not clean_value:
                        logger.warning(f"Skipping rule '{rule_name}': pattern is empty after sanitization.")
                        continue

                    config_lines.append(
                        f"# Rule: {rule_name} (Type: {param_type}, Match: {param_value})"
                    )
                    config_lines.append(f"map {nginx_var} $limit_key_{rule_id} {{")
                    # Map to $limit_key (so trusted IPs automatically bypass this check)
                    # If param_type is Country, IP or numeric ISP/ASN, anchor matching with ^...$ to prevent substring matching
                    if param_type in ("Country", "IP") or (param_type == "ISP/ASN" and param_value.strip().isdigit()):
                        config_lines.append(f'    "~*^{clean_value}$" {zone_key};')
                    else:
                        config_lines.append(f'    "~*{clean_value}" {zone_key};')
                    config_lines.append('    default "";')
                    config_lines.append("}")

                config_lines.append(
                    f"limit_req_zone $limit_key_{rule_id} zone=zone_{rule_id}:10m rate={rule_rps}r/s;"
                )
                config_lines.append(
                    f"limit_req zone=zone_{rule_id} burst={rule_burst} nodelay;"
                )
                config_lines.append("")

        config_content = "\n".join(config_lines) + "\n"

        logger.info(f"Generated NGINX DDoS config for {DDOS_CONF_PATH}, validating before apply...")

        # Validate + apply + reload (rolls back this file if the new config is invalid)
        return write_and_apply_configs({DDOS_CONF_PATH: config_content})

    except Exception as e:
        logger.error(f"Failed to apply DDoS settings: {e}")
        return False, str(e)


def reload_nginx() -> bool:
    """
    Reloads the NGINX/OpenResty service gracefully.
    Tries sudo-prefixed commands first (required when running as non-root service user).
    Falls back to direct execution if sudo is not available.
    Requires /etc/sudoers.d/cybersentinel-waf to grant NOPASSWD for these commands.
    """
    candidates = [
        # Docker reload variants (first check if running in docker-compose environment)
        ["docker", "exec", "waf-openresty", "openresty", "-c", "/etc/nginx/nginx.conf", "-s", "reload"],
        ["docker", "exec", "waf-openresty", "nginx", "-c", "/etc/nginx/nginx.conf", "-s", "reload"],
        # sudo variants (for non-root service user via sudoers grant)
        ["sudo", "/usr/local/openresty/bin/openresty", "-c", "/etc/nginx/nginx.conf", "-s", "reload"],
        ["sudo", "/usr/local/openresty/nginx/sbin/nginx", "-c", "/etc/nginx/nginx.conf", "-s", "reload"],
        # Direct variants (when running as root)
        ["/usr/local/openresty/bin/openresty", "-c", "/etc/nginx/nginx.conf", "-s", "reload"],
        ["/usr/local/openresty/nginx/sbin/nginx", "-c", "/etc/nginx/nginx.conf", "-s", "reload"],
        ["openresty", "-c", "/etc/nginx/nginx.conf", "-s", "reload"],
        ["nginx", "-c", "/etc/nginx/nginx.conf", "-s", "reload"],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10  # nosec B603
            )
            if result.returncode == 0:
                logger.info(f"NGINX/OpenResty reloaded successfully via: {' '.join(cmd)}")
                return True
            else:
                logger.warning(
                    f"Reload via '{' '.join(cmd)}' failed (rc={result.returncode}): "
                    f"{result.stderr.strip()}"
                )
        except FileNotFoundError:
            logger.debug(f"Command not found: {cmd[0]}, trying next...")
            continue
        except subprocess.TimeoutExpired:
            logger.error(f"Reload command timed out: {' '.join(cmd)}")
            continue
        except Exception as e:
            logger.error(f"Error reloading via '{' '.join(cmd)}': {e}")
            continue
    logger.error("All NGINX/OpenResty reload attempts exhausted. Check sudoers and binary paths.")
    return False


def get_redis_client():
    """
    Get Redis client using centralized configuration.
    This function now delegates to app.utils.redis_client.get_global_redis_client()
    for consistent password handling across the codebase.
    """
    from app.utils.redis_client import get_global_redis_client as get_centralized_client
    return get_centralized_client()


def apply_hardening_settings(settings: dict) -> tuple[bool, str]:
    """
    Generates NGINX hardening configuration (server_tokens) and stores whitelisted/blacklisted
    IPs dynamically in Redis to enable zero-reload IP blocking.
    """
    try:
        server_cloaking = settings.get("server_cloaking", True)
        ip_blacklist = settings.get("ip_blacklist", [])
        ip_whitelist = settings.get("ip_whitelist", [])

        # 1. Update dynamic IP Whitelist/Blacklist in Redis
        r = get_redis_client()
        
        # Flush previous keys
        r.delete("waf:whitelist", "waf:whitelist:cidrs", "waf:blacklist", "waf:blacklist:cidrs")
        
        # Add whitelist
        for ip in ip_whitelist:
            ip = ip.strip()
            if ip:
                if not _validate_ip_or_cidr(ip):
                    logger.warning(f"Skipping invalid IP/CIDR in whitelist: '{ip}'")
                    continue
                if "/" in ip:
                    r.sadd("waf:whitelist:cidrs", ip)
                else:
                    r.sadd("waf:whitelist", ip)

        # Add blacklist
        for ip in ip_blacklist:
            ip = ip.strip()
            if ip:
                if not _validate_ip_or_cidr(ip):
                    logger.warning(f"Skipping invalid IP/CIDR in blacklist: '{ip}'")
                    continue
                if "/" in ip:
                    r.sadd("waf:blacklist:cidrs", ip)
                else:
                    r.sadd("waf:blacklist", ip)

        logger.info("Successfully updated dynamic WAF IP whitelist/blacklist in Redis.")

        # 2. Write server_tokens configuration to files
        config_lines = [
            "# Auto-generated by CyberSentinel WAF GUI",
            "# Do not edit manually",
            "",
        ]

        if server_cloaking:
            config_lines.append("server_tokens off;")
        else:
            config_lines.append("server_tokens on;")

        config_lines.append("")
        config_content = "\n".join(config_lines) + "\n"

        # Check if config content changed before writing and reloading to achieve zero-reload IP blocking
        existing_content = ""
        if os.path.exists(HARDENING_CONF_PATH):
            with open(HARDENING_CONF_PATH, "r", encoding="utf-8") as f:
                existing_content = f.read()

        if existing_content == config_content:
            logger.info("NGINX hardening config (server_tokens) is unchanged. Skipping NGINX reload.")
            return True, ""

        logger.info(f"Generated NGINX hardening config for {HARDENING_CONF_PATH}, validating before apply...")
        return write_and_apply_configs({HARDENING_CONF_PATH: config_content})
    except Exception as e:
        logger.error(f"Failed to apply hardening settings: {e}")
        return False, str(e)


def apply_positive_security_settings(settings: dict) -> tuple[bool, str]:
    """
    Generates ModSecurity rules enforcing the Positive Security allowlist
    (allowed HTTP methods, allowed request Content-Types, restricted file
    extensions) and reloads to apply. Disabled by default — settings.get
    ("enabled") must be explicitly true, since these defaults (e.g.
    allowed_methods: GET/POST/HEAD only) would otherwise silently start
    rejecting any protected app that legitimately uses PUT/DELETE/PATCH the
    moment this feature shipped. When disabled, writes a comment-only file,
    which correctly removes any previously-active rules.

    Any of the three lists being empty just skips generating that specific
    check (not "block everything") — an accidentally-cleared field should
    degrade to "not enforced", not "deny all traffic".

    Scoping to protected-app traffic only (never the dashboard) is done by
    WHERE this file gets referenced (see POSITIVE_SECURITY_CONF_PATH's
    docstring above) — no skip rule needed here.
    """
    try:
        enabled = bool(settings.get("enabled", False))
        config_lines = [
            "# Auto-generated by CyberSentinel WAF GUI — Positive Security policy",
            "# Do not edit manually",
        ]

        if not enabled:
            config_lines.append("# Positive Security is currently disabled — no active rules.")
            config_content = "\n".join(config_lines) + "\n"
            logger.info("Positive Security is disabled — applying an empty policy.")
            return write_and_apply_configs({POSITIVE_SECURITY_CONF_PATH: config_content})

        allowed_methods = [m.strip().upper() for m in settings.get("allowed_methods", []) if m.strip()]
        allowed_content_types = [c.strip() for c in settings.get("allowed_content_types", []) if c.strip()]
        restricted_extensions = [e.strip().lower().lstrip(".") for e in settings.get("restricted_extensions", []) if e.strip()]

        config_lines.append("")

        if allowed_methods:
            method_pattern = "^(" + "|".join(re.escape(m) for m in allowed_methods) + ")$"
            config_lines.append(
                f'SecRule REQUEST_METHOD "!@rx {method_pattern}" '
                f'"id:5900002,phase:1,deny,status:405,log,'
                f"msg:'Method not allowed by Positive Security policy'\""
            )
            config_lines.append("")

        if allowed_content_types:
            ct_pattern = "^(" + "|".join(re.escape(c) for c in allowed_content_types) + ")"
            config_lines.append(
                'SecRule REQUEST_METHOD "@rx ^(POST|PUT|PATCH)$" '
                '"id:5900003,phase:1,chain,deny,status:415,log,'
                "msg:'Content-Type not allowed by Positive Security policy'\""
            )
            config_lines.append(
                f'    SecRule REQUEST_HEADERS:Content-Type "!@rx {ct_pattern}" ""'
            )
            config_lines.append("")

        if restricted_extensions:
            ext_pattern = r"\.(" + "|".join(re.escape(e) for e in restricted_extensions) + ")$"
            config_lines.append(
                f'SecRule REQUEST_FILENAME "@rx {ext_pattern}" '
                f'"id:5900004,phase:1,deny,status:403,log,t:lowercase,'
                f"msg:'Restricted file extension blocked by Positive Security policy'\""
            )
            config_lines.append("")

        config_content = "\n".join(config_lines) + "\n"
        logger.info(
            f"Generated Positive Security policy for {POSITIVE_SECURITY_CONF_PATH} "
            f"({len(allowed_methods)} allowed methods, {len(allowed_content_types)} allowed "
            f"content-types, {len(restricted_extensions)} restricted extensions), "
            "validating before apply..."
        )
        return write_and_apply_configs({POSITIVE_SECURITY_CONF_PATH: config_content})
    except Exception as e:
        logger.error(f"Failed to apply positive security settings: {e}")
        return False, str(e)


def apply_custom_response_page(html_content: str) -> tuple[bool, str]:
    """
    Writes the admin-configured "WAF blocked you" page to
    CUSTOM_RESPONSE_PAGE_PATH. The file itself is inert until a protected
    app's server{} block references it via an `internal` location (added in
    sync_protected_apps_to_nginx()) — that's what makes this actually get
    served on a real 403 instead of just sitting on disk.

    Uses write_and_apply_configs() purely for the atomic-write + validate +
    reload guarantee every other config writer here gets, even though nginx
    syntax validation has nothing to check in a plain HTML file — the value
    is the same backup/rollback-on-failure behavior and cache-busting reload.
    """
    try:
        return write_and_apply_configs({CUSTOM_RESPONSE_PAGE_PATH: html_content})
    except Exception as e:
        logger.error(f"Failed to apply custom response page: {e}")
        return False, str(e)


def app_auth_conf_path(app_id) -> str:
    return f"{APP_AUTH_CONF_DIR}/app_{app_id}.conf"


def _generate_app_auth_conf(app: dict) -> str:
    """
    Generates a ModSecurity rule denying (401) any request missing a
    configured header or cookie — a PRESENCE check, not token validation
    (the token isn't verified, just that something was sent). Comment-only
    when require_auth is off, same "always reference the file, content
    decides" pattern as apply_positive_security_settings().
    """
    lines = [
        "# Auto-generated by CyberSentinel WAF GUI — per-app auth requirement",
        "# Do not edit manually",
    ]

    if not app.get("require_auth"):
        lines.append("# Authentication requirement is disabled for this app — no active rules.")
        return "\n".join(lines) + "\n"

    check_type = app.get("auth_check_type") or "header"
    raw_name = (app.get("auth_header_name") or "Authorization").strip()
    # Header/cookie names are restricted to token characters (RFC 7230) —
    # stripping anything else both sanitizes for safe embedding in the
    # ModSecurity variable name and rejects nonsense input safely.
    safe_name = re.sub(r"[^A-Za-z0-9!#$%&'*+\-.^_`|~]", "", raw_name) or "Authorization"

    variable = f"REQUEST_COOKIES:{safe_name}" if check_type == "cookie" else f"REQUEST_HEADERS:{safe_name}"
    app_id = app.get("id")

    lines.append(
        f'SecRule &{variable} "@eq 0" '
        f'"id:{5_910_000 + int(app_id)},phase:1,deny,status:401,log,'
        f"msg:'Request missing required authentication'\""
    )
    return "\n".join(lines) + "\n"


def sync_protected_apps_to_nginx() -> tuple[bool, str]:
    """
    Generates NGINX virtual host configurations for all active protected applications
    and reloads NGINX.
    """
    from app.services.db_service import get_all_protected_apps
    
    try:
        apps = get_all_protected_apps()
        active_apps = [app for app in apps if app.get("is_active", 1) == 1]
        
        # 1. Generate dynamic rate limit zones file in /etc/nginx/conf.d/
        rate_limit_lines = [
            "# Auto-generated by CyberSentinel WAF GUI",
            "# Per-application rate limit zones definition",
            ""
        ]
        
        for app in active_apps:
            app_id = app.get("id")
            rate_rps = app.get("rate_limit_rps", 50)
            rate_limit_lines.append(
                f"limit_req_zone $binary_remote_addr zone=zone_app_{app_id}:10m rate={rate_rps}r/s;"
            )
            
        rate_limits_content = "\n".join(rate_limit_lines) + "\n"
        rate_limits_conf_path = "/etc/nginx/conf.d/waf_app_rate_limits.conf"

        config_lines = [
            "# =============================================================================",
            "# Dynamic WAF Protected Applications — Virtual Host Configuration",
            "# Auto-generated by CyberSentinel WAF GUI",
            "# Do not edit manually",
            "# =============================================================================",
            "",
            "# Port 80: ACME HTTP-01 challenge passthrough + HTTPS redirect",
            "server {",
            "    listen 80 default_server;",
            "    listen [::]:80 default_server;",
            "    server_name _;",
            "    access_log /var/log/nginx/http_redirect.log combined;",
            "",
            "    # Let's Encrypt HTTP-01 challenge: serve webroot, do NOT redirect",
            "    location /.well-known/acme-challenge/ {",
            "        root /etc/nginx/acme-challenge;",
            "        default_type text/plain;",
            "        try_files $uri =404;",
            "    }",
            "",
            "    # All other traffic: redirect to HTTPS",
            "    location / {",
            "        return 301 https://$host$request_uri;",
            "    }",
            "}",
            ""
        ]

        # Populated per-app inside the loop below; must exist regardless of
        # which branch runs so the final write_and_apply_configs() call
        # (outside both branches) can always reference it.
        app_auth_files = {}

        if not active_apps:
            logger.warning("No active protected applications found in database. Generating fallback server block.")
            config_lines.extend([
                "# Fallback dummy server when no apps are active",
                "server {",
                "    listen 443 ssl default_server;",
                "    listen [::]:443 ssl default_server;",
                "    http2 on;",
                "    server_name _;",
                "",
                "    ssl_certificate     /etc/nginx/ssl/cybersentinel.crt;",
                "    ssl_certificate_key /etc/nginx/ssl/cybersentinel.key;",
                "",
                "    location / {",
                "        default_type text/html;",
                "        return 404 \"<html><head><title>No Protected Applications</title></head><body style='font-family:sans-serif; text-align:center; padding:50px; background:#0b0f19; color:#f3f4f6;'><h2>CyberSentinel WAF</h2><p style='color:#9ca3af;'>No active protected applications are currently routed through this gateway.</p></body></html>\";",
                "    }",
                "}"
            ])
        else:
            has_wildcard_default = any(app.get("domain") == "_" for app in active_apps)

            for idx, app in enumerate(active_apps):
                app_id = app.get("id")
                name = app.get("name", f"App {app_id}")
                domain = app.get("domain", "_").strip().lower()
                upstream_host = app.get("upstream_host", "host.docker.internal").strip()
                upstream_port = app.get("upstream_port", 7000)
                protocol = app.get("protocol", "http").strip().lower()
                burst = app.get("burst_tolerance", 100)
                
                # Decide if default_server is applied
                is_default = False
                if domain == "_":
                    is_default = True
                elif not has_wildcard_default and idx == 0:
                    is_default = True
                    
                listen_suffix = " default_server" if is_default else ""
                
                # Determine which cert to use for this app
                ssl_option = app.get("ssl_option", "self-signed")
                ssl_cert_path = app.get("ssl_cert_path") or ""
                ssl_key_path  = app.get("ssl_key_path")  or ""

                # Validate that the configured cert files actually exist on disk;
                # fall back to the default self-signed cert if they are missing.
                DEFAULT_CERT = "/etc/nginx/ssl/cybersentinel.crt"
                DEFAULT_KEY  = "/etc/nginx/ssl/cybersentinel.key"

                if ssl_option in ("letsencrypt", "custom") and ssl_cert_path and ssl_key_path:
                    if os.path.exists(ssl_cert_path) and os.path.exists(ssl_key_path):
                        active_cert = ssl_cert_path
                        active_key  = ssl_key_path
                    else:
                        logger.warning(
                            f"App {app_id} ({domain}): configured cert not found at {ssl_cert_path}. "
                            "Falling back to self-signed cert."
                        )
                        active_cert = DEFAULT_CERT
                        active_key  = DEFAULT_KEY
                else:
                    active_cert = DEFAULT_CERT
                    active_key  = DEFAULT_KEY

                auth_conf_path = app_auth_conf_path(app_id)
                app_auth_files[auth_conf_path] = _generate_app_auth_conf(app)

                config_lines.extend([
                    f"# --- Upstream App {app_id}: {name} ({domain}) ---",
                    f"upstream upstream_app_{app_id} {{",
                    f"    server {upstream_host}:{upstream_port} max_fails=3 fail_timeout=10s;",
                    "}",
                    "",
                    f"# --- App {app_id}: {name} ({domain}) [{ssl_option}] ---",
                    "server {",
                    f"    listen 443 ssl{listen_suffix};",
                    f"    listen [::]:443 ssl{listen_suffix};",
                    "    http2 on;",
                    f"    server_name {domain};",
                    "",
                    f"    ssl_certificate     {active_cert};",
                    f"    ssl_certificate_key {active_key};",
                    "",
                    "    resolver 127.0.0.11 valid=30s ipv6=off;",
                    "",
                    # Scoped to this protected app's own server block only —
                    # never the WAF GUI's own dashboard (a separate vhost on
                    # port 3020 that doesn't reference this file). Content is
                    # comment-only when Positive Security is disabled, so
                    # this reference is always safe to include.
                    f"    modsecurity_rules_file {POSITIVE_SECURITY_CONF_PATH};",
                    f"    modsecurity_rules_file {auth_conf_path};",
                    "",
                    # Admin-configurable block page (Settings > Custom Response).
                    # Only overrides the browser-facing `/` location below —
                    # /api keeps its own JSON error_page, which is location-
                    # scoped and so takes precedence for requests under /api.
                    "    error_page 403 /__waf_block_page__.html;",
                    "    location = /__waf_block_page__.html {",
                    "        internal;",
                    f"        alias {CUSTOM_RESPONSE_PAGE_PATH};",
                    "        default_type text/html;",
                    "        sub_filter_types text/html;",
                    "        sub_filter '{{transaction_id}}' $request_id;",
                    "        sub_filter_once off;",
                    "    }",
                    "",
                    "    location @json_forbidden {",
                    "        default_type application/json;",
                    "        add_header Content-Type 'application/json; charset=utf-8' always;",
                    "        return 403 '{\"error\": \"🚨 WAF caught you! This attack has been blocked 🚫 and logged 📋. CyberSentinel is watching 👀\", \"code\": 403}';",
                    "    }",
                    "",
                    "    location / {",
                    f"        limit_req zone=zone_app_{app_id} burst={burst};",
                    f"        proxy_pass {protocol}://upstream_app_{app_id};",
                    "        proxy_http_version 1.1;",
                    "        proxy_set_header Upgrade $http_upgrade;",
                    "        proxy_set_header Connection 'upgrade';",
                    "        proxy_set_header Host $host;",
                    "        proxy_set_header X-Real-IP $remote_addr;",
                    "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                    "        proxy_set_header X-Forwarded-Proto $scheme;",
                    "        proxy_next_upstream error timeout http_502 http_503;",
                    "        proxy_next_upstream_tries 3;",
                    "        proxy_next_upstream_timeout 10s;",
                    "    }",
                    "",
                    "    location /api {",
                    "        error_page 403 = @json_forbidden;",
                    f"        limit_req zone=zone_app_{app_id} burst={max(5, burst // 3)} nodelay;",
                    "",
                    f"        proxy_pass {protocol}://upstream_app_{app_id};",
                    "        proxy_http_version 1.1;",
                    "        proxy_set_header Upgrade $http_upgrade;",
                    "        proxy_set_header Connection 'upgrade';",
                    "        proxy_set_header Host $host;",
                    "        proxy_set_header X-Real-IP $remote_addr;",
                    "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                    "        proxy_set_header X-Forwarded-Proto $scheme;",
                    "        proxy_next_upstream error timeout http_502 http_503;",
                    "        proxy_next_upstream_tries 3;",
                    "        proxy_next_upstream_timeout 10s;",
                    "    }",
                    "}",
                    ""
                ])

            
        config_content = "\n".join(config_lines) + "\n"
        apps_conf_path = "/etc/nginx/sites-enabled/mssp"

        logger.info(
            f"Generated dynamic WAF apps config for {apps_conf_path} "
            f"({len(active_apps)} active app(s)), validating before apply..."
        )
        return write_and_apply_configs({
            rate_limits_conf_path: rate_limits_content,
            apps_conf_path: config_content,
            **app_auth_files,
        })
    except Exception as e:
        logger.error(f"Failed to sync protected apps to NGINX: {e}")
        return False, str(e)


def test_nginx_config() -> tuple[bool, str]:
    """
    Runs syntax check on NGINX/OpenResty configuration (openresty -c /etc/nginx/nginx.conf -t).
    Returns (True, "") if syntax is valid, or (False, error_details) otherwise.
    """
    candidates = [
        # Docker syntax test variants
        ["docker", "exec", "waf-openresty", "openresty", "-c", "/etc/nginx/nginx.conf", "-t"],
        ["docker", "exec", "waf-openresty", "nginx", "-c", "/etc/nginx/nginx.conf", "-t"],
        # sudo variants
        ["sudo", "/usr/local/openresty/bin/openresty", "-c", "/etc/nginx/nginx.conf", "-t"],
        ["sudo", "/usr/local/openresty/nginx/sbin/nginx", "-c", "/etc/nginx/nginx.conf", "-t"],
        # Direct variants
        ["/usr/local/openresty/bin/openresty", "-c", "/etc/nginx/nginx.conf", "-t"],
        ["/usr/local/openresty/nginx/sbin/nginx", "-c", "/etc/nginx/nginx.conf", "-t"],
        ["openresty", "-c", "/etc/nginx/nginx.conf", "-t"],
        ["nginx", "-c", "/etc/nginx/nginx.conf", "-t"],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10  # nosec B603
            )
            if result.returncode == 0:
                logger.info(f"NGINX/OpenResty config test passed via: {' '.join(cmd)}")
                return True, ""
            else:
                stderr = result.stderr or result.stdout or ""
                logger.warning(
                    f"Config test via '{' '.join(cmd)}' failed (rc={result.returncode}): "
                    f"{stderr.strip()}"
                )
                return False, stderr.strip()
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            logger.error(f"Config test command timed out: {' '.join(cmd)}")
            return False, "Syntax validation check timed out."
        except Exception as e:
            logger.error(f"Error testing config via '{' '.join(cmd)}': {e}")
            return False, str(e)
    logger.error("All NGINX/OpenResty configuration test attempts exhausted.")
    return False, "Could not run configuration syntax validation check."

