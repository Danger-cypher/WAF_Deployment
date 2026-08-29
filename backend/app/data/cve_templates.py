"""
CyberSentinel WAF - CVE Virtual Patch Template Library (P1-5)
================================================================
A small, curated set of well-documented, high-confidence virtual-patch
rules for specific, widely-known CVEs — bundled and shipped with the app,
not fetched live. This mirrors the existing precedent in this codebase
(custom-dlp.conf's hand-authored DLP rules) rather than the one live-fetch
precedent (threat_intel_service.py), which is architecturally different:
it only ever pulls IP-reputation *data* into a blocklist, never generates
or executes rule *syntax* from an external source — doing that here would
mean trusting and auto-deploying someone else's WAF logic sight-unseen,
a real supply-chain risk this project has no reason to take on.

Each template's `rule_body` is a complete, hand-authored ModSecurity
SecRule (or the small handful of well-documented cases, a chain), written
and reviewed the same way custom-dlp.conf's rules were — not generated
from a generic "variables + operator" abstraction, because real CVE
signatures vary too much in shape (headers vs body vs URI, single rule vs
chain, transformation functions needed) for a one-size template to stay
both simple and actually correct. Two tokens are substituted by
virtual_patch_service.py at deploy time, never trusted from this file
directly:
  - __ID__   — a numeric rule id, computed deterministically per CVE (see
               virtual_patch_service._rule_id_for), not hardcoded here, so
               there is exactly one source of truth for ID allocation and
               it can never collide with another feature's reserved band.
  - __MODE__ — the disruptive action, "pass" for detect-only or "block"
               for enforcing, chosen by the admin at deploy time (this is
               the entire "staged rollout" story for virtual patches: a
               patch can be deployed in detect mode first, its real-world
               hit rate reviewed via ClickHouse, then switched to block —
               see virtual_patch_service.set_mode()).

IMPORTANT — what this is and isn't: these are signature-based mitigations
meant to buy time, not a substitute for actually patching the underlying
software. Each description says so explicitly; the UI surfaces that text
rather than hiding it, so this feature can't be mistaken for "CVE fixed."
"""

CVE_TEMPLATES = [
    {
        "cve_id": "CVE-2021-44228",
        "title": "Log4Shell — Apache Log4j2 JNDI Lookup RCE",
        "affected_product": "Apache Log4j2 2.0-beta9 through 2.14.1",
        "severity": "critical",
        "cvss_score": 10.0,
        "description": (
            "Log4j2's JNDI message-lookup substitution lets attacker-controlled "
            "input reaching a log statement trigger a JNDI lookup (LDAP, RMI, "
            "DNS, ...), leading to remote code execution when the response is "
            "deserialized. This rule detects the '${jndi:' lookup pattern in "
            "request headers, parameters, body, and URI. Signature-based "
            "detection only — it does not replace upgrading Log4j2 to 2.17.1+."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        ],
        "rule_body": (
            'SecRule REQUEST_HEADERS|ARGS|REQUEST_BODY|REQUEST_URI '
            '"@rx (?i)\\$\\{jndi:(?:ldap|ldaps|rmi|dns|iiop|corba|nis|nds|http|https):" \\\n'
            '    "id:__ID__,\\\n'
            '    phase:2,\\\n'
            '    __MODE__,\\\n'
            '    log,\\\n'
            '    t:none,\\\n'
            '    t:urlDecodeUni,\\\n'
            "    msg:'Virtual Patch CVE-2021-44228 (Log4Shell): JNDI lookup pattern detected',\\\n"
            "    logdata:'Matched Data: %{MATCHED_VAR}',\\\n"
            "    severity:'CRITICAL',\\\n"
            "    tag:'virtual-patch',\\\n"
            "    tag:'CVE-2021-44228'\""
        ),
    },
    {
        "cve_id": "CVE-2022-22965",
        "title": "Spring4Shell — Spring Framework ClassLoader RCE",
        "affected_product": "Spring Framework (JDK 9+) prior to 5.3.18 / 5.2.20",
        "severity": "critical",
        "cvss_score": 9.8,
        "description": (
            "Spring's data-binding for JDK 9+ allows a crafted parameter name "
            "referencing the class's ClassLoader (e.g. 'class.module.classLoader') "
            "to manipulate application internals via property binding, leading "
            "to remote code execution on Tomcat deployments. This rule detects "
            "that parameter-name pattern in request parameter names and body. "
            "Signature-based detection only — upgrade Spring Framework to fix "
            "the underlying issue."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965",
        ],
        "rule_body": (
            'SecRule ARGS_NAMES|REQUEST_BODY '
            '"@rx (?i)(?:class\\.module\\.classLoader|class\\.classLoader)" \\\n'
            '    "id:__ID__,\\\n'
            '    phase:2,\\\n'
            '    __MODE__,\\\n'
            '    log,\\\n'
            '    t:none,\\\n'
            '    t:urlDecodeUni,\\\n'
            "    msg:'Virtual Patch CVE-2022-22965 (Spring4Shell): ClassLoader property-binding attempt',\\\n"
            "    logdata:'Matched Data: %{MATCHED_VAR}',\\\n"
            "    severity:'CRITICAL',\\\n"
            "    tag:'virtual-patch',\\\n"
            "    tag:'CVE-2022-22965'\""
        ),
    },
    {
        "cve_id": "CVE-2017-5638",
        "title": "Apache Struts2 Jakarta Multipart Parser RCE",
        "affected_product": "Apache Struts 2.3.5 – 2.3.31, 2.5 – 2.5.10",
        "severity": "critical",
        "cvss_score": 10.0,
        "description": (
            "The Jakarta Multipart parser in Struts2 evaluates the Content-Type "
            "header as an OGNL expression when parsing a malformed value, "
            "allowing remote code execution (the CVE behind the 2017 Equifax "
            "breach). This rule detects OGNL injection syntax ('%{...}') in the "
            "Content-Type header. Signature-based detection only — upgrade "
            "Struts to a patched version."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638",
        ],
        "rule_body": (
            'SecRule REQUEST_HEADERS:Content-Type "@rx (?i)%\\{[^}]*\\}" \\\n'
            '    "id:__ID__,\\\n'
            '    phase:1,\\\n'
            '    __MODE__,\\\n'
            '    log,\\\n'
            '    t:none,\\\n'
            "    msg:'Virtual Patch CVE-2017-5638 (Apache Struts2 Jakarta Multipart RCE): OGNL injection pattern in Content-Type header',\\\n"
            "    logdata:'Matched Data: %{MATCHED_VAR}',\\\n"
            "    severity:'CRITICAL',\\\n"
            "    tag:'virtual-patch',\\\n"
            "    tag:'CVE-2017-5638'\""
        ),
    },
    {
        "cve_id": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal / RCE (mod_cgi)",
        "affected_product": "Apache HTTP Server 2.4.49 – 2.4.50",
        "severity": "critical",
        "cvss_score": 9.8,
        "description": (
            "A path-normalization regression in Apache HTTPD 2.4.49/2.4.50 "
            "allows encoded directory-traversal sequences to escape the "
            "document root, leading to information disclosure or, when "
            "mod_cgi is enabled, remote code execution. This rule detects "
            "encoded traversal sequences in cgi-bin request paths. "
            "Signature-based detection only — upgrade to 2.4.51+."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        ],
        "rule_body": (
            'SecRule REQUEST_URI "@rx (?i)/cgi-bin/.*(?:\\.\\.%2f|%2e%2e/|%2e%2e%2f|\\.\\./)" \\\n'
            '    "id:__ID__,\\\n'
            '    phase:1,\\\n'
            '    __MODE__,\\\n'
            '    log,\\\n'
            '    t:none,\\\n'
            "    msg:'Virtual Patch CVE-2021-41773/CVE-2021-42013 (Apache HTTPD path traversal): encoded traversal in cgi-bin path',\\\n"
            "    logdata:'Matched Data: %{MATCHED_VAR}',\\\n"
            "    severity:'CRITICAL',\\\n"
            "    tag:'virtual-patch',\\\n"
            "    tag:'CVE-2021-41773'\""
        ),
    },
    {
        "cve_id": "CVE-2014-6271",
        "title": "Shellshock — GNU Bash Function Definition RCE",
        "affected_product": "GNU Bash prior to 4.3 patch 25",
        "severity": "critical",
        "cvss_score": 9.8,
        "description": (
            "Bash incorrectly executes trailing commands appended after a "
            "function definition stored in an environment variable, letting an "
            "attacker who controls a header or parameter that ends up in a CGI "
            "script's environment execute arbitrary commands. This rule detects "
            "the '() { :;};' function-definition pattern in request headers, "
            "parameters, and body. Signature-based detection only — patch Bash."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271",
        ],
        "rule_body": (
            'SecRule REQUEST_HEADERS|ARGS|REQUEST_BODY "@rx \\(\\)\\s*\\{\\s*:;?\\s*\\}" \\\n'
            '    "id:__ID__,\\\n'
            '    phase:2,\\\n'
            '    __MODE__,\\\n'
            '    log,\\\n'
            '    t:none,\\\n'
            "    msg:'Virtual Patch CVE-2014-6271 (Shellshock): Bash function-definition pattern detected',\\\n"
            "    logdata:'Matched Data: %{MATCHED_VAR}',\\\n"
            "    severity:'CRITICAL',\\\n"
            "    tag:'virtual-patch',\\\n"
            "    tag:'CVE-2014-6271'\""
        ),
    },
]
