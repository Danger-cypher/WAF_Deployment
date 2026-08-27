"""
CyberSentinel WAF - CVE Virtual Patch Deployment (P1-5)
==========================================================
Deploys/undeploys/switches-mode for entries from the curated template
library in app/data/cve_templates.py, into their own clearly-delimited,
machine-managed section of custom-rules.conf — mirrors
routes/api_protection.py's endpoint-block marker/upsert pattern exactly
(same file, same "don't disturb the admin's own hand-written Virtual
Patching rules" goal), but keyed by explicit start/end marker LINES per
block rather than a fixed line-count offset, since each CVE template's
rule_body spans a different number of lines (api_protection.py's
generated block is always exactly 2 lines, so it can hardcode that; these
can't).

Staged rollout: unlike CRS rules (P1-6's canary mechanism — see
rule_manager.py), a virtual patch is admin/template-generated raw SecRule
text, so "detect first, block later" is just a matter of which disruptive
action verb gets written — no shadow-mode infrastructure needed. Deploy in
mode="detect" (writes "pass") to observe hits via ClickHouse
(get_rule_canary_report, reused as-is against this rule's own numeric id)
before promoting to mode="block" (writes "block", using this deployment's
already-configured default block status/action, matching how the rest of
this WAF's rules block).
"""
import hashlib
import logging
import re
from typing import Dict, List, Optional, Tuple

from app.data.cve_templates import CVE_TEMPLATES

logger = logging.getLogger(__name__)

CUSTOM_RULES_FILE = "/etc/nginx/modsec/custom-rules.conf"

_SECTION_START_MARKER = "# >>> VIRTUAL-PATCH-AUTO-GENERATED-START (do not edit manually) >>>"
_SECTION_END_MARKER = "# <<< VIRTUAL-PATCH-AUTO-GENERATED-END <<<"
_START_LINE_RE = re.compile(r"^# virtual-patch: (\S+) mode=(detect|block)$")

_TEMPLATES_BY_ID = {t["cve_id"]: t for t in CVE_TEMPLATES}

VALID_MODES = ("detect", "block")


def _start_marker(cve_id: str, mode: str) -> str:
    return f"# virtual-patch: {cve_id} mode={mode}"


def _end_marker(cve_id: str) -> str:
    return f"# /virtual-patch: {cve_id}"


def rule_id_for(cve_id: str) -> int:
    """Deterministic rule id so the same CVE always maps to the same id
    (redeploy / mode-switch stays idempotent, and a hit-count lookup can
    always find the right id without a separate lookup table). Landed in
    its own band — 6,000,000+ — clearly outside every other reserved
    range already in use in this codebase: CRS (900000-999999), FP
    exclusions (10000000+), DLP (2000001+), API Protection
    (5000000 + hash%900000, i.e. tops out at 5,900,000), hardening
    (5900002-5900005). Same SHA-256-not-hash() reasoning as
    api_protection.py's _rule_id_for: Python's hash() is randomized per
    process and would change the id on every restart."""
    digest = hashlib.sha256(cve_id.encode("utf-8")).hexdigest()
    return 6_000_000 + (int(digest, 16) % 900_000)


def get_template(cve_id: str) -> Optional[dict]:
    return _TEMPLATES_BY_ID.get(cve_id)


def _read_custom_rules() -> str:
    import os

    if not os.path.exists(CUSTOM_RULES_FILE):
        return ""
    with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
        return f.read()


def list_deployed(content: Optional[str] = None) -> Dict[str, str]:
    """{cve_id: mode} for every currently-deployed virtual patch."""
    if content is None:
        content = _read_custom_rules()
    deployed = {}
    for line in content.split("\n"):
        m = _START_LINE_RE.match(line.strip())
        if m:
            deployed[m.group(1)] = m.group(2)
    return deployed


def _find_block_bounds(lines: List[str], cve_id: str) -> Optional[Tuple[int, int]]:
    """Returns (start_idx, end_idx) inclusive, covering the marker line
    through the closing marker line, for the given cve_id's currently
    deployed block (any mode) — or None if not present."""
    end = _end_marker(cve_id)
    start_idx = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if start_idx is None:
            m = _START_LINE_RE.match(stripped)
            if m and m.group(1) == cve_id:
                start_idx = i
                continue
        elif stripped == end:
            return start_idx, i
    return None


def _remove_existing_block(content: str, cve_id: str) -> str:
    lines = content.split("\n")
    bounds = _find_block_bounds(lines, cve_id)
    if bounds is None:
        return content
    start_idx, end_idx = bounds
    return "\n".join(lines[:start_idx] + lines[end_idx + 1:])


def _build_block(cve_id: str, mode: str, rule_id: int) -> str:
    template = _TEMPLATES_BY_ID[cve_id]
    action = "pass" if mode == "detect" else "block"
    rule_text = template["rule_body"].replace("__ID__", str(rule_id)).replace("__MODE__", action)
    return f"{_start_marker(cve_id, mode)}\n{rule_text}\n{_end_marker(cve_id)}"


def _upsert_block(content: str, cve_id: str, mode: str, rule_id: int) -> str:
    """Replaces this CVE's block (any prior mode) with a freshly-built one
    — used for both "deploy" and "switch mode", since a mode switch is
    just a redeploy with a different action verb. Creates the
    auto-generated wrapper section on first use, same as
    api_protection.py's _upsert_block."""
    content = _remove_existing_block(content, cve_id)
    block = _build_block(cve_id, mode, rule_id)

    if _SECTION_START_MARKER in content and _SECTION_END_MARKER in content:
        return content.replace(_SECTION_END_MARKER, block + "\n" + _SECTION_END_MARKER)

    separator = "\n" if content and not content.endswith("\n") else ""
    return (
        content + separator +
        f"\n{_SECTION_START_MARKER}\n" + block + f"\n{_SECTION_END_MARKER}\n"
    )


def deploy(cve_id: str, mode: str) -> Tuple[bool, str]:
    """Deploys (or redeploys, e.g. to switch mode) a virtual patch. Admin
    only — see routes/virtual_patches.py; this module has no auth of its
    own, same convention as api_protection.py's block helpers."""
    from app.services.nginx_manager import write_and_apply_configs

    if cve_id not in _TEMPLATES_BY_ID:
        return False, f"Unknown CVE template: {cve_id}"
    if mode not in VALID_MODES:
        return False, f"mode must be one of {VALID_MODES}"

    current_content = _read_custom_rules()
    rule_id = rule_id_for(cve_id)
    new_content = _upsert_block(current_content, cve_id, mode, rule_id)
    if new_content == current_content:
        return True, "No change."

    success, err_msg = write_and_apply_configs({CUSTOM_RULES_FILE: new_content})
    if not success:
        return False, f"Failed to deploy virtual patch: {err_msg}"
    return True, ""


def undeploy(cve_id: str) -> Tuple[bool, str]:
    from app.services.nginx_manager import write_and_apply_configs

    current_content = _read_custom_rules()
    new_content = _remove_existing_block(current_content, cve_id)
    if new_content == current_content:
        return True, "Not currently deployed."

    success, err_msg = write_and_apply_configs({CUSTOM_RULES_FILE: new_content})
    if not success:
        return False, f"Failed to remove virtual patch: {err_msg}"
    return True, ""


def get_library() -> List[dict]:
    """The full curated template list, each entry annotated with its
    current deployment status — the single response the frontend's
    library view needs, no separate round-trip to figure out what's
    already deployed."""
    deployed = list_deployed()
    result = []
    for template in CVE_TEMPLATES:
        cve_id = template["cve_id"]
        entry = dict(template)
        entry["rule_id"] = rule_id_for(cve_id)
        entry["deployed_mode"] = deployed.get(cve_id)
        result.append(entry)
    return result
