"""
api_spec.py — CyberSentinel WAF
===============================================
OpenAPI/Swagger spec parsing and traffic-drift comparison for API
Protection. Answers two questions competitors in this space (Salt,
Noname, 42Crunch) treat as core: does real traffic include endpoints
nobody documented (shadow APIs), and does the documented surface include
endpoints nobody's actually seen hit (possibly deprecated/never-shipped
or just not yet exercised)?

Scope: path + method comparison only, via OpenAPI's own path-templating
syntax ("/users/{id}"). Does not validate request/response schemas,
parameters, or auth requirements against the spec — that's a much
bigger feature (contract testing) this doesn't attempt.
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

_VALID_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def parse_spec(content: str) -> Dict[str, Any]:
    """
    Parse an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML) and
    extract its (method, path_template) endpoint list.

    Raises ValueError with a human-readable reason on anything
    unparseable — callers turn this into an HTTP 400, not a 500, since a
    bad upload is a user input error, not a server fault.
    """
    parsed = _load_document(content)

    paths = parsed.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("No 'paths' object found — doesn't look like an OpenAPI/Swagger document.")

    endpoints: List[Dict[str, str]] = []
    for path_template, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in path_item.keys():
            if method.lower() in _VALID_HTTP_METHODS:
                endpoints.append({"method": method.upper(), "path_template": path_template})

    if not endpoints:
        raise ValueError("Spec parsed but contains no operations (methods) under any path.")

    version = parsed.get("openapi") or parsed.get("swagger") or "unknown"
    return {"version": str(version), "endpoints": endpoints}


def _load_document(content: str) -> Dict[str, Any]:
    """Try JSON first (strict, fast, no ambiguity), then YAML — safe_load
    only, never yaml.load, since this is admin-uploaded content parsed
    server-side and unsafe loading can execute arbitrary Python objects
    embedded in the document."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError(f"Not valid JSON or YAML: {e}")
    if not isinstance(doc, dict):
        raise ValueError("Parsed content is not a JSON/YAML object at the top level.")
    return doc


def path_template_to_regex(template: str) -> re.Pattern:
    """
    Convert an OpenAPI path template ("/users/{id}/orders/{orderId}")
    into a regex that matches concrete request URIs. Each {param}
    segment matches one path segment (no slashes) — OpenAPI's own
    semantics; a param spanning multiple segments would need an
    explicit wildcard extension, which this doesn't support.
    """
    parts = re.split(r"(\{[^/{}]+\})", template)
    pattern_parts = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            pattern_parts.append(r"[^/]+")
        else:
            pattern_parts.append(re.escape(part))
    return re.compile("^" + "".join(pattern_parts) + "$")


def _compile_spec_patterns(spec_endpoints: List[Dict[str, str]]) -> List[Tuple[str, re.Pattern, str]]:
    """Returns [(method, compiled_regex, original_template), ...] —
    compiled once per drift computation rather than per discovered
    endpoint, since the same spec is checked against every one of them."""
    compiled = []
    for ep in spec_endpoints:
        try:
            compiled.append((ep["method"], path_template_to_regex(ep["path_template"]), ep["path_template"]))
        except re.error as e:
            logger.warning(f"Skipping unparseable spec path template '{ep.get('path_template')}': {e}")
    return compiled


def compute_drift(
    spec_endpoints: List[Dict[str, str]],
    discovered_endpoints: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compare the spec's documented (method, path_template) set against
    real observed traffic.

    - shadow_endpoints: seen in traffic, matches no spec path — an
      undocumented endpoint that's real and reachable right now.
    - undocumented_spec_endpoints: in the spec, never matched by any
      observed endpoint — could be deprecated, not yet shipped, or just
      not exercised by whatever traffic has been captured so far.
    """
    compiled_spec = _compile_spec_patterns(spec_endpoints)
    spec_matched = set()  # indices into compiled_spec that matched at least one discovered endpoint

    shadow_endpoints = []
    for dep in discovered_endpoints:
        method = dep.get("method", "")
        uri = dep.get("uri", "")
        matched = False
        for i, (spec_method, pattern, template) in enumerate(compiled_spec):
            if spec_method == method and pattern.match(uri):
                matched = True
                spec_matched.add(i)
                # Don't break — a URI can match more than one spec pattern
                # in a loosely-specified document; every match should still
                # count toward "this spec path was observed".
        if not matched:
            shadow_endpoints.append({
                "method": method,
                "uri": uri,
                "hit_count": dep.get("hit_count", 0),
                "first_seen": dep.get("first_seen"),
                "last_seen": dep.get("last_seen"),
            })

    undocumented_spec_endpoints = [
        {"method": m, "path_template": t}
        for i, (m, _, t) in enumerate(compiled_spec)
        if i not in spec_matched
    ]

    return {
        "shadow_endpoints": sorted(shadow_endpoints, key=lambda e: e["hit_count"], reverse=True),
        "undocumented_spec_endpoints": undocumented_spec_endpoints,
        "spec_endpoint_count": len(spec_endpoints),
        "matched_spec_endpoint_count": len(spec_matched),
    }
