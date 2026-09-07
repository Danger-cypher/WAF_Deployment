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


def _resolve_local_ref(doc: Dict[str, Any], ref: str) -> Optional[Dict[str, Any]]:
    """
    Resolves a same-document JSON-pointer $ref (OpenAPI 3.x's
    '#/components/schemas/Foo', Swagger 2.0's '#/definitions/Foo'). Returns
    None for anything else — an external ref (a URL, or a path outside
    this document) is deliberately never followed: this parser runs on
    admin-uploaded spec content, and fetching an arbitrary URL embedded in
    that content to resolve a $ref would be an SSRF vector. An unresolved
    ref just means "no field-level schema available for this operation",
    same as if the spec had no requestBody at all — never an error.
    """
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: Any = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")  # JSON Pointer escaping
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def _resolve_schema(doc: Dict[str, Any], schema: Any, _depth: int = 0) -> Optional[Dict[str, Any]]:
    """Follows local $ref indirection (a schema can $ref another schema
    that itself $refs a third). _depth caps this at a small constant so a
    circular reference in a malformed/hostile upload can't hang the
    parser — real specs never nest more than one or two levels deep."""
    if not isinstance(schema, dict):
        return None
    if _depth > 5:
        return None
    if "$ref" in schema:
        resolved = _resolve_local_ref(doc, schema["$ref"])
        if resolved is None:
            return None
        return _resolve_schema(doc, resolved, _depth + 1)
    return schema


# JSON Schema type -> schema_validate.lua's field_types.type. "integer" and
# "number" both collapse to Lua's single numeric type (Lua doesn't
# distinguish int/float); "array"/"object"/unset have no equivalent check
# in schema_validate.lua and are left unconstrained rather than guessed at.
_JSON_SCHEMA_TYPE_MAP = {"string": "string", "integer": "number", "number": "number", "boolean": "boolean"}


def _field_type_spec(prop_schema: Any) -> Optional[Dict[str, Any]]:
    """Converts one JSON Schema property definition into one field_types
    entry (routes/apps.py's ApiFieldTypeSpec shape), or None if there's
    nothing this importer can represent (object/array/untyped properties,
    or no schema at all)."""
    if not isinstance(prop_schema, dict):
        return None

    enum_vals = prop_schema.get("enum")
    if isinstance(enum_vals, list) and enum_vals:
        return {"type": "enum", "enum": enum_vals}

    lua_type = _JSON_SCHEMA_TYPE_MAP.get(prop_schema.get("type"))
    if not lua_type:
        return None

    spec: Dict[str, Any] = {"type": lua_type}
    if lua_type == "string":
        max_len = prop_schema.get("maxLength")
        if isinstance(max_len, int) and max_len > 0:
            spec["max_length"] = max_len
        pattern = prop_schema.get("pattern")
        if isinstance(pattern, str) and pattern:
            spec["pattern"] = pattern
    return spec


def _request_body_schema(doc: Dict[str, Any], operation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extracts + resolves one operation's JSON request-body schema,
    whichever form this document uses: OpenAPI 3.x
    (requestBody.content['application/json'].schema) or Swagger 2.0 (a
    `parameters` entry with in: 'body'). None if this operation has no
    JSON body (a GET, or a body of some other content type)."""
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            json_content = content.get("application/json")
            if isinstance(json_content, dict):
                return _resolve_schema(doc, json_content.get("schema"))

    for param in operation.get("parameters", []) or []:
        if isinstance(param, dict) and param.get("in") == "body":
            return _resolve_schema(doc, param.get("schema"))

    return None


def extract_positive_security_schema(content: str) -> Dict[str, Any]:
    """
    Parses an OpenAPI 3.x/Swagger 2.0 document into schema_validate.lua's
    per-app endpoint-declaration format (routes/apps.py's
    ApiSchemaEndpoint list, PUT /apps/{id}/schema) — reuses
    _load_document() for the same safe JSON/YAML parsing as parse_spec()
    above. Returns a PREVIEW only; nothing is written to Redis or the DB
    here — the caller (routes/apps.py) hands this back to the admin to
    review/edit, same "never auto-apply" convention as this codebase's
    other suggestion-generating features (e.g. Auto-Learning), and the
    actual save still goes through PUT /apps/{id}/schema's existing
    validation, not a second copy of it here.

    Deliberately excludes any path containing a {parameter} template
    segment: schema_validate.lua's find_endpoint() does an EXACT string
    match against the request URI, with no path-templating support —
    importing "/users/{id}" as a literal endpoint would silently produce a
    rule that can never match real traffic ("/users/42"). An admin seeing
    it in the schema list would reasonably assume it's being enforced,
    which would be worse than not importing it — so it's reported in
    `skipped` instead, visible rather than silently dropped.

    Raises ValueError on anything unparseable, same convention as
    parse_spec() (caller turns this into a 400, not a 500).
    """
    doc = _load_document(content)

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("No 'paths' object found — doesn't look like an OpenAPI/Swagger document.")

    endpoints: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []

    for path_template, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        if "{" in path_template:
            for method in path_item.keys():
                if method.lower() in _VALID_HTTP_METHODS:
                    skipped.append({
                        "method": method.upper(),
                        "path": path_template,
                        "reason": "templated path — this WAF's schema enforcement only matches exact, literal paths",
                    })
            continue

        for method, operation in path_item.items():
            if method.lower() not in _VALID_HTTP_METHODS or not isinstance(operation, dict):
                continue

            entry: Dict[str, Any] = {
                "method": method.upper(),
                "path": path_template,
                "required_fields": [],
                "allowed_fields": [],
                "field_types": {},
            }

            body_schema = _request_body_schema(doc, operation)
            if isinstance(body_schema, dict) and body_schema.get("type", "object") == "object":
                properties = body_schema.get("properties")
                if isinstance(properties, dict) and properties:
                    required = body_schema.get("required")
                    if isinstance(required, list):
                        entry["required_fields"] = [f for f in required if isinstance(f, str)]

                    # Only a strict allowlist when the spec itself says so —
                    # JSON Schema's default is additionalProperties: true,
                    # so populating this from `properties` regardless would
                    # turn every imported endpoint into a stricter contract
                    # than the spec actually declares, rejecting legitimate
                    # extra fields the real API accepts.
                    if body_schema.get("additionalProperties") is False:
                        entry["allowed_fields"] = list(properties.keys())

                    field_types = {}
                    for prop_name, prop_schema in properties.items():
                        spec = _field_type_spec(prop_schema)
                        if spec:
                            field_types[prop_name] = spec
                    entry["field_types"] = field_types

            endpoints.append(entry)

    return {"endpoints": endpoints, "skipped": skipped}


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
