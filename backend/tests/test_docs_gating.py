"""
Regression tests for audit finding P2-11: FastAPI's default /docs (Swagger
UI), /redoc and /openapi.json were live and reachable with zero
authentication — confirmed against the running deployment before this fix
(all three returned 200 to a bare curl with no session). That hands anyone
a complete map of the API surface: every route, parameter name and response
schema, unauthenticated recon for free.

Fix: FastAPI(docs_url=None, redoc_url=None, openapi_url=None) disables the
built-ins; the same three paths are re-registered in main.py behind
Depends(require_admin). The CSP middleware also special-cases these three
paths to allow the jsdelivr CDN Swagger UI/ReDoc load their bundle from —
otherwise the blanket `default-src 'none'` every other response gets would
leave an authenticated admin looking at a blank page.
"""
import pytest


DOC_PATHS = ["/docs", "/redoc", "/openapi.json"]


@pytest.mark.parametrize("path", DOC_PATHS)
def test_docs_paths_require_auth(client, path):
    r = client.get(path)
    assert r.status_code in (401, 403), (path, r.status_code)


@pytest.mark.parametrize("path", DOC_PATHS)
def test_docs_paths_reachable_by_admin(admin_session, path):
    client, _csrf, _user = admin_session
    r = client.get(path)
    assert r.status_code == 200, (path, r.status_code, r.text[:200])


@pytest.mark.parametrize("path", DOC_PATHS)
def test_docs_paths_not_reachable_by_analyst(analyst_session, path):
    # require_admin, not require_any_role — a read-only analyst gets the
    # same map of every mutating route an attacker would want, so this must
    # stay admin-only.
    client, _csrf, _user = analyst_session
    r = client.get(path)
    assert r.status_code == 403, (path, r.status_code)


def test_openapi_json_is_the_real_schema(admin_session):
    client, _csrf, _user = admin_session
    r = client.get("/openapi.json")
    assert r.status_code == 200
    body = r.json()
    assert "paths" in body
    # Sanity: the schema actually describes real routes, not an empty stub.
    assert any("/users" in p for p in body["paths"])


@pytest.mark.parametrize("path", DOC_PATHS)
def test_docs_paths_get_a_cdn_allowing_csp(admin_session, path):
    client, _csrf, _user = admin_session
    r = client.get(path)
    csp = r.headers.get("content-security-policy", "")
    assert "cdn.jsdelivr.net" in csp


def test_other_routes_keep_the_strict_csp(admin_session):
    client, _csrf, _user = admin_session
    r = client.get("/health")
    csp = r.headers.get("content-security-policy", "")
    assert csp == "default-src 'none'; frame-ancestors 'none';"
