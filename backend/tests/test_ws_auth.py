"""Tests for the /logs/stream WebSocket handshake auth (Module 3).

Regression guard for a real bug: this route previously inherited a
router-level CSRF dependency that crashed on every connection attempt
(verify_csrf_token() expects an HTTP Request, not a WebSocket), and had
no authentication at all once that was fixed naively.
"""
from starlette.testclient import WebSocketDisconnect


def test_websocket_rejects_missing_session_cookie(client):
    try:
        with client.websocket_connect("/logs/stream") as ws:
            ws.receive_text()
        assert False, "expected the connection to be rejected"
    except WebSocketDisconnect:
        pass


def test_websocket_rejects_garbage_token(client):
    client.cookies.set("waf_session_v3", "garbage.invalid.token")
    try:
        with client.websocket_connect("/logs/stream") as ws:
            ws.receive_text()
        assert False, "expected the connection to be rejected"
    except WebSocketDisconnect:
        pass


def test_websocket_accepts_valid_session(admin_session):
    client, _csrf, _user = admin_session
    with client.websocket_connect("/logs/stream") as ws:
        # Connection accepted and stays open (server is push-only; there's
        # nothing to receive without a triggered event, so just tear down
        # cleanly without reading — the important assertion is that
        # __enter__ didn't raise).
        pass
