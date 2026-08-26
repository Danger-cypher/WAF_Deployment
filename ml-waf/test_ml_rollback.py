from fastapi.testclient import TestClient

import ml_server

client = TestClient(ml_server.app)


def test_malformed_timestamp_rejected_before_touching_disk():
    # Would previously have been built straight into a backup filename and
    # passed to pickle.load — this must never reach that far.
    resp = client.post("/models/rollback", json={"timestamp": "../../../../tmp/evil"})
    assert resp.status_code == 400


def test_empty_timestamp_rejected():
    resp = client.post("/models/rollback", json={"timestamp": ""})
    assert resp.status_code == 400


def test_well_formed_but_nonexistent_timestamp_still_reaches_not_found():
    # A validly-shaped timestamp with no matching backup files should fall
    # through the regex check untouched and hit the existing not-found path.
    resp = client.post("/models/rollback", json={"timestamp": "19990101-000000"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "error"
    assert "not found" in resp.json()["message"]
