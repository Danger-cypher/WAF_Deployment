import sqlite3
import importlib

import collect_data


def _make_db(tmp_path, monkeypatch, rows):
    """Create an isolated ml_events.db with (decision, admin_label) rows and
    repoint collect_data at it."""
    db_path = str(tmp_path / "ml_events.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE ml_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision TEXT, admin_label TEXT
        )
        """
    )
    for decision, admin_label in rows:
        conn.execute(
            "INSERT INTO ml_events (decision, admin_label) VALUES (?, ?)",
            (decision, admin_label),
        )
    conn.commit()
    conn.close()

    monkeypatch.setenv("ML_DB_PATH", db_path)
    importlib.reload(collect_data)
    return db_path


def test_confirmed_false_positive_moves_to_benign(tmp_path, monkeypatch):
    _make_db(tmp_path, monkeypatch, rows=[
        ("block", "false_positive"),
        ("block", "true_positive"),
        ("block", None),
        ("allow", None),
    ])
    benign, attack = collect_data.get_training_datasets()

    assert len(benign) == 2  # the confirmed false_positive block + the allow
    assert len(attack) == 2  # true_positive block + unreviewed block


def test_reviewed_rows_get_full_weight_unreviewed_get_down_weighted(tmp_path, monkeypatch):
    _make_db(tmp_path, monkeypatch, rows=[
        ("block", "true_positive"),
        ("block", None),
        ("allow", None),
    ])
    benign, attack = collect_data.get_training_datasets()

    reviewed = [r for r in attack if r["admin_label"] == "true_positive"]
    unreviewed_attack = [r for r in attack if r["admin_label"] is None]
    unreviewed_benign = [r for r in benign if r["admin_label"] is None]

    assert all(r["_training_weight"] == collect_data.REVIEWED_WEIGHT for r in reviewed)
    assert all(r["_training_weight"] == collect_data.SELF_LABELED_WEIGHT for r in unreviewed_attack)
    assert all(r["_training_weight"] == collect_data.SELF_LABELED_WEIGHT for r in unreviewed_benign)


def test_import_does_not_require_opensearchpy():
    # opensearchpy is intentionally absent from requirements.txt — importing
    # this module (as train_xgb.py does) must not raise ModuleNotFoundError.
    importlib.reload(collect_data)
    assert collect_data.connect_opensearch() is None


def _make_db_with_signature(tmp_path, monkeypatch, rows):
    """Same as _make_db but with uri/method/args columns, for tests of the
    duplicate-signature poisoning cap (which needs a real signature to cap
    on, not just decision/admin_label)."""
    db_path = str(tmp_path / "ml_events.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE ml_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision TEXT, admin_label TEXT, uri TEXT, method TEXT, args TEXT
        )
        """
    )
    for decision, admin_label, uri, method, args in rows:
        conn.execute(
            "INSERT INTO ml_events (decision, admin_label, uri, method, args) VALUES (?, ?, ?, ?, ?)",
            (decision, admin_label, uri, method, args),
        )
    conn.commit()
    conn.close()

    monkeypatch.setenv("ML_DB_PATH", db_path)
    importlib.reload(collect_data)
    return db_path


def test_duplicate_unreviewed_signature_capped(tmp_path, monkeypatch):
    rows = [("allow", None, "/search", "GET", "q=hello") for _ in range(30)]
    _make_db_with_signature(tmp_path, monkeypatch, rows=rows)
    benign, _ = collect_data.get_training_datasets()

    assert len(benign) == collect_data.MAX_DUPLICATE_UNREVIEWED_SAMPLES


def test_reviewed_duplicate_signature_not_capped(tmp_path, monkeypatch):
    # A human vouched for each of these individually (admin_label set) —
    # the cap only bounds what an attacker can force through unreviewed.
    rows = [("block", "false_positive", "/search", "GET", "q=hello") for _ in range(30)]
    _make_db_with_signature(tmp_path, monkeypatch, rows=rows)
    benign, _ = collect_data.get_training_datasets()

    assert len(benign) == 30


def test_distinct_signatures_each_get_their_own_cap_budget(tmp_path, monkeypatch):
    rows = (
        [("allow", None, "/a", "GET", "") for _ in range(25)]
        + [("allow", None, "/b", "GET", "") for _ in range(25)]
    )
    _make_db_with_signature(tmp_path, monkeypatch, rows=rows)
    benign, _ = collect_data.get_training_datasets()

    assert len(benign) == 2 * collect_data.MAX_DUPLICATE_UNREVIEWED_SAMPLES
    a_rows = [r for r in benign if r["uri"] == "/a"]
    b_rows = [r for r in benign if r["uri"] == "/b"]
    assert len(a_rows) == collect_data.MAX_DUPLICATE_UNREVIEWED_SAMPLES
    assert len(b_rows) == collect_data.MAX_DUPLICATE_UNREVIEWED_SAMPLES


def test_under_cap_threshold_unaffected(tmp_path, monkeypatch):
    rows = [("allow", None, "/search", "GET", "q=hello") for _ in range(5)]
    _make_db_with_signature(tmp_path, monkeypatch, rows=rows)
    benign, _ = collect_data.get_training_datasets()

    assert len(benign) == 5
