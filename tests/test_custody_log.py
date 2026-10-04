import sqlite3
from pathlib import Path

import pytest

from seal.custody_log import GENESIS_PREV_HASH, append_entry, recompute_and_verify_chain

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "schema.sql"


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    connection.executescript(SCHEMA_PATH.read_text())
    yield connection
    connection.close()


def test_genesis_entry_uses_fixed_prev_hash(conn):
    h = append_entry(conn, actor="ash", role="examiner", action="test")
    conn.commit()
    row = conn.execute("SELECT prev_hash, entry_hash FROM custody_log WHERE entry_id = 1").fetchone()
    assert row[0] == GENESIS_PREV_HASH
    assert row[1] == h


def test_appending_five_entries_then_recomputing_matches(conn):
    for i in range(5):
        append_entry(conn, actor="ash", role="examiner", action=f"action_{i}")
    conn.commit()

    ok, bad_entry = recompute_and_verify_chain(conn)
    assert ok is True
    assert bad_entry is None


def test_corrupting_an_entry_is_detected_at_the_right_point(conn):
    for i in range(5):
        append_entry(conn, actor="ash", role="examiner", action=f"action_{i}")
    conn.commit()

    # Corrupt entry 3's action after the fact (simulating tampering).
    conn.execute("UPDATE custody_log SET action = 'tampered' WHERE entry_id = 3")
    conn.commit()

    ok, bad_entry = recompute_and_verify_chain(conn)
    assert ok is False
    assert bad_entry == 3


def test_no_update_or_delete_functions_exist():
    import seal.custody_log as module
    assert not hasattr(module, "update_entry")
    assert not hasattr(module, "delete_entry")