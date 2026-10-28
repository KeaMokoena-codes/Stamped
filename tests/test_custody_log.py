import ast
import hashlib
import json
import re
import sqlite3
import threading
from pathlib import Path

import pytest

from seal import custody_log
from seal.custody_log import GENESIS_PREV_HASH, append_entry, recompute_and_verify_chain

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "schema.sql"
GUARD_TRIGGERS = ("custody_log_no_update", "custody_log_no_delete", "custody_log_no_replace")


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    connection.executescript(SCHEMA_PATH.read_text())
    yield connection
    connection.close()


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "log.db"
    setup = sqlite3.connect(path)
    setup.executescript(SCHEMA_PATH.read_text())
    setup.close()
    return path


def fill(conn, n=5):
    for i in range(n):
        append_entry(
            conn, actor="ash", role="examiner", action=f"action_{i}",
            evidence_id="ev1", details={"i": i, "note": "café"},
        )
    conn.commit()


def tamper(conn, sql, args=()):
    """Run SQL as an attacker with raw DB-file access would: guards removed first."""
    for trigger in GUARD_TRIGGERS:
        conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    conn.execute(sql, args)
    conn.commit()


# ---------------------------------------------------------------------------
# Format: deterministic, documented, reproducible by someone else
# ---------------------------------------------------------------------------
# These literals were produced by a standalone script that does NOT import
# seal.*, following docs/custody-log-format.md. If either assertion fails, the
# serialisation changed, and every existing log (and the independent verifier,
# #1.5) would break. Do not "fix" the constants without a team decision.
GOLDEN_FIELDS = {
    "timestamp_utc": "2026-10-05T08:30:00+00:00",
    "actor": "ash",
    "role": "examiner",
    "action": "sealed",
    "evidence_id": "ab" * 32,
    "artifact_id": None,
    "details_json": '{"n":1,"note":"caf\\u00e9"}',
}
GOLDEN_CANONICAL = (
        '{"action":"sealed","actor":"ash","artifact_id":null,'
        '"details_json":"{\\"n\\":1,\\"note\\":\\"caf\\\\u00e9\\"}",'
        '"evidence_id":"' + "ab" * 32 + '","role":"examiner",'
                                        '"timestamp_utc":"2026-10-05T08:30:00+00:00"}'
)
GOLDEN_HASH = "2b2f3fb66296aede41737bf9d88bffac73de8abdacd9885c7716e909db27ef38"


def test_golden_vector_canonical_form_is_pinned():
    assert custody_log._canonical_json(GOLDEN_FIELDS) == GOLDEN_CANONICAL


def test_golden_vector_hash_is_pinned():
    assert custody_log._compute_entry_hash(GOLDEN_FIELDS, GENESIS_PREV_HASH) == GOLDEN_HASH


def test_canonical_json_ignores_key_insertion_order():
    reordered = dict(reversed(list(GOLDEN_FIELDS.items())))
    assert custody_log._canonical_json(reordered) == GOLDEN_CANONICAL


def test_details_key_order_does_not_change_stored_details(conn):
    append_entry(conn, "a", "examiner", "x", details={"b": 1, "a": 2})
    append_entry(conn, "a", "examiner", "x", details={"a": 2, "b": 1})
    conn.commit()
    rows = conn.execute("SELECT details_json FROM custody_log ORDER BY entry_id").fetchall()
    assert rows[0][0] == rows[1][0] == '{"a":2,"b":1}'


def test_non_ascii_is_escaped_so_output_is_pure_ascii():
    out = custody_log._canonical_json({"x": "é😀"})
    assert out == '{"x":"\\u00e9\\ud83d\\ude00"}'
    assert out.isascii()


def test_nan_and_infinity_are_rejected_and_leave_no_lock_or_row(conn):
    for bad in (float("nan"), float("inf")):
        with pytest.raises(ValueError):
            append_entry(conn, "a", "examiner", "x", details={"v": bad})
        assert conn.in_transaction is False
    assert conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0] == 0


def test_stored_chain_is_reproducible_from_the_documented_spec_alone(conn):
    """Re-derive every hash using ONLY hashlib + json, exactly as the doc says,
    with no import of seal.*. This is what the independent verifier will do."""
    fill(conn, 5)
    rows = conn.execute(
        "SELECT timestamp_utc, actor, role, action, evidence_id, artifact_id, "
        "details_json, prev_hash, entry_hash FROM custody_log ORDER BY entry_id"
    ).fetchall()

    expected_prev = "0" * 64
    for ts, actor, role, action, ev, art, details, prev, stored in rows:
        fields = {
            "timestamp_utc": ts, "actor": actor, "role": role, "action": action,
            "evidence_id": ev, "artifact_id": art, "details_json": details,
        }
        canonical = json.dumps(
            fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
        assert prev == expected_prev
        assert hashlib.sha256((canonical + prev).encode("utf-8")).hexdigest() == stored
        expected_prev = stored


# ---------------------------------------------------------------------------
# Chain behaviour
# ---------------------------------------------------------------------------
def test_genesis_entry_uses_fixed_prev_hash(conn):
    h = append_entry(conn, actor="ash", role="examiner", action="test")
    conn.commit()
    row = conn.execute("SELECT prev_hash, entry_hash FROM custody_log WHERE entry_id = 1").fetchone()
    assert row[0] == GENESIS_PREV_HASH == "0" * 64
    assert row[1] == h


def test_each_entry_links_to_the_previous_entry_hash(conn):
    fill(conn, 5)
    rows = conn.execute("SELECT prev_hash, entry_hash FROM custody_log ORDER BY entry_id").fetchall()
    assert rows[0][0] == GENESIS_PREV_HASH
    for earlier, later in zip(rows, rows[1:]):
        assert later[0] == earlier[1]


def test_appending_five_entries_then_recomputing_matches(conn):
    fill(conn, 5)
    assert recompute_and_verify_chain(conn) == (True, None)


def test_empty_log_verifies(conn):
    assert recompute_and_verify_chain(conn) == (True, None)


# ---------------------------------------------------------------------------
# Tamper detection: reported at exactly the right entry, wherever it is
# ---------------------------------------------------------------------------
TAMPER_COLUMNS = {
    "action": "'tampered'",
    "actor": "'mallory'",
    "details_json": "'{\"x\":1}'",
    "evidence_id": "'other'",
    "timestamp_utc": "'1999-01-01T00:00:00+00:00'",
    "entry_hash": "'" + "f" * 64 + "'",
    "prev_hash": "'" + "e" * 64 + "'",
}


@pytest.mark.parametrize("entry_id", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("column", sorted(TAMPER_COLUMNS))
def test_corrupting_any_field_of_any_entry_is_detected_at_that_entry(conn, entry_id, column):
    fill(conn, 5)
    tamper(conn, f"UPDATE custody_log SET {column} = {TAMPER_COLUMNS[column]} WHERE entry_id = ?", (entry_id,))
    ok, bad_entry = recompute_and_verify_chain(conn)
    assert ok is False
    assert bad_entry == entry_id  # not earlier, not later


def test_deleting_a_middle_entry_is_detected_at_the_following_entry(conn):
    fill(conn, 5)
    tamper(conn, "DELETE FROM custody_log WHERE entry_id = 3")
    assert recompute_and_verify_chain(conn) == (False, 4)


def test_reordering_entries_is_detected(conn):
    fill(conn, 5)
    tamper(conn, "UPDATE custody_log SET entry_id = 99 WHERE entry_id = 2")
    ok, _ = recompute_and_verify_chain(conn)
    assert ok is False


# These two document what the chain ALONE cannot catch. They are tests so the
# limitation is explicit and cannot be quietly forgotten or over-claimed.
def test_LIMITATION_deleting_the_newest_entries_is_not_detectable_without_an_anchor(conn):
    fill(conn, 5)
    tamper(conn, "DELETE FROM custody_log WHERE entry_id IN (4, 5)")
    assert recompute_and_verify_chain(conn) == (True, None)  # a shorter chain is still self-consistent


def test_LIMITATION_attacker_who_rewrites_every_later_hash_is_not_detected_without_an_anchor(conn):
    fill(conn, 5)
    tamper(conn, "UPDATE custody_log SET action = 'tampered' WHERE entry_id = 3")
    rows = conn.execute(
        "SELECT entry_id, timestamp_utc, actor, role, action, evidence_id, artifact_id, details_json "
        "FROM custody_log WHERE entry_id >= 3 ORDER BY entry_id"
    ).fetchall()
    prev = conn.execute("SELECT entry_hash FROM custody_log WHERE entry_id = 2").fetchone()[0]
    for entry_id, ts, actor, role, action, ev, art, details in rows:
        fields = {"timestamp_utc": ts, "actor": actor, "role": role, "action": action,
                  "evidence_id": ev, "artifact_id": art, "details_json": details}
        new_hash = custody_log._compute_entry_hash(fields, prev)
        conn.execute("UPDATE custody_log SET prev_hash = ?, entry_hash = ? WHERE entry_id = ?",
                     (prev, new_hash, entry_id))
        prev = new_hash
    conn.commit()
    # Fully self-consistent forgery: only an externally anchored head hash (#1.4) exposes it.
    assert recompute_and_verify_chain(conn) == (True, None)


# ---------------------------------------------------------------------------
# Append-only: structurally prevented, not merely discouraged
# ---------------------------------------------------------------------------
def test_database_refuses_update(conn):
    fill(conn, 3)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE custody_log SET actor = 'mallory' WHERE entry_id = 2")


def test_database_refuses_delete(conn):
    fill(conn, 3)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM custody_log WHERE entry_id = 3")


def test_database_refuses_insert_or_replace_over_an_existing_entry(conn):
    """INSERT OR REPLACE deletes the conflicting row WITHOUT firing the DELETE
    trigger, so it needs its own guard."""
    fill(conn, 3)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute(
            "INSERT OR REPLACE INTO custody_log (entry_id, timestamp_utc, actor, role, action, "
            "details_json, prev_hash, entry_hash) VALUES (2, 't', 'evil', 'r', 'a', '{}', 'p', 'h')"
        )
    prev = conn.execute("SELECT prev_hash FROM custody_log WHERE entry_id = 2").fetchone()[0]
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute(
            "INSERT OR REPLACE INTO custody_log (timestamp_utc, actor, role, action, "
            "details_json, prev_hash, entry_hash) VALUES ('t', 'evil', 'r', 'a', '{}', ?, 'h2')",
            (prev,),
        )
    assert recompute_and_verify_chain(conn) == (True, None)
    assert conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0] == 3


def test_database_refuses_a_forked_entry(conn):
    fill(conn, 3)
    head_prev = conn.execute("SELECT prev_hash FROM custody_log WHERE entry_id = 3").fetchone()[0]
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute(
            "INSERT INTO custody_log (timestamp_utc, actor, role, action, details_json, prev_hash, entry_hash) "
            "VALUES ('t', 'a', 'r', 'fork', '{}', ?, ?)", (head_prev, "d" * 64),
        )


def test_no_update_or_delete_function_exists_anywhere_in_the_codebase():
    forbidden_names = {"update_entry", "delete_entry", "edit_entry", "remove_entry"}
    forbidden_sql = re.compile(r"\bUPDATE\s+custody_log\b|\bDELETE\s+FROM\s+custody_log\b", re.I)
    skip_dirs = {".git", "tests", "node_modules", "__pycache__", ".venv", "venv", "env", "keys"}
    offenders = []
    for path in REPO_ROOT.rglob("*.py"):
        rel = path.relative_to(REPO_ROOT)
        if skip_dirs & set(rel.parts):
            continue
        source = path.read_text(errors="ignore")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in forbidden_names:
                offenders.append(f"{rel}: defines {node.name}()")
        # ci_guardrails.py quotes the forbidden SQL to look for it; run_e2e.py runs it on purpose, against
        # throwaway copies of the database, to prove the append-only trigger and the hash chain catch tampering.
        if forbidden_sql.search(source) and rel.as_posix() not in {"scripts/ci_guardrails.py", "scripts/run_e2e.py"}:
            offenders.append(f"{rel}: contains SQL that mutates custody_log")
    assert offenders == []


def test_custody_log_module_exposes_no_mutation_api():
    for name in ("update_entry", "delete_entry", "edit_entry", "remove_entry"):
        assert not hasattr(custody_log, name)


# ---------------------------------------------------------------------------
# Concurrency: two writers must never fork the chain
# ---------------------------------------------------------------------------
def test_many_concurrent_writers_produce_one_unbroken_chain(db_path):
    threads_n, per_thread = 8, 40
    errors = []

    def worker(worker_id):
        try:
            c = sqlite3.connect(db_path, timeout=30)
            for i in range(per_thread):
                append_entry(c, f"worker{worker_id}", "examiner", f"op{i}")
                c.commit()
            c.close()
        except Exception as exc:  # collect, assert after join
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    check = sqlite3.connect(db_path)
    assert check.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0] == threads_n * per_thread
    assert recompute_and_verify_chain(check) == (True, None)
    assert check.execute("SELECT COUNT(DISTINCT prev_hash) FROM custody_log").fetchone()[0] == threads_n * per_thread


def test_a_second_writer_is_blocked_not_forked_and_leaves_no_lock_behind(db_path):
    a = sqlite3.connect(db_path)
    b = sqlite3.connect(db_path, timeout=0.05)

    append_entry(a, "writer_a", "examiner", "first")          # a holds the write lock, uncommitted
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        append_entry(b, "writer_b", "examiner", "blocked")    # must fail loudly, not read a stale head
    assert b.in_transaction is False                           # b did not leave a lock/txn behind

    a.commit()
    append_entry(b, "writer_b", "examiner", "after")           # now b sees a's entry as the head
    b.commit()

    assert recompute_and_verify_chain(a) == (True, None)
    assert a.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0] == 2
    a.close()
    b.close()