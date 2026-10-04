import sqlite3
from pathlib import Path

import pytest

from schemas.init_db import init_db

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "schema.sql"
EXPECTED_TABLES = {
    "evidence",
    "custody_log",
    "artifacts",
    "findings",
    "anchors",
    "users",
}


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    connection.executescript(SCHEMA_PATH.read_text())
    yield connection
    connection.close()


def test_schema_creates_all_shared_tables(conn):
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    assert EXPECTED_TABLES <= tables


def test_custody_log_has_required_fields_and_no_foreign_keys(conn):
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(custody_log)")
    }
    assert {
        "entry_id",
        "timestamp_utc",
        "actor",
        "role",
        "action",
        "evidence_id",
        "artifact_id",
        "details_json",
        "prev_hash",
        "entry_hash",
    } <= columns
    assert list(conn.execute("PRAGMA foreign_key_list(custody_log)")) == []


def test_artifacts_require_exactly_one_source(conn):
    insert = """
        INSERT INTO artifacts (
            artifact_id, source_evidence_id, source_artifact_id, tool_name,
            tool_version, created_at, input_hash, output_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    common = ("parser", "1.0", "2026-10-04T00:00:00+00:00", "input", "output")

    conn.execute(insert, ("from-evidence", "evidence-hash", None, *common))
    conn.execute(insert, ("from-artifact", None, "parent-artifact", *common))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(insert, ("without-source", None, None, *common))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(insert, ("two-sources", "evidence-hash", "parent-artifact", *common))


def test_init_db_creates_fresh_database_with_empty_tables(tmp_path):
    db_path = tmp_path / "fresh" / "stamped.db"
    init_db(db_path)

    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert EXPECTED_TABLES <= tables
        for table in EXPECTED_TABLES:
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
