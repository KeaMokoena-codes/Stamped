"""Tests for the auth.log ingestion parser (Issue #16)."""

import sqlite3
from pathlib import Path
import pytest

from ingest.parsers.auth_log import parse_and_record_auth_log
from schemas.init_db import SCHEMA_PATH


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_PATH.read_text())
    yield conn
    conn.close()


@pytest.fixture
def sample_auth_file(tmp_path: Path):
    log_content = (
        "Oct 12 10:14:00 workstation sshd[1200]: Failed password for invalid user admin from 192.168.1.50 port 4422 ssh2\n"
        "Oct 12 10:14:15 workstation sshd[1200]: Failed password for root from 192.168.1.50 port 4423 ssh2\n"
        "Oct 12 10:15:00 workstation sshd[1205]: Accepted password for abdi from 192.168.1.20 port 5010 ssh2\n"
        "Oct 12 10:16:00 workstation sshd[1210]: Received disconnect from 192.168.1.50: 11: Bye [preauth]\n"
        "Random unparseable garbage line that must increment unparsed counter\n"
    )
    p = tmp_path / "auth.log"
    p.write_text(log_content)
    return p


def test_auth_log_parser_generates_events_and_artifact(
    db_conn: sqlite3.Connection, sample_auth_file: Path
):
    evidence_id = "ev_test_123"
    artifact_id, events, stats = parse_and_record_auth_log(
        conn=db_conn,
        file_path=sample_auth_file,
        source_evidence_id=evidence_id,
        base_year=2026,
    )
    db_conn.commit()

    # Verify event parsing and line reporting
    assert stats["parsed_events"] == 3
    assert stats["unparsed_lines"] == 1
    assert len(events) == 3

    assert events[0].outcome == "failure"
    assert events[0].account == "admin"
    assert events[0].source_ip == "192.168.1.50"
    assert events[0].raw_ref == "line:1"

    assert events[2].outcome == "success"
    assert events[2].account == "abdi"
    assert events[2].source_ip == "192.168.1.20"
    assert events[2].raw_ref == "line:3"

    # Verify artifacts table registration
    row = db_conn.execute(
        "SELECT artifact_id, source_evidence_id, tool_name FROM artifacts WHERE artifact_id = ?",
        (artifact_id,),
    ).fetchone()
    assert row is not None
    assert row[1] == evidence_id
    assert row[2] == "auth_log_parser"

    # Verify custody log append
    log_entry = db_conn.execute(
        "SELECT action, artifact_id, evidence_id FROM custody_log WHERE artifact_id = ?",
        (artifact_id,),
    ).fetchone()
    assert log_entry is not None
    assert log_entry[0] == "parsed_auth_log"
    assert log_entry[1] == artifact_id
    assert log_entry[2] == evidence_id