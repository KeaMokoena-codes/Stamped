"""Tests for the CloudTrail JSON parser (Issue #17)."""

import sqlite3
from pathlib import Path
import pytest

from ingest.parsers.cloudtrail_json import parse_and_record_cloudtrail
from schemas.init_db import SCHEMA_PATH


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_PATH.read_text())
    yield conn
    conn.close()


def test_cloudtrail_sample_fixture_parses_correctly(db_conn: sqlite3.Connection):
    sample_file = (
        Path(__file__).resolve().parent.parent / "data" / "sample" / "cloudtrail_sample.json"
    )
    assert sample_file.exists(), "Sample CloudTrail fixture must exist"

    evidence_id = "ev_cloudtrail_001"
    artifact_id, events, stats = parse_and_record_cloudtrail(
        conn=db_conn,
        file_path=sample_file,
        source_evidence_id=evidence_id,
    )
    db_conn.commit()

    assert stats["parsed_events"] == 3
    assert stats["unparsed_records"] == 0
    assert len(events) == 3

    # Check failure mapping
    assert events[0].outcome == "failure"
    assert events[0].account == "admin"
    assert events[0].source_ip == "192.168.1.50"
    assert events[0].raw_ref == "record:0"

    # Check success mapping
    assert events[1].outcome == "success"
    assert events[1].account == "abdi"
    assert events[1].source_ip == "192.168.1.20"
    assert events[1].raw_ref == "record:1"

    # Check database persistence
    artifact_row = db_conn.execute(
        "SELECT tool_name, source_evidence_id FROM artifacts WHERE artifact_id = ?",
        (artifact_id,),
    ).fetchone()
    assert artifact_row is not None
    assert artifact_row[0] == "cloudtrail_json_parser"
    assert artifact_row[1] == evidence_id

    # Check custody log
    custody_row = db_conn.execute(
        "SELECT action, evidence_id FROM custody_log WHERE artifact_id = ?",
        (artifact_id,),
    ).fetchone()
    assert custody_row is not None
    assert custody_row[0] == "parsed_cloudtrail_log"