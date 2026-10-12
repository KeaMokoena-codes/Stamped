"""Validation tests against real public datasets in data/public_samples/ (Issue #18)."""

import sqlite3
from pathlib import Path
import pytest

from detect.datasets.openssh import parse_openssh
from ingest.parsers.auth_log import parse_and_record_auth_log
from ingest.parsers.cloudtrail_json import parse_and_record_cloudtrail
from schemas.init_db import SCHEMA_PATH
from seal.custody_log import recompute_and_verify_chain

PUBLIC_DIR = Path(__file__).resolve().parent.parent / "data" / "public_samples"


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_PATH.read_text())
    yield conn
    conn.close()


def test_public_openssh_2k_log_parses_cleanly(db_conn: sqlite3.Connection):
    openssh_path = PUBLIC_DIR / "OpenSSH_2k.log"
    assert openssh_path.is_file(), "OpenSSH_2k.log must be present in data/public_samples/"

    # Compare against detect's validation loader for exact parity
    expected = parse_openssh(openssh_path, year=2015)

    artifact_id, events, stats = parse_and_record_auth_log(
        conn=db_conn,
        file_path=openssh_path,
        source_evidence_id=expected.evidence_id,
        base_year=2015,
    )
    db_conn.commit()

    assert stats["total_lines"] == 2000
    assert stats["unparsed_lines"] == 0
    assert stats["parsed_events"] == 518
    assert stats["ignored_lines"] == 1482
    assert stats["parsed_events"] + stats["ignored_lines"] + stats["unparsed_lines"] == 2000
    assert events == expected.events

    # Confirm provenance and custody chain integrity
    assert all(e.evidence_id == expected.evidence_id for e in events)
    assert all(e.raw_ref.startswith("line:") for e in events)
    assert recompute_and_verify_chain(db_conn) == (True, None)


def test_public_cloudtrail_log_parses_cleanly(db_conn: sqlite3.Connection):
    ct_path = PUBLIC_DIR / "aws_cloudtrail_public.json"
    assert ct_path.is_file(), "aws_cloudtrail_public.json must be present in data/public_samples/"

    artifact_id, events, stats = parse_and_record_cloudtrail(
        conn=db_conn,
        file_path=ct_path,
        source_evidence_id="ev_public_cloudtrail",
    )
    db_conn.commit()

    assert stats["total_records"] >= 2
    assert stats["unparsed_records"] == 0
    assert stats["parsed_events"] == stats["total_records"]
    assert len(events) == stats["parsed_events"]

    # Verify extracted fields from real AWS sample
    assert events[0].account is not None
    assert events[0].timestamp_utc.endswith("+00:00")
    assert events[0].raw_ref == "record:0"
    assert recompute_and_verify_chain(db_conn) == (True, None)