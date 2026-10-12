"""Unit and integration tests for ingest/timeline.py (Issue #19)."""

import sqlite3
from pathlib import Path
import pytest

from detect.findings import detect_and_record
from detect.rules.brute_force import BruteForceConfig, detect
from ingest.parsers.auth_log import parse_and_record_auth_log
from ingest.parsers.cloudtrail_json import parse_and_record_cloudtrail
from ingest.timeline import build_timeline, load_findings_from_db, normalize_utc_timestamp
from schemas.init_db import SCHEMA_PATH
from schemas.normalized_event import NormalizedEvent, make_event_id


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_PATH.read_text())
    yield conn
    conn.close()


def test_chronological_order_and_provenance_preserved():
    ev_late = NormalizedEvent(
        event_id=make_event_id("ev_1", "line:2"),
        evidence_id="ev_1",
        raw_ref="line:2",
        timestamp_utc="2026-10-12T10:30:00+00:00",
        event_type="auth",
        outcome="success",
        account="alice",
        source_ip="10.0.0.1",
        service="ssh",
    )
    ev_early = NormalizedEvent(
        event_id=make_event_id("ev_1", "line:1"),
        evidence_id="ev_1",
        raw_ref="line:1",
        timestamp_utc="2026-10-12T10:00:00+00:00",
        event_type="auth",
        outcome="failure",
        account="alice",
        source_ip="10.0.0.1",
        service="ssh",
    )

    timeline = build_timeline([ev_late, ev_early])
    assert len(timeline) == 2
    assert [t["id"] for t in timeline] == [ev_early.event_id, ev_late.event_id]
    assert timeline[0]["provenance"] == {
        "evidence_id": "ev_1",
        "raw_ref": "line:1",
        "event_id": ev_early.event_id,
    }
    assert timeline[1]["provenance"] == {
        "evidence_id": "ev_1",
        "raw_ref": "line:2",
        "event_id": ev_late.event_id,
    }


def test_timezone_offsets_are_normalized_to_utc_before_sorting():
    """
    Guardrail check: 12:00+02:00 is 10:00 UTC, which must sort BEFORE 10:30Z.
    A naive string sort would place '12:00+02:00' after '10:30Z'.
    """
    ev_sast = NormalizedEvent(
        event_id=make_event_id("ev_tz", "line:1"),
        evidence_id="ev_tz",
        raw_ref="line:1",
        timestamp_utc="2026-10-12T12:00:00+02:00",  # 10:00:00 UTC
        event_type="auth",
        outcome="failure",
        account="abdi",
        source_ip="192.168.1.10",
        service="ssh",
    )
    ev_utc = NormalizedEvent(
        event_id=make_event_id("ev_tz", "record:0"),
        evidence_id="ev_tz",
        raw_ref="record:0",
        timestamp_utc="2026-10-12T10:30:00Z",  # 10:30:00 UTC
        event_type="auth",
        outcome="success",
        account="abdi",
        source_ip="192.168.1.10",
        service="signin.amazonaws.com",
    )

    timeline = build_timeline([ev_utc, ev_sast])
    assert [t["id"] for t in timeline] == [ev_sast.event_id, ev_utc.event_id]
    assert timeline[0]["timestamp_utc"] == "2026-10-12T10:00:00+00:00"
    assert timeline[1]["timestamp_utc"] == "2026-10-12T10:30:00+00:00"


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        normalize_utc_timestamp("2026-10-12T10:00:00")


def test_unified_timeline_merges_both_parsers_and_findings(
    db_conn: sqlite3.Connection, tmp_path: Path
):
    auth_file = tmp_path / "auth.log"
    auth_file.write_text(
        "Oct 12 10:21:00 host sshd[10]: Failed password for admin from 192.168.1.50 port 1001 ssh2\n"
        "Oct 12 10:22:00 host sshd[11]: Failed password for admin from 192.168.1.50 port 1002 ssh2\n"
        "Oct 12 10:23:00 host sshd[12]: Failed password for admin from 192.168.1.50 port 1003 ssh2\n"
        "Oct 12 10:24:00 host sshd[13]: Accepted password for admin from 192.168.1.50 port 1004 ssh2\n"
    )
    ct_sample = Path(__file__).resolve().parent.parent / "data" / "sample" / "cloudtrail_sample.json"

    _, auth_events, _ = parse_and_record_auth_log(
        db_conn, auth_file, source_evidence_id="ev_auth", base_year=2026
    )
    _, ct_events, _ = parse_and_record_cloudtrail(
        db_conn, ct_sample, source_evidence_id="ev_ct"
    )
    db_conn.commit()

    combined_events = auth_events + ct_events
    cfg = BruteForceConfig(threshold=3, window_seconds=300, success_follow_seconds=300)
    detect_and_record(db_conn, combined_events, cfg)

    db_findings = load_findings_from_db(db_conn)
    assert len(db_findings) >= 1

    timeline = build_timeline(combined_events, db_findings)
    assert len(timeline) == len(combined_events) + len(db_findings)

    # Verify monotonic UTC timestamps across the entire merged timeline
    timestamps = [t["timestamp_utc"] for t in timeline]
    assert timestamps == sorted(timestamps)

    # Verify both events and findings exist and retain provenance
    event_items = [t for t in timeline if t["entry_type"] == "event"]
    finding_items = [t for t in timeline if t["entry_type"] == "finding"]
    assert len(event_items) == len(combined_events)
    assert len(finding_items) == len(db_findings)

    for f_item in finding_items:
        prov = f_item["provenance"]
        assert prov["finding_id"]
        assert prov["input_hash"]
        assert len(prov["source_events"]) >= 3
        assert set(prov["evidence_ids"]) <= {"ev_auth", "ev_ct"}