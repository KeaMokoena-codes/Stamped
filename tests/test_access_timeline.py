import json
import sqlite3
from hashlib import sha256
from pathlib import Path

import pytest

from access import Pseudonymizer, Role, export_timeline_from_db, get_timeline_from_db
from access.data import TimelineSourceError
from ingest.parsers.auth_log import parse_and_record_auth_log
from ingest.parsers.cloudtrail_json import parse_and_record_cloudtrail
from schemas.init_db import SCHEMA_PATH


@pytest.fixture
def conn(tmp_path):
    connection = sqlite3.connect(":memory:")
    connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    auth_path = tmp_path / "auth.log"
    auth_path.write_text(
        "Oct 12 10:21:00 host sshd[10]: Failed password for alice from 192.0.2.10 port 1001 ssh2\n"
        "Oct 12 10:22:00 host sshd[11]: Failed password for alice from 192.0.2.10 port 1002 ssh2\n"
    )
    cloudtrail_path = tmp_path / "cloudtrail.json"
    cloudtrail_path.write_bytes(
        (Path(__file__).resolve().parent.parent / "data" / "sample" / "cloudtrail_sample.json")
        .read_bytes()
    )

    for evidence_id, path in (("auth-evidence", auth_path), ("cloudtrail-evidence", cloudtrail_path)):
        raw_bytes = path.read_bytes()
        connection.execute(
            "INSERT INTO evidence (evidence_id, content_hash, sealed_path, sealed_at) "
            "VALUES (?, ?, ?, ?)",
            (
                evidence_id,
                sha256(raw_bytes).hexdigest(),
                str(path),
                "2026-10-12T10:00:00+00:00",
            ),
        )
    parse_and_record_auth_log(
        connection, auth_path, "auth-evidence", base_year=2026
    )
    parse_and_record_cloudtrail(
        connection, cloudtrail_path, "cloudtrail-evidence"
    )
    connection.execute(
        "INSERT INTO findings (finding_id, source_evidence_id, artifact_id, rule_id, severity, "
        "title, description, created_at, details_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "finding-1",
            "auth-evidence",
            "finding-artifact-1",
            "test_rule@1",
            "high",
            "Suspicious login for alice",
            "A finding linked to parser event provenance",
            "2026-10-12T10:23:00+00:00",
            json.dumps({"finding_id": "finding-1", "source_evidence_id": "auth-evidence"}),
        ),
    )
    connection.commit()
    yield connection, auth_path
    connection.close()


def test_timeline_from_database_replays_both_parser_artifacts_and_merges_findings(conn):
    connection, _ = conn

    rows = get_timeline_from_db(connection, Role.EXAMINER, "tester")

    assert {row["entry_type"] for row in rows} == {"event", "finding"}
    assert any(row["provenance"].get("evidence_id") == "auth-evidence" for row in rows)
    assert any(row["provenance"].get("evidence_id") == "cloudtrail-evidence" for row in rows)
    assert any(row["provenance"].get("finding_id") == "finding-1" for row in rows)
    timestamps = [row["timestamp_utc"] for row in rows]
    assert timestamps == sorted(timestamps)
    assert connection.execute(
        "SELECT action FROM custody_log ORDER BY entry_id DESC LIMIT 1"
    ).fetchone()[0] == "viewed_timeline"


def test_timeline_from_database_applies_role_projection(conn):
    connection, _ = conn
    pseudonymizer = Pseudonymizer(b"timeline-test-key-0123456789")

    rows = get_timeline_from_db(
        connection,
        Role.PROSECUTOR,
        "tester",
        pseudonymizer=pseudonymizer,
    )
    auth_event = next(
        row
        for row in rows
        if row["entry_type"] == "event"
        and row["provenance"]["evidence_id"] == "auth-evidence"
    )

    assert auth_event["account"] == pseudonymizer.token("account", "alice")
    assert auth_event["source_ip"] == pseudonymizer.token("ip", "192.0.2.10")
    assert "sealed_path" not in json.dumps(rows)


def test_timeline_from_database_refuses_changed_sealed_source(conn):
    connection, auth_path = conn
    auth_path.write_text("tampered source bytes\n")

    with pytest.raises(TimelineSourceError, match="input hash"):
        get_timeline_from_db(connection, Role.EXAMINER, "tester")


def test_timeline_from_database_can_filter_to_one_evidence_item(conn):
    connection, _ = conn

    rows = get_timeline_from_db(
        connection, Role.EXAMINER, "tester", evidence_id="cloudtrail-evidence"
    )

    assert rows
    assert all(
        row["provenance"].get("evidence_id") == "cloudtrail-evidence"
        for row in rows
        if row["entry_type"] == "event"
    )
    assert not any(
        row["entry_type"] == "event"
        and row["provenance"]["evidence_id"] == "auth-evidence"
        for row in rows
    )


def test_timeline_report_exports_the_same_persisted_parser_pipeline(conn):
    connection, _ = conn

    report = export_timeline_from_db(connection, Role.EXAMINER, "tester")
    exported = json.loads(report.content)

    assert report.row_count == len(exported["rows"])
    assert {row["entry_type"] for row in exported["rows"]} == {"event", "finding"}
    assert any(
        row["provenance"].get("evidence_id") == "auth-evidence"
        for row in exported["rows"]
    )
    assert any(
        row["provenance"].get("evidence_id") == "cloudtrail-evidence"
        for row in exported["rows"]
    )
