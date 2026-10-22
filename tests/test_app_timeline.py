import sqlite3
from hashlib import sha256
from pathlib import Path

from streamlit.testing.v1 import AppTest

from ingest.parsers.auth_log import parse_and_record_auth_log
from ingest.parsers.cloudtrail_json import parse_and_record_cloudtrail
from schemas.init_db import SCHEMA_PATH

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def _run_timeline_page():
    from app.main import timeline_page

    timeline_page()


def test_timeline_page_renders_real_parser_events_and_clickable_findings(tmp_path, monkeypatch):
    database_path = tmp_path / "stamped.db"
    auth_path = tmp_path / "auth.log"
    auth_path.write_text(
        "Oct 12 10:21:00 host sshd[10]: Failed password for alice from 192.0.2.10 port 1001 ssh2\n"
    )
    cloudtrail_path = REPOSITORY_ROOT / "data" / "sample" / "cloudtrail_sample.json"

    with sqlite3.connect(database_path) as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO users (user_id, display_name, role, created_at, active) "
            "VALUES (?, ?, ?, ?, 1)",
            ("examiner-1", "Examiner One", "examiner", "2026-10-20T08:00:00+00:00"),
        )
        for evidence_id, path in (
            ("auth-evidence", auth_path),
            ("cloudtrail-evidence", cloudtrail_path),
        ):
            connection.execute(
                "INSERT INTO evidence (evidence_id, content_hash, sealed_path, sealed_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    evidence_id,
                    sha256(path.read_bytes()).hexdigest(),
                    str(path),
                    "2026-10-12T10:00:00+00:00",
                ),
            )
        parse_and_record_auth_log(connection, auth_path, "auth-evidence")
        parse_and_record_cloudtrail(connection, cloudtrail_path, "cloudtrail-evidence")
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
                "Suspicious login",
                "Finding details",
                "2026-10-12T10:23:00+00:00",
                '{"finding_id":"finding-1"}',
            ),
        )
        connection.commit()

    monkeypatch.setenv("STAMPED_DB_PATH", str(database_path))

    app = AppTest.from_function(_run_timeline_page)
    app.session_state["stamped_actor"] = "examiner-1"
    app.run(timeout=15)

    assert not app.exception
    assert any(header.value == "Timeline" for header in app.header)
    assert len(app.expander) == 5
    assert any("Finding" in expander.label and "Suspicious login" in expander.label for expander in app.expander)
    assert any("High severity finding" in alert.value for alert in app.error)
    assert app.json
