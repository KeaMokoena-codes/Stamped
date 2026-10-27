import json
import sqlite3
from pathlib import Path

from streamlit.testing.v1 import AppTest

from seal.custody_log import append_entry

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "schema.sql"
APP_PATH = REPOSITORY_ROOT / "app" / "main.py"


def _run_case_overview():
    from app.main import case_overview

    case_overview()


def _run_findings_page():
    from app.main import findings_page

    findings_page()


def _run_timeline_page():
    from app.main import timeline_page

    timeline_page()


def _run_custody_history_page():
    from app.main import custody_history_page

    custody_history_page()


def _run_reports_page():
    from app.main import reports_page

    reports_page()


def _create_app_db(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO users (user_id, display_name, role, created_at, active) "
            "VALUES (?, ?, ?, ?, 1)",
            ("examiner-1", "Examiner One", "examiner", "2026-10-20T08:00:00+00:00"),
        )
        connection.execute(
            "INSERT INTO users (user_id, display_name, role, created_at, active) "
            "VALUES (?, ?, ?, ?, 1)",
            (
                "officer-1",
                "Officer One",
                "investigating_officer",
                "2026-10-20T08:00:00+00:00",
            ),
        )
        connection.execute(
            "INSERT INTO users (user_id, display_name, role, created_at, active) "
            "VALUES (?, ?, ?, ?, 1)",
            (
                "prosecutor-1",
                "Prosecutor One",
                "prosecutor",
                "2026-10-20T08:00:00+00:00",
            ),
        )


def test_app_shows_an_explicit_empty_database_login_state(tmp_path, monkeypatch):
    db_path = tmp_path / "stamped.db"
    _create_app_db(db_path)
    monkeypatch.setenv("STAMPED_DB_PATH", str(db_path))

    app = AppTest.from_file(str(APP_PATH)).run(timeout=15)
    assert not app.exception
    assert any("add an active user" in info.value for info in app.info)
    assert not app.dataframe


def test_registered_login_opens_real_case_views_without_mock_data(tmp_path, monkeypatch):
    db_path = tmp_path / "stamped.db"
    _create_app_db(db_path)
    monkeypatch.setenv("STAMPED_DB_PATH", str(db_path))

    app = AppTest.from_file(str(APP_PATH)).run(timeout=15)
    app.text_input(key="stamped_login_user_id").set_value("examiner-1")
    app.button[0].click()
    app.run(timeout=15)

    assert not app.exception
    assert any(header.value == "Case overview" for header in app.header)
    assert any(metric.label == "Evidence items" and metric.value == "0" for metric in app.metric)
    assert any("No evidence items are recorded" in info.value for info in app.info)


def test_app_switches_to_the_role_registered_for_the_new_user(tmp_path, monkeypatch):
    db_path = tmp_path / "stamped.db"
    _create_app_db(db_path)
    monkeypatch.setenv("STAMPED_DB_PATH", str(db_path))
    key_path = tmp_path / "pseudonym.key"
    key_path.write_bytes(b"test-pseudonym-key-for-dashboard")
    monkeypatch.setenv("STAMPED_PSEUDONYM_KEY", str(key_path))

    app = AppTest.from_file(str(APP_PATH)).run(timeout=15)
    app.text_input(key="stamped_login_user_id").set_value("examiner-1")
    app.button[0].click()
    app.run(timeout=15)
    assert any(element.value == "Forensic analysis workspace" for element in app.subheader)
    app.text_input(key="stamped_login_user_id").set_value("officer-1")
    app.button[0].click()
    app.run(timeout=15)

    assert not app.exception
    assert any("officer-1 (investigating_officer)" in caption.value for caption in app.caption)
    assert any(element.value == "Investigation workspace" for element in app.subheader)
    assert any(element.label == "Filter leads by severity" for element in app.selectbox)

    app.text_input(key="stamped_login_user_id").set_value("prosecutor-1")
    app.button[0].click()
    app.run(timeout=15)

    assert not app.exception
    assert any("prosecutor-1 (prosecutor)" in caption.value for caption in app.caption)
    assert any(
        element.value == "Prosecution case brief" for element in app.subheader
    ), [element.value for element in app.subheader]
    assert any(metric.label == "Custody entries" for metric in app.metric)


def test_direct_page_routes_still_render_only_role_projected_data(tmp_path, monkeypatch):
    database_path = tmp_path / "stamped.db"
    _create_app_db(database_path)
    secret_path = "/srv/stamped/sealed/EXAMINER-ONLY.log"
    secret_metadata = "EXAMINER-ONLY-METADATA"
    original_name = "alice-private-device.log"
    account = "alice-private-account"
    ip_address = "203.0.113.99"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO evidence (evidence_id, content_hash, sealed_path, source, collector, "
            "original_name, captured_at, sealed_at, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "evidence-1",
                "content-hash",
                secret_path,
                "manual-upload",
                "examiner-1",
                original_name,
                "2026-10-20T08:00:00+00:00",
                "2026-10-20T08:01:00+00:00",
                json.dumps({"notes": secret_metadata}),
            ),
        )
        connection.execute(
            "INSERT INTO findings (finding_id, source_evidence_id, rule_id, severity, title, "
            "description, created_at, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "finding-1",
                "evidence-1",
                "test_rule@1",
                "high",
                f"Suspicious login for {account} from {ip_address}",
                f"Account {account} accessed the service from {ip_address}",
                "2026-10-20T08:02:00+00:00",
                json.dumps(
                    {
                        "finding_id": "finding-1",
                        "grouped_by": "account",
                        "key": account,
                        "logins": [
                            {
                                "event_id": "event-1",
                                "timestamp_utc": "2026-10-20T08:00:00+00:00",
                                "source_ip": ip_address,
                                "lat": -26.2041,
                                "lon": 28.0473,
                            }
                        ],
                        "geo_source": "EXAMINER-ONLY-GEO-DATABASE",
                        "details_json": "EXAMINER-ONLY-RAW-DETAILS",
                    }
                ),
            ),
        )
        append_entry(
            connection,
            "examiner-1",
            "examiner",
            "sealed",
            evidence_id="evidence-1",
            details={"sealed_path": secret_path, "error": secret_metadata},
        )
        connection.commit()

    key_path = tmp_path / "pseudonym.key"
    key_path.write_bytes(b"test-pseudonym-key-for-dashboard")
    monkeypatch.setenv("STAMPED_DB_PATH", str(database_path))
    monkeypatch.setenv("STAMPED_PSEUDONYM_KEY", str(key_path))

    for role, actor in (
        ("investigating_officer", "officer-1"),
        ("prosecutor", "prosecutor-1"),
    ):
        for page in (
            _run_case_overview,
            _run_findings_page,
            _run_timeline_page,
            _run_custody_history_page,
        ):
            app = AppTest.from_function(page)
            app.session_state["stamped_actor"] = actor
            app.run(timeout=15)

            assert not app.exception
            rendered_data = "\n".join(
                str(element.value)
                for element in (*app.dataframe, *app.json)
            )
            for private_value in (
                secret_path,
                secret_metadata,
                "EXAMINER-ONLY-GEO-DATABASE",
                "EXAMINER-ONLY-RAW-DETAILS",
            ):
                assert private_value not in rendered_data
            if role == "prosecutor":
                for private_value in (original_name, account, ip_address):
                    assert private_value not in rendered_data


def test_direct_reports_route_exports_role_projected_rows(tmp_path, monkeypatch):
    database_path = tmp_path / "stamped.db"
    _create_app_db(database_path)
    account = "alice-private-account"
    ip_address = "203.0.113.99"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO findings (finding_id, source_evidence_id, rule_id, severity, title, "
            "description, created_at, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "finding-1",
                "evidence-1",
                "test_rule@1",
                "high",
                f"Suspicious login for {account} from {ip_address}",
                f"Account {account} accessed the service from {ip_address}",
                "2026-10-20T08:02:00+00:00",
                json.dumps({"grouped_by": "account", "key": account}),
            ),
        )
        connection.commit()
    key_path = tmp_path / "pseudonym.key"
    key_path.write_bytes(b"test-pseudonym-key-for-dashboard")
    monkeypatch.setenv("STAMPED_DB_PATH", str(database_path))
    monkeypatch.setenv("STAMPED_PSEUDONYM_KEY", str(key_path))

    import app.main as app_main

    original_export_findings = app_main.export_findings
    exported_reports = []

    def capture_findings_export(*args, **kwargs):
        result = original_export_findings(*args, **kwargs)
        exported_reports.append(result.content)
        return result

    monkeypatch.setattr(app_main, "export_findings", capture_findings_export)
    app = AppTest.from_function(_run_reports_page)
    app.session_state["stamped_actor"] = "prosecutor-1"
    app.run(timeout=15)
    app.button(key="stamped_prepare_report").click()
    app.run(timeout=15)

    assert not app.exception
    assert any("Prepared 1 rows" in element.value for element in app.success)
    assert len(exported_reports) == 1
    assert account not in exported_reports[0]
    assert ip_address not in exported_reports[0]
