import sqlite3
from pathlib import Path

from streamlit.testing.v1 import AppTest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "schema.sql"
APP_PATH = REPOSITORY_ROOT / "app" / "main.py"


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

    app = AppTest.from_file(str(APP_PATH)).run(timeout=15)
    app.text_input(key="stamped_login_user_id").set_value("examiner-1")
    app.button[0].click()
    app.run(timeout=15)
    app.text_input(key="stamped_login_user_id").set_value("officer-1")
    app.button[0].click()
    app.run(timeout=15)

    assert not app.exception
    assert any("officer-1 (investigating_officer)" in caption.value for caption in app.caption)
