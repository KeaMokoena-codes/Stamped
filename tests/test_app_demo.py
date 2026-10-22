import sqlite3
from pathlib import Path

from streamlit.testing.v1 import AppTest

from schemas.init_db import SCHEMA_PATH

def _run_verification_page():
    from app.main import verification_page

    verification_page()


def test_verification_page_has_separate_non_mutating_demo_control(tmp_path, monkeypatch):
    database_path = tmp_path / "stamped.db"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO users (user_id, display_name, role, created_at, active) "
            "VALUES (?, ?, ?, ?, 1)",
            ("examiner-1", "Examiner One", "examiner", "2026-10-20T08:00:00+00:00"),
        )
    monkeypatch.setenv("STAMPED_DB_PATH", str(database_path))

    app = AppTest.from_function(_run_verification_page)
    app.session_state["stamped_actor"] = "examiner-1"
    app.run(timeout=15)

    assert not app.exception
    assert any(
        button.label == "demo: simulate tampering" for button in app.button
    )
    assert any(
        "separate from real evidence handling" in warning.value
        for warning in app.warning
    )

    app.button[0].click()
    app.run(timeout=15)

    assert not app.exception
    assert any("No data was changed" in info.value for info in app.info)
    with sqlite3.connect(database_path) as connection:
        actions = {
            row[0]
            for row in connection.execute("SELECT action FROM custody_log")
        }
    assert actions == {"viewed_custody_log"}
