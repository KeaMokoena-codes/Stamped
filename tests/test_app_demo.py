import sqlite3

from streamlit.testing.v1 import AppTest

from schemas.init_db import SCHEMA_PATH
from seal.custody_log import append_entry


def _run_verification_page():
    from app.main import verification_page

    verification_page()


def test_tamper_demo_runs_real_verifier_on_isolated_case_three_times(
        tmp_path, monkeypatch
):
    database_path = tmp_path / "stamped.db"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO users (user_id, display_name, role, created_at, active) "
            "VALUES (?, ?, ?, ?, 1)",
            ("examiner-1", "Examiner One", "examiner", "2026-10-20T08:00:00+00:00"),
        )
        append_entry(
            connection,
            actor="live-user",
            role="examiner",
            action="live-case-before-demo",
            evidence_id="LIVE-ONLY",
            details={"case": "live"},
        )
        connection.commit()
    monkeypatch.setenv("STAMPED_DB_PATH", str(database_path))

    with sqlite3.connect(database_path) as connection:
        original_live_log = connection.execute(
            "SELECT entry_id, actor, action, prev_hash, entry_hash FROM custody_log"
        ).fetchall()

    for _ in range(3):
        app = AppTest.from_function(_run_verification_page)
        app.session_state["stamped_actor"] = "examiner-1"
        app.run(timeout=15)

        assert not app.exception
        assert any(
            button.label == "Run tamper-detection demo" for button in app.button
        )
        assert any(
            "disposable copy" in warning.value for warning in app.warning
        )

        next(
            button
            for button in app.button
            if button.label == "Run tamper-detection demo"
        ).click()
        app.run(timeout=60)

        assert not app.exception
        # The verdict is a styled card (Markdown), not a plain alert box. It must say FAIL,
        # name the broken entry, and never read like a pass (Issue #31 guardrail).
        card = "\n".join(element.value for element in app.markdown)
        assert "RESULT: FAIL" in card
        assert "first entry that no longer matches is #2" in card
        assert "RESULT: PASS" not in card
        verifier_output = "\n".join(element.value for element in app.code)
        assert '"tool": "stamped-verify/1"' in verifier_output
        assert '"overall": "FAIL"' in verifier_output
        assert '"broken_entry_id": 2' in verifier_output
        assert verifier_output.count('"status": "SKIPPED"') == 2

    with sqlite3.connect(database_path) as connection:
        unchanged_live_log = connection.execute(
            "SELECT entry_id, actor, action, prev_hash, entry_hash FROM custody_log"
        ).fetchall()
    assert unchanged_live_log == original_live_log