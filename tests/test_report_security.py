import pytest

from report.export_report import _deny_pdf_resource, generate_full_report, validate_case_id
from schemas.init_db import SCHEMA_PATH


@pytest.mark.parametrize("case_id", ["CASE-001", "case_2", "7", "CASE-E2E-001"])
def test_case_id_validation_accepts_demo_and_safe_references(case_id):
    assert validate_case_id(case_id) == case_id


@pytest.mark.parametrize(
    "case_id",
    ["", "../outside", "a/b", "a\\b", "CASE 1", "CASE-1.html", "x" * 65, None],
)
def test_case_id_validation_rejects_hostile_or_ambiguous_values(case_id):
    with pytest.raises(ValueError):
        validate_case_id(case_id)


@pytest.mark.parametrize("uri", ["https://example.invalid/x", "file:///etc/passwd", "../secret.txt"])
def test_pdf_renderer_never_resolves_local_or_remote_resources(uri):
    with pytest.raises(ValueError, match="resource loading is disabled"):
        _deny_pdf_resource(uri)


def test_hostile_database_text_is_escaped_in_the_html_report(tmp_path):
    import sqlite3

    database_path = tmp_path / "synthetic.db"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO users (user_id, display_name, role, created_at, active) "
            "VALUES (?, ?, ?, ?, 1)",
            ("examiner1", "Synthetic Examiner", "examiner", "2026-10-28T00:00:00+00:00"),
        )
        connection.execute(
            "INSERT INTO findings (finding_id, source_evidence_id, rule_id, severity, title, "
            "description, created_at, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "finding1",
                "evidence1",
                "synthetic@1",
                "medium",
                "<script>alert(1)</script>",
                "SQL fragment '; DROP TABLE findings; -- and path ../outside",
                "2026-10-28T00:00:00+00:00",
                "{}",
            ),
        )

    html, pdf = generate_full_report(
        "CASE-001", "examiner", "examiner1", db_path=database_path
    )
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "DROP TABLE findings" in html
    assert "../outside" in html
    if pdf is not None:
        assert pdf.startswith(b"%PDF-")
