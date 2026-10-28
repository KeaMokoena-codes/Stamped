"""Friendly names on screen (display_name, original_name, finding title), without touching the record.

Guardrails under test:
  * names are for the screen only: never written into a custody entry, never hashed, never in an export;
  * role-based masking still applies: a name never reveals what the role could not already read;
  * the raw id is still reachable, and a missing record falls back to the id instead of an error.
"""

import json
import sqlite3

import pytest

from access import (AccessDenied, Pseudonymizer, PseudonymizerRequired, Role, export_custody_log,
                    export_findings, get_custody_log, get_directory, get_evidence, get_findings,
                    resolve_display_name)
from app.plain_language import (CUSTODY_COLUMNS, EMPTY_DIRECTORY, EVIDENCE_COLUMNS, Directory,
                                friendly_time, plain_rows, provenance_lines)
from seal.custody_log import append_entry, recompute_and_verify_chain
from tests.test_access import (ACCOUNTS, EXAMINER_INTERNAL, IPS, KEY, ORIGINAL_NAME, seeded)

EXAMINER, OFFICER, PROSECUTOR = Role.EXAMINER, Role.INVESTIGATING_OFFICER, Role.PROSECUTOR
NAMES = {"examiner-1": "Ayesha Examiner", "officer-1": "Olivia Officer", "pros-1": "Pieter Prosecutor"}


def _with_users():
    conn, events = seeded()
    for user_id, role, name in (("examiner-1", "examiner", NAMES["examiner-1"]),
                                ("officer-1", "investigating_officer", NAMES["officer-1"]),
                                ("pros-1", "prosecutor", NAMES["pros-1"])):
        conn.execute("INSERT INTO users (user_id, display_name, role, created_at, active) VALUES (?,?,?,?,1)",
                     (user_id, name, role, "2026-01-01T00:00:00+00:00"))
    conn.commit()
    return conn, events


def _directory(conn, role, actor="examiner-1"):
    return Directory.from_rows(get_directory(conn, role, actor, pseudonymizer=KEY))


# ---------------------------------------------------------------------- the access layer

def test_directory_gives_names_for_users_evidence_and_findings():
    conn, _ = _with_users()
    d = _directory(conn, EXAMINER)
    assert d.user_name("examiner-1") == "Ayesha Examiner"
    assert d.user_label("officer-1") == "Olivia Officer (Investigating officer)"
    assert d.evidence_label("E1") == f"{ORIGINAL_NAME} (captured 2026-03-01 00:00 UTC)"
    some_finding = get_findings(conn, EXAMINER, "examiner-1")[0]
    label = d.finding_label(some_finding["finding_id"])
    assert some_finding["title"] in label and label.startswith(("Critical", "High", "Medium", "Low", "Informational"))


def test_a_prosecutor_gets_no_file_name_and_no_identifier_in_a_finding_title():
    conn, _ = _with_users()
    rows = get_directory(conn, PROSECUTOR, "pros-1", pseudonymizer=KEY)
    text = json.dumps(rows)
    assert ORIGINAL_NAME not in text and "cloudtrail.json" not in text
    for secret in ACCOUNTS + IPS + EXAMINER_INTERNAL:
        assert secret not in text, secret
    d = Directory.from_rows(rows)
    assert d.evidence_label("E1") == "Evidence item E1 (captured 2026-03-01 00:00 UTC)"


def test_every_name_is_something_the_same_role_can_already_read_elsewhere():
    conn, _ = _with_users()
    for role in (EXAMINER, OFFICER, PROSECUTOR):
        rows = get_directory(conn, role, "examiner-1", pseudonymizer=KEY)
        evidence = {e["evidence_id"]: e for e in get_evidence(conn, role, "examiner-1", pseudonymizer=KEY)}
        for row in (r for r in rows if r["kind"] == "evidence"):
            assert row.get("original_name") == evidence[row["evidence_id"]].get("original_name")
        titles = {f["finding_id"]: f["title"] for f in get_findings(conn, role, "examiner-1", pseudonymizer=KEY)}
        for row in (r for r in rows if r["kind"] == "finding"):
            assert row["title"] == titles[row["finding_id"]]


def test_a_prosecutor_still_needs_the_key_so_names_cannot_bypass_masking():
    conn, _ = _with_users()
    with pytest.raises(PseudonymizerRequired):
        get_directory(conn, PROSECUTOR, "pros-1")


def test_unknown_roles_are_refused_like_every_other_read():
    conn, _ = _with_users()
    with pytest.raises(Exception) as info:
        get_directory(conn, "admin", "examiner-1", pseudonymizer=KEY)
    assert "role" in str(info.value).lower()


def test_names_are_never_written_into_the_custody_log_or_the_hash_chain():
    conn, _ = _with_users()
    before = conn.execute("SELECT entry_id, entry_hash, prev_hash, details_json FROM custody_log ORDER BY entry_id").fetchall()
    for role in (EXAMINER, OFFICER, PROSECUTOR):
        get_directory(conn, role, "examiner-1", pseudonymizer=KEY)
    after = conn.execute("SELECT entry_id, entry_hash, prev_hash, details_json FROM custody_log ORDER BY entry_id").fetchall()
    assert after[:len(before)] == before                     # nothing already recorded was touched
    assert len(after) == len(before) + 3                     # one "viewed_directory" entry per read
    assert recompute_and_verify_chain(conn)[0] is True       # the chain still verifies
    everything = json.dumps(conn.execute("SELECT * FROM custody_log").fetchall())
    for name in list(NAMES.values()) + [ORIGINAL_NAME]:
        assert name not in everything, name
    actions = {r[0] for r in conn.execute("SELECT action FROM custody_log WHERE entry_id > ?", (before[-1][0],))}
    assert actions == {"viewed_directory"}


def test_exports_still_use_the_stored_ids_and_carry_no_display_names():
    conn, _ = _with_users()
    for export in (export_findings, export_custody_log):
        content = export(conn, EXAMINER, "examiner-1", pseudonymizer=KEY).content
        assert "display_name" not in content
        for name in NAMES.values():
            assert name not in content
    assert any(row["actor"] == "examiner-1" for row in get_custody_log(conn, EXAMINER, "examiner-1"))
    assert "examiner-1" in export_custody_log(conn, EXAMINER, "examiner-1").content


def test_resolve_display_name_falls_back_to_the_id():
    conn, _ = _with_users()
    assert resolve_display_name(conn, "officer-1") == "Olivia Officer"
    assert resolve_display_name(conn, "ghost") == "ghost"
    conn.execute("INSERT INTO users (user_id, display_name, role, created_at, active) VALUES "
                 "('blank', '   ', 'examiner', '2026-01-01T00:00:00+00:00', 1)")
    assert resolve_display_name(conn, "blank") == "blank"


# ---------------------------------------------------------------- the fallback behaviour

def test_missing_or_deleted_records_fall_back_to_the_id_never_an_error():
    d = Directory.from_rows([{"kind": "user", "user_id": "u1", "display_name": "Una", "role": "examiner"}])
    assert d.user_label("deleted-user") == "deleted-user"
    assert d.user_label("deleted-user", "prosecutor") == "deleted-user (Prosecutor)"
    assert d.user_name("ingest") == "ingest"                       # a process, not a person
    assert d.evidence_label("abc123") == "abc123"
    assert d.finding_label("f-missing") == "f-missing"
    assert d.related_label("a-derived-artifact") == "a-derived-artifact"
    assert d.user_label(None) == d.evidence_label(None) == d.finding_label("") == ""
    assert EMPTY_DIRECTORY.user_label("anyone") == "anyone"
    assert Directory.from_rows(None).users == {} and Directory.from_rows(["junk", 3, {}]).users == {}


def test_blank_names_and_titles_fall_back_to_the_id():
    d = Directory.from_rows([
        {"kind": "user", "user_id": "u1", "display_name": "  ", "role": "examiner"},
        {"kind": "finding", "finding_id": "f1", "severity": "high", "title": ""},
        {"kind": "evidence", "evidence_id": "e1234567890", "original_name": None, "sealed_at": "2026-03-01T10:00:00Z"},
    ])
    assert d.user_label("u1") == "u1 (Forensic examiner)"
    assert d.finding_label("f1") == "f1"
    assert d.evidence_label("e1234567890") == "Evidence item e1234567 (sealed 2026-03-01 10:00 UTC)"


def test_a_role_recorded_with_an_action_wins_over_the_users_current_role():
    d = Directory.from_rows([{"kind": "user", "user_id": "u1", "display_name": "Una", "role": "prosecutor"}])
    assert d.user_label("u1") == "Una (Prosecutor)"
    assert d.user_label("u1", "examiner") == "Una (Forensic examiner)"


def test_friendly_time_only_reformats_what_it_understands():
    assert friendly_time("2026-10-20T08:01:00+00:00") == "2026-10-20 08:01 UTC"
    assert friendly_time("2026-10-20T10:01:00+02:00") == "2026-10-20 08:01 UTC"
    assert friendly_time("not a time") == "not a time"
    assert friendly_time("2026-10-20T08:01:00") == "2026-10-20T08:01:00"     # no zone: shown as stored


# ----------------------------------------------------------------------------- the tables

def test_custody_table_shows_names_but_keeps_the_stored_row_untouched():
    conn, _ = _with_users()
    append_entry(conn, "examiner-1", "examiner", "sealed", evidence_id="E1", details={"content_hash": "h1"})
    conn.commit()
    d = _directory(conn, EXAMINER)
    rows = get_custody_log(conn, EXAMINER, "examiner-1", pseudonymizer=KEY)
    plain = plain_rows(rows, CUSTODY_COLUMNS, d)
    sealed = next(p for p, r in zip(plain, rows) if r["actor"] == "examiner-1" and r["evidence_id"] == "E1")
    assert sealed["Who"] == "Ayesha Examiner" and sealed["Role"] == "Forensic examiner"
    assert sealed["Evidence"].startswith(ORIGINAL_NAME)
    assert any(r["actor"] == "examiner-1" and r["evidence_id"] == "E1" for r in rows)   # raw record unchanged
    assert plain_rows(rows, CUSTODY_COLUMNS)[0]["Who"] == rows[0]["actor"]               # no directory: ids as before


def test_a_process_actor_is_shown_as_it_is_recorded():
    conn, _ = _with_users()
    d = _directory(conn, EXAMINER)
    rows = get_custody_log(conn, EXAMINER, "examiner-1", pseudonymizer=KEY)
    plain = plain_rows(rows, CUSTODY_COLUMNS, d)
    assert any(p["Who"] == "ingest" for p in plain)


def test_evidence_table_for_a_role_without_file_names_says_so_and_keeps_a_short_id():
    conn, _ = _with_users()
    rows = get_evidence(conn, PROSECUTOR, "pros-1", pseudonymizer=KEY)
    plain = plain_rows(rows, EVIDENCE_COLUMNS, _directory(conn, PROSECUTOR, "pros-1"))
    assert all(p["File name"].startswith("Not shown for your role (item E") for p in plain)
    assert ORIGINAL_NAME not in json.dumps(plain)
    assert "File name" not in plain_rows(rows, EVIDENCE_COLUMNS)[0]                      # no directory: as before


def test_evidence_table_collector_is_shown_as_a_name_when_it_is_a_known_user():
    conn, _ = _with_users()
    conn.execute("UPDATE evidence SET collector = 'examiner-1' WHERE evidence_id = 'E1'")
    conn.commit()
    rows = get_evidence(conn, EXAMINER, "examiner-1")
    plain = plain_rows(rows, EVIDENCE_COLUMNS, _directory(conn, EXAMINER))
    by_file = {p["File name"]: p for p in plain}
    assert by_file[ORIGINAL_NAME]["Collected by"] == "Ayesha Examiner"
    assert by_file["cloudtrail.json"]["Collected by"] == "amir"                          # unknown user: the id


def test_timeline_provenance_is_described_in_words_and_the_raw_ids_stay_available():
    conn, _ = _with_users()
    d = _directory(conn, EXAMINER)
    finding = get_findings(conn, EXAMINER, "examiner-1")[0]
    provenance = {"evidence_id": "E1", "finding_id": finding["finding_id"], "raw_ref": "line:3"}
    lines = provenance_lines(provenance, d)
    assert lines[0] == f"Evidence: {ORIGINAL_NAME} (captured 2026-03-01 00:00 UTC)"
    assert finding["title"] in lines[1]
    assert provenance["evidence_id"] == "E1"                                              # input never changed
    assert provenance_lines({"evidence_id": "gone"}, d) == ["Evidence: gone"]
    assert provenance_lines(None, d) == [] and provenance_lines({}, d) == []


def test_the_page_code_still_never_touches_the_database():
    # the UI and report only use the access layer: no SQL in app/ (checked in full by test_access)
    from pathlib import Path
    for name in ("main.py", "plain_language.py"):
        source = (Path(__file__).resolve().parent.parent / "app" / name).read_text(encoding="utf-8")
        assert "sqlite3" not in source and ".execute(" not in source


# ---------------------------------------------------------------------------- the report

def _report_for(tmp_path, role, actor):
    from report.export_report import generate_full_report

    conn, _ = _with_users()
    path = tmp_path / "case.db"
    target = sqlite3.connect(path)
    conn.backup(target)
    target.close()
    return generate_full_report("CASE-001", role, actor, KEY, db_path=path)[0]


def test_examiner_report_shows_names_next_to_the_stored_ids(tmp_path):
    html = _report_for(tmp_path, "examiner", "examiner-1")
    assert "Ayesha Examiner (Forensic examiner)" in html
    assert "user ID: examiner-1" in html
    assert ORIGINAL_NAME in html and "captured 2026-03-01 00:00 UTC" in html
    assert ">E1<" in html                                    # the stored evidence id is still printed
    assert "amir" in html                                    # a recorded actor with no user record: the id


def test_prosecutor_report_does_not_gain_a_name_the_role_may_not_see(tmp_path):
    html = _report_for(tmp_path, "prosecutor", "pros-1")
    assert "Pieter Prosecutor (Prosecutor)" in html
    assert ORIGINAL_NAME not in html and "cloudtrail.json" not in html
    assert "Evidence item E1" in html
    for secret in ACCOUNTS + IPS + EXAMINER_INTERNAL:
        assert secret not in html, secret