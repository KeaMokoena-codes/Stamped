"""Issue #31 guardrails: plain wording must never soften what the verifier reported,
never leak a raw exception, and never add data a role was not given."""

import json

from access import AccessError, DatabaseError, PseudonymizerRequired
from access.data import AccessLogError, TimelineSourceError
from access.roles import AccessDenied, UnknownRoleError
from app.plain_language import (
    CUSTODY_COLUMNS,
    EVIDENCE_COLUMNS,
    FINDINGS_COLUMNS,
    demo_expectation,
    friendly_error,
    plain_rows,
    role_label,
    signin_error,
    summarise_verification,
)


def _report(overall, chain="PASS", signatures="SKIPPED", anchors="SKIPPED", limited=True, broken=None):
    return {
        "overall": overall,
        "limited": limited,
        "broken_entry_id": broken,
        "checks": {
            "chain": {"status": chain},
            "signatures": {"status": signatures},
            "anchors": {"status": anchors},
        },
    }


def _words(summary):
    return " ".join([summary.headline, summary.what_it_means, summary.next_step, *summary.facts]).lower()


# --------------------------------------------------------------- never softened


def test_fail_is_never_worded_like_a_pass():
    reports = [
        _report("FAIL", chain="FAIL", broken=2),
        _report("FAIL", chain="FAIL", broken=None),
        _report("FAIL", chain="PASS", signatures="FAIL"),
        _report("FAIL", chain="PASS", signatures="PASS", anchors="FAIL", limited=False),
        _report("FAIL", chain="PASS", signatures="PASS", anchors="PASS", limited=False),  # inconsistent
    ]
    for report in reports:
        summary = summarise_verification(report)
        assert summary.level == "fail" and summary.label == "FAIL", report
        assert "do not" in summary.next_step.lower(), report
        assert "no alteration was found" not in _words(summary), report
        assert "every check passed" not in _words(summary), report


def test_fail_names_the_first_broken_entry():
    summary = summarise_verification(_report("FAIL", chain="FAIL", broken=2))
    assert "#2" in summary.headline
    assert "altered" in summary.headline.lower()


def test_error_is_not_a_pass():
    summary = summarise_verification(_report("ERROR", chain="ERROR"))
    assert summary.level == "error" and summary.label == "ERROR"
    assert "not a pass" in summary.what_it_means.lower()
    assert "nothing has been confirmed" in summary.headline.lower()


def test_missing_or_unreadable_report_is_never_a_pass():
    for report in (None, {}, {"overall": ""}, {"overall": "MAYBE"}, {"overall": None}):
        summary = summarise_verification(report)
        assert summary.level == "error", report
        assert summary.label == "UNKNOWN", report
        assert "not a pass" in summary.what_it_means.lower(), report


def test_level_always_follows_the_verifiers_overall_result():
    for overall, level in (("PASS", "pass"), ("FAIL", "fail"), ("ERROR", "error")):
        assert summarise_verification(_report(overall)).level == level
        # lower case from a sloppy caller must not change the outcome
        assert summarise_verification(_report(overall.lower())).level == level


# ----------------------------------------------------------- honest about limits


def test_limited_pass_says_what_was_not_checked():
    summary = summarise_verification(_report("PASS", limited=True))
    assert summary.level == "pass" and summary.label == "PASS"
    text = _words(summary)
    assert "only the chain" in text
    assert "not checked" in text or "were not checked" in text
    assert "does not prove" in text


def test_full_pass_is_only_claimed_when_nothing_was_skipped():
    full = summarise_verification(_report("PASS", signatures="PASS", anchors="PASS", limited=False))
    assert "every check passed" in _words(full)
    limited = summarise_verification(_report("PASS", limited=True))
    assert "every check passed" not in _words(limited)


def test_skipped_checks_are_stated_as_not_checked():
    summary = summarise_verification(_report("FAIL", chain="FAIL", broken=2))
    assert any("signatures were not checked" in f for f in summary.facts)
    assert any("not compared" in f for f in summary.facts)


def test_unrecognised_check_status_is_not_read_as_a_pass():
    summary = summarise_verification(_report("ERROR", chain="WEIRD"))
    assert any("not confirmed" in f for f in summary.facts)


def test_demo_expectation_requires_the_deliberate_change_to_be_caught():
    assert demo_expectation(_report("FAIL", chain="FAIL", broken=2))[0] is True
    caught, note = demo_expectation(_report("PASS"))
    assert caught is False and "do not present" in note.lower()
    assert demo_expectation(None)[0] is False
    assert demo_expectation(_report("ERROR", chain="ERROR"))[0] is False


# ---------------------------------------------------------------------- errors


def test_error_messages_never_contain_the_raw_exception_text():
    secret = r"LEAK-MARKER-7731 C:\Users\someone\stamped.db Traceback (most recent call last)"
    for exc in (
            PseudonymizerRequired(secret),
            AccessDenied(secret),
            UnknownRoleError(secret),
            AccessLogError(secret),
            TimelineSourceError(secret),
            AccessError(secret),
            DatabaseError(secret),
            OSError(secret),
            ValueError(secret),
            RuntimeError(secret),
    ):
        friendly = friendly_error(exc)
        text = f"{friendly.what_happened} {friendly.what_to_do}"
        assert "LEAK-MARKER" not in text and "Traceback" not in text and "stamped.db" not in text
        assert friendly.what_happened and friendly.what_to_do
        assert friendly.reference == type(exc).__name__
    for exc in (AccessError(secret), DatabaseError(secret)):
        friendly = signin_error(exc)
        assert "LEAK-MARKER" not in friendly.what_happened + friendly.what_to_do


def test_integrity_errors_are_not_softened():
    friendly = friendly_error(TimelineSourceError("x"))
    assert "do not rely" in friendly.what_to_do.lower()
    assert "changed" in friendly.what_happened.lower()
    assert "did not show it" in friendly_error(AccessLogError("x")).what_happened


# ---------------------------------------------------------------- table wording


def test_plain_rows_only_reshape_what_the_role_was_given():
    prosecutor_evidence = [{"evidence_id": "e1", "content_hash": "h", "source": "s", "collector": "c",
                            "captured_at": "t", "sealed_at": "t2"}]
    shaped = plain_rows(prosecutor_evidence, EVIDENCE_COLUMNS)
    assert "File name" not in shaped[0]  # this role was never given original_name
    assert set(shaped[0]) == {"Where it came from", "Collected by", "Captured at", "Sealed (locked) at"}
    assert plain_rows([{"unrelated": 1}], FINDINGS_COLUMNS) is None
    assert plain_rows([], FINDINGS_COLUMNS) is None


def test_plain_rows_use_plain_wording_without_changing_values():
    findings = [{"finding_id": "f", "severity": "high", "title": "T", "description": "D",
                 "created_at": "2026-01-01", "details_json": "{}"}]
    row = plain_rows(findings, FINDINGS_COLUMNS)[0]
    assert row == {"How serious": "High", "What was found": "T", "Details": "D", "Recorded at": "2026-01-01"}
    custody = [{"entry_id": 1, "timestamp_utc": "t", "actor": "a", "role": "investigating_officer",
                "action": "sealed", "entry_hash": "x"}]
    shaped = plain_rows(custody, CUSTODY_COLUMNS)[0]
    assert shaped["Role"] == "Investigating officer"
    assert shaped["Who"] == "a" and shaped["When (UTC)"] == "t"
    assert "locked" in shaped["What happened"]


def test_unknown_values_fall_back_to_readable_words():
    shaped = plain_rows([{"severity": "weird_level", "action": "some_new_action", "title": "x"}],
                        FINDINGS_COLUMNS + (("action", "What happened"),))[0]
    assert shaped["How serious"] == "Weird level"
    assert shaped["What happened"] == "Some new action"


def test_role_labels():
    assert role_label("examiner") == "Forensic examiner"
    assert role_label("investigating_officer") == "Investigating officer"
    assert role_label("prosecutor") == "Prosecutor"
    assert role_label("new_role") == "New role"


def test_report_is_json_serialisable_example():
    # the Streamlit page passes the verifier's parsed JSON straight in
    assert summarise_verification(json.loads(json.dumps(_report("FAIL", chain="FAIL", broken=2)))).level == "fail"