"""Least privilege for the screens: a role is offered, and may open, only the pages it needs."""

from pathlib import Path

import pytest

from access import Action, Resource, Role, can, can_open_page
from access.roles import PAGE_ACCESS
from app.plain_language import signin_error
from access import AccessDenied, DatabaseError

ALL_PAGES = ("case_overview", "timeline", "findings", "custody_history", "verification", "reports")


def test_every_page_has_a_rule_and_no_page_is_missing_from_the_table():
    assert set(PAGE_ACCESS) == set(ALL_PAGES)


def test_only_the_examiner_is_offered_the_verification_demo():
    assert can_open_page(Role.EXAMINER, "verification")
    assert not can_open_page(Role.INVESTIGATING_OFFICER, "verification")
    assert not can_open_page(Role.PROSECUTOR, "verification")


def test_every_role_still_gets_the_pages_its_work_needs():
    for role in Role:
        for page in ("case_overview", "timeline", "findings", "custody_history", "reports"):
            assert can_open_page(role, page), (role, page)


def test_unknown_roles_and_unlisted_pages_are_refused():
    for role in (None, "", "admin", "Prosecutor", " examiner"):
        assert not any(can_open_page(role, page) for page in ALL_PAGES), role
    assert not can_open_page(Role.EXAMINER, "admin_console")
    assert not can_open_page(Role.EXAMINER, "")


@pytest.mark.parametrize("role", list(Role))
def test_a_page_is_never_offered_for_something_the_role_may_not_do(role):
    for page, (mode, needs) in PAGE_ACCESS.items():
        results = [can(role, resource, action) for resource, action in needs]
        expected = all(results) if mode == "all" else any(results)
        assert can_open_page(role, page) is expected


def test_the_documentation_lists_every_page():
    doc = (Path(__file__).resolve().parent.parent / "docs" / "access-control.md").read_text(encoding="utf-8")
    for title in ("Case overview", "Timeline", "Findings", "Custody history", "Verification", "Reports"):
        assert f"| {title}" in doc


def test_sign_in_errors_say_nothing_about_the_system_before_anyone_is_signed_in():
    secret = r"/srv/stamped/data/stamped.db sqlite OperationalError"
    for exc in (DatabaseError(secret), AccessDenied(secret), ValueError(secret)):
        friendly = signin_error(exc)
        text = f"{friendly.what_happened} {friendly.what_to_do}".lower()
        for word in ("database", "stamped.db", "sqlite", "file", "install", "initialize", "inactive", "unknown user"):
            assert word not in text, (type(exc).__name__, word)
    # a wrong ID, a disabled account and an unrecognised role must all read the same
    assert signin_error(AccessDenied("Unknown user.")) == signin_error(AccessDenied("This user's access is disabled."))


def test_the_sign_in_screen_source_no_longer_mentions_set_up_or_passwords():
    source = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(encoding="utf-8")
    for text in ("First-time setup", "init_db.py", "does not use a password", "demonstration sign-in"):
        assert text not in source, text