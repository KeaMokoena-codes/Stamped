"""Plain-language wording for the Stamped dashboard (Issue #31).

PRESENTATION ONLY. Nothing in this module decides anything: it never changes what the
verifier reported, what the access layer allows, or which rows a role can see. It only
turns those results into sentences a non-technical reader can act on.

Rules this module is held to (and tests/test_plain_language.py checks):
  * A FAIL or ERROR is never worded like a pass, and never softer than what the verifier said.
  * A PASS from a limited check says what was NOT checked.
  * Error messages say what happened and what to do, and never include the raw exception.
  * It imports nothing from Streamlit, so it can be tested without a browser.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from access import AccessError, DatabaseError, PseudonymizerRequired
from access.data import AccessLogError, TimelineSourceError
from access.roles import AccessDenied, UnknownRoleError

# --------------------------------------------------------------------------- roles

ROLE_LABELS = {
    "examiner": "Forensic examiner",
    "investigating_officer": "Investigating officer",
    "prosecutor": "Prosecutor",
}


def humanize(name: str) -> str:
    """'sealed_at' -> 'Sealed at'. Used only as a fallback for names we have no wording for."""
    return str(name).replace("_", " ").strip().capitalize()


def role_label(role) -> str:
    value = getattr(role, "value", role)
    return ROLE_LABELS.get(str(value), humanize(value))


# ----------------------------------------------------------------------- glossary

GLOSSARY: tuple[tuple[str, str], ...] = (
    (
        "Custody log / chain of custody",
        "The record of who handled the evidence, what they did and when. Every entry is "
        "added to the end; nothing is meant to be edited or removed.",
    ),
    (
        "Hash chain",
        "Each custody entry carries a digital fingerprint of the entry before it. If any "
        "earlier entry is changed, the fingerprints after it stop matching, so tampering shows.",
    ),
    (
        "Fingerprint (SHA-256 hash)",
        "A short code worked out from the exact contents of a file or record. Change one "
        "character and the code changes completely.",
    ),
    (
        "Sealed",
        "Locked in: a fingerprint of the evidence was recorded when it was received, so any "
        "later change can be detected.",
    ),
    (
        "Anchor (signed checkpoint)",
        "A signed snapshot of the custody log kept outside the log. It lets a checker prove "
        "nothing was removed or rewritten afterwards.",
    ),
    (
        "Digital signature (Ed25519, ML-DSA)",
        "A mark that proves who issued a checkpoint and that it has not been altered. Stamped "
        "uses two kinds together so the proof stays sound even against future computers.",
    ),
    (
        "Masked / pseudonymised",
        "Names, accounts and IP addresses are replaced with consistent codes, so patterns can "
        "be followed without revealing who the people are.",
    ),
    (
        "Finding",
        "Suspicious activity the system flagged, such as many failed logins in a short time.",
    ),
)

# ------------------------------------------------------------------- table wording

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}

ACTION_LABELS = {
    "sealed": "Evidence sealed (locked against changes)",
    "parsed_auth_log": "Login log read and turned into events",
    "parsed_cloudtrail": "Cloud activity log read and turned into events",
    "finding_created": "Finding recorded",
    "viewed_evidence": "Evidence list opened",
    "viewed_findings": "Findings opened",
    "viewed_timeline": "Timeline opened",
    "viewed_custody_log": "Custody history opened",
    "viewed_directory": "Names and labels looked up",
}

# (field name in the stored record, plain heading). The default view shows only these;
# every field, unchanged, stays available under "Technical details".
FINDINGS_COLUMNS = (
    ("severity", "How serious"),
    ("title", "What was found"),
    ("description", "Details"),
    ("created_at", "Recorded at"),
)
EVIDENCE_COLUMNS = (
    ("original_name", "File name"),
    ("source", "Where it came from"),
    ("collector", "Collected by"),
    ("captured_at", "Captured at"),
    ("sealed_at", "Sealed (locked) at"),
)
CUSTODY_COLUMNS = (
    ("timestamp_utc", "When (UTC)"),
    ("actor", "Who"),
    ("role", "Role"),
    ("action", "What happened"),
    ("evidence_id", "Evidence"),
)


def severity_label(value) -> str:
    key = str(value).strip().lower()
    return SEVERITY_LABELS.get(key, humanize(key) if key else "Unknown")


def action_label(value) -> str:
    return ACTION_LABELS.get(str(value), humanize(value))


# ------------------------------------------------------------ names for the screen
#
# DISPLAY ONLY. A name here is never written into a custody entry, never hashed and never placed in an
# export; the stored id stays the record's identity everywhere except what a person reads on screen.
# Every lookup falls back to the raw id, so a missing or deleted record can never cause an error.
# The rows come from access.get_directory, which applies the same role restrictions as the evidence
# and findings views, so a name that a role may not see simply is not in the directory.

SHORT_ID_LENGTH = 8


def short_id(value) -> str:
    return str(value)[:SHORT_ID_LENGTH]


def friendly_time(value) -> str:
    """'2026-10-20T08:01:00+00:00' -> '2026-10-20 08:01 UTC'. Anything unreadable is returned as stored."""
    text = str(value).strip()
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if moment.tzinfo is None:
        return text
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class Directory:
    users: dict = field(default_factory=dict)      # user_id -> (display_name, role)
    evidence: dict = field(default_factory=dict)   # evidence_id -> {"original_name", "captured_at", "sealed_at"}
    findings: dict = field(default_factory=dict)   # finding_id -> (severity, title)

    @classmethod
    def from_rows(cls, rows) -> "Directory":
        users, evidence, findings = {}, {}, {}
        for row in rows or ():
            if not isinstance(row, dict):
                continue
            kind = row.get("kind")
            if kind == "user" and row.get("user_id"):
                users[str(row["user_id"])] = (row.get("display_name"), row.get("role"))
            elif kind == "evidence" and row.get("evidence_id"):
                evidence[str(row["evidence_id"])] = {k: row.get(k) for k in ("original_name", "captured_at", "sealed_at")}
            elif kind == "finding" and row.get("finding_id"):
                findings[str(row["finding_id"])] = (row.get("severity"), row.get("title"))
        return cls(users, evidence, findings)

    def user_name(self, user_id) -> str:
        """The display name, or the id itself when there is no usable name."""
        if user_id is None:
            return ""
        name = self.users.get(str(user_id), (None, None))[0]
        return name.strip() if isinstance(name, str) and name.strip() else str(user_id)

    def user_label(self, user_id, role=None) -> str:
        """'Name (Role)'. `role` is the role recorded with an action; otherwise the user's current role."""
        if user_id is None:
            return ""
        role = role if role not in (None, "") else self.users.get(str(user_id), (None, None))[1]
        name = self.user_name(user_id)
        return f"{name} ({role_label(role)})" if role not in (None, "") else name

    def evidence_label(self, evidence_id) -> str:
        """'file name (captured time)'. A role that is not given the file name gets 'Evidence item <short id>'
        instead (the short id is a prefix of the real one, so the record can still be found)."""
        if evidence_id is None or evidence_id == "":
            return ""
        info = self.evidence.get(str(evidence_id))
        if info is None:
            return str(evidence_id)
        name = info.get("original_name")
        name = name.strip() if isinstance(name, str) else ""
        title = name or f"Evidence item {short_id(evidence_id)}"
        when = info.get("captured_at")
        if when:
            return f"{title} (captured {friendly_time(when)})"
        if info.get("sealed_at"):
            return f"{title} (sealed {friendly_time(info['sealed_at'])})"
        return title

    def finding_label(self, finding_id) -> str:
        """'High: finding title'. Falls back to the id when the finding is not known."""
        if finding_id is None or finding_id == "":
            return ""
        entry = self.findings.get(str(finding_id))
        if entry is None:
            return str(finding_id)
        severity, title = entry
        title = title.strip() if isinstance(title, str) else ""
        if not title:
            return str(finding_id)
        return f"{severity_label(severity)}: {title}" if severity else title

    def related_label(self, item_id) -> str:
        """A custody entry's artifact id: a finding's title when it is a finding, otherwise the id."""
        return self.finding_label(item_id)


EMPTY_DIRECTORY = Directory()


def provenance_lines(provenance, directory: Directory) -> list[str]:
    """Plain sentences for a timeline entry's provenance. The raw record is still shown beside them."""
    if not isinstance(provenance, dict):
        return []
    lines = []
    if provenance.get("evidence_id"):
        lines.append(f"Evidence: {directory.evidence_label(provenance['evidence_id'])}")
    if provenance.get("finding_id"):
        lines.append(f"Finding: {directory.finding_label(provenance['finding_id'])}")
    return lines


def _plain_value(key: str, value, row=None, directory: Directory | None = None):
    if key == "severity":
        return severity_label(value)
    if key == "action":
        return action_label(value)
    if key == "role" and value is not None:
        return role_label(value)
    if directory is not None:
        if key in ("actor", "collector") and value:
            return directory.user_name(value)
        if key == "evidence_id" and value:
            return directory.evidence_label(value)
    return value


def plain_rows(rows: list[dict], columns: tuple[tuple[str, str], ...],
               directory: Directory | None = None) -> list[dict] | None:
    """Rows reduced to the plain columns, with plain headings and wording.

    Returns None when none of the plain columns are present, so the caller can fall back to
    showing the full record rather than an empty table. Never adds data that was not in `rows`.

    With a `directory`, ids are replaced by names for display (user, evidence). An evidence row from a
    role that is not given the file name says so, with a short id, instead of leaving a blank column.
    """
    shaped = []
    for row in rows:
        shown = {label: _plain_value(key, row[key], row, directory) for key, label in columns if key in row}
        if (directory is not None and "original_name" in dict(columns)
                and "original_name" not in row and row.get("evidence_id")):
            shown = {"File name": f"Not shown for your role (item {short_id(row['evidence_id'])})", **shown}
        shaped.append(shown)
    return shaped if any(shaped) else None


# ---------------------------------------------------------------------- errors


@dataclass(frozen=True)
class FriendlyError:
    what_happened: str
    what_to_do: str
    reference: str  # the exception TYPE only, for support; the message goes to the server log


def friendly_error(exc: BaseException) -> FriendlyError:
    """What happened and what to do, without the raw exception text.

    Order matters: subclasses are tested before their parents.
    """
    ref = type(exc).__name__
    if isinstance(exc, PseudonymizerRequired):
        return FriendlyError(
            "This view hides names, accounts and IP addresses behind codes, and the secret key "
            "that makes those codes is not set up on this computer. Nothing was shown.",
            "Ask your administrator to install the privacy key, then reload this page.",
            ref,
        )
    if isinstance(exc, AccessDenied):
        return FriendlyError(
            "Your role is not allowed to open this information.",
            "If you need it, ask your administrator to review your access. "
            "The other pages are not affected.",
            ref,
        )
    if isinstance(exc, UnknownRoleError):
        return FriendlyError(
            "Your account has a role Stamped does not recognise, so access was refused.",
            "Ask your administrator to correct your account.",
            ref,
        )
    if isinstance(exc, AccessLogError):
        return FriendlyError(
            "The system could not record in the custody log that you opened this information, "
            "so it did not show it. This protects the chain of custody.",
            "Try again in a moment. If it keeps happening, ask your administrator to check "
            "the case database.",
            ref,
        )
    if isinstance(exc, TimelineSourceError):
        return FriendlyError(
            "A timeline entry could not be re-created from the original sealed evidence file. "
            "The file may be missing or may have been changed.",
            "Do not rely on this timeline until the reason is explained. Report this to your "
            "administrator or a forensic examiner.",
            ref,
        )
    if isinstance(exc, AccessError):
        return FriendlyError(
            "Access to this information was refused.",
            "Ask your administrator if you believe you should have access.",
            ref,
        )
    if isinstance(exc, DatabaseError):
        return FriendlyError(
            "The case database could not be opened.",
            "Check that the case database exists and is not open in another program, then "
            "reload this page. If it still fails, ask your administrator.",
            ref,
        )
    if isinstance(exc, OSError):
        return FriendlyError(
            "A file that Stamped needs could not be read.",
            "Check that the evidence and key files are in place, then try again.",
            ref,
        )
    if isinstance(exc, ValueError):
        return FriendlyError(
            "Some stored information was not in the form Stamped expected.",
            "Try again. If it keeps happening, report it to your administrator.",
            ref,
        )
    return FriendlyError(
        "Something unexpected went wrong. Nothing was changed.",
        "Try again. If it keeps happening, report it to your administrator.",
        ref,
    )


def signin_error(exc: BaseException) -> FriendlyError:
    """Shown BEFORE anyone is signed in, so it says nothing about how the system is set up: no database
    or file wording, and no hint whether an ID exists, is disabled or has an unrecognised role."""
    if isinstance(exc, DatabaseError):
        return FriendlyError(
            "Sign-in is not available right now.",
            "Please try again in a few minutes. If it keeps happening, contact your administrator.",
            type(exc).__name__,
        )
    return FriendlyError(
        "We could not sign you in with that user ID.",
        "Check the ID for typing mistakes. If it is correct, ask your administrator to "
        "confirm that your account exists and is active.",
        type(exc).__name__,
    )


# --------------------------------------------------------------- verification result

_CHECK_NAMES = ("chain", "signatures", "anchors")

_FACT_WORDING = {
    "chain": {
        "PASS": "The chain of custody entries is unbroken.",
        "FAIL": "The chain of custody entries is broken{where}.",
        "ERROR": "The chain of custody entries could not be checked.",
        "SKIPPED": "The chain of custody entries were not checked.",
    },
    "signatures": {
        "PASS": "The digital signatures on the signed checkpoints are valid.",
        "FAIL": "A digital signature on a signed checkpoint is not valid.",
        "ERROR": "The digital signatures could not be checked.",
        "SKIPPED": "The digital signatures were not checked (no signed checkpoints were available).",
    },
    "anchors": {
        "PASS": "The log matches its signed checkpoints, so nothing was removed or rewritten afterwards.",
        "FAIL": "The log does not match a signed checkpoint: entries may have been removed, added or rewritten.",
        "ERROR": "The log could not be compared with its signed checkpoints.",
        "SKIPPED": "The log was not compared with signed checkpoints (none were available).",
    },
}


@dataclass(frozen=True)
class VerdictSummary:
    level: str  # "pass" | "fail" | "error": drives the colour AND the label, never just the colour
    label: str  # exactly what the verifier reported: PASS, FAIL or ERROR (or UNKNOWN)
    headline: str
    what_it_means: str
    next_step: str
    facts: tuple[str, ...] = field(default_factory=tuple)


def _status(report: dict, name: str) -> str:
    return str(report.get("checks", {}).get(name, {}).get("status", "SKIPPED")).upper()


def _facts(report: dict) -> tuple[str, ...]:
    broken = report.get("broken_entry_id")
    where = f" at entry #{broken}" if isinstance(broken, int) else ""
    lines = []
    for name in _CHECK_NAMES:
        status = _status(report, name)
        template = _FACT_WORDING[name].get(status)
        if template is None:
            template = f"This check reported an unrecognised status ({status}); treat it as not confirmed."
        lines.append(template.format(where=where) if "{where}" in template else template)
    return tuple(lines)


def summarise_verification(report: dict | None) -> VerdictSummary:
    """One reader-friendly verdict for a verifier report (the dict from `verify.py --json`).

    The level always follows the verifier's own `overall` value. Anything missing or
    unrecognised is treated as ERROR (not confirmed), never as a pass.
    """
    overall = str((report or {}).get("overall", "")).upper()
    if report is None or overall not in {"PASS", "FAIL", "ERROR"}:
        return VerdictSummary(
            "error",
            "UNKNOWN",
            "The check did not give a result Stamped can read, so nothing has been confirmed.",
            "This is not a pass. The record has been neither confirmed nor ruled out.",
            "Do not treat the record as verified. Ask your administrator to run the check again.",
        )

    facts = _facts(report)
    broken = report.get("broken_entry_id")

    if overall == "FAIL":
        if _status(report, "chain") == "FAIL":
            where = (
                f"The first entry that no longer matches is #{broken}."
                if isinstance(broken, int)
                else "The point where it stops matching could not be pinned to one entry."
            )
            headline = f"This record has been altered or damaged. {where}"
        else:
            headline = (
                "One or more checks failed, so this record cannot be relied on. It may have "
                "been changed, or entries may have been removed or added."
            )
        return VerdictSummary(
            "fail",
            "FAIL",
            headline,
            "Do not rely on this record until the problem is explained. Entries after the "
            "first problem may also be affected.",
            "Do not use this record as evidence. Report it to the person responsible for the "
            "case and ask a forensic examiner to investigate.",
            facts,
        )

    if overall == "ERROR":
        return VerdictSummary(
            "error",
            "ERROR",
            "The check could not be completed, so nothing has been confirmed either way.",
            "This is not a pass. The record has been neither confirmed nor ruled out.",
            "Do not treat the record as verified. Ask your administrator to run the check "
            "again; if it keeps failing, contact the technical team.",
            facts,
        )

    if report.get("limited"):
        return VerdictSummary(
            "pass",
            "PASS",
            "No alteration was found in the checks that ran.",
            "Only the chain of custody entries was checked. Signatures and signed checkpoints "
            "were not checked, so this does not prove that nothing was removed from the end "
            "of the log.",
            "You may continue, but ask for the full check (with signed checkpoints) before "
            "relying on this record in court.",
            facts,
        )
    return VerdictSummary(
        "pass",
        "PASS",
        "Every check passed. No alteration was found.",
        "The custody entries are unbroken, the signatures are valid and the log matches its "
        "signed checkpoints.",
        "No action is needed.",
        facts,
    )


def demo_expectation(report: dict | None) -> tuple[bool, str]:
    """For the tamper demo only: did the verifier catch the deliberate change?"""
    caught = (
            isinstance(report, dict)
            and report.get("overall") == "FAIL"
            and _status(report, "chain") == "FAIL"
            and isinstance(report.get("broken_entry_id"), int)
    )
    if caught:
        return True, (
            "This is the expected result for the demo: one record was deliberately altered "
            "and the verifier caught it."
        )
    if isinstance(report, dict) and report.get("overall") == "PASS":
        return False, (
            "Unexpected: the verifier reported PASS, but this demo is meant to be caught. "
            "Do not present this run as a success."
        )
    return False, (
        "Unexpected: the verifier did not confirm the deliberate change. "
        "Do not present this run as a success."
    )