"""
Role definitions, permissions matrix and field-level visibility policy (Issue #9).

This file is DATA, deliberately: every decision about who may see what is a line
in a table here, and nowhere else. access/data.py and access/masking.py only
*apply* these tables. docs/access-control.md is checked against them by a test,
so the documentation cannot drift from the behaviour.

THREE LAYERS, all enforced below the UI (the UI never queries the database):

  1. PERMISSIONS  role x resource x action (view / edit / export), DEFAULT DENY.
  2. FIELD POLICY per dataset, per field: FULL, PSEUDONYM or HIDDEN for each role.
     This is an ALLOW-LIST. A field that is not listed is HIDDEN from every role
     except the examiner, so a column or JSON key added later is invisible to
     restricted roles until someone consciously lists it.
  3. Reads and exports are themselves custody entries (access/data.py).

WHAT EACH ROLE IS FOR (edit the tables below if your organisation decides otherwise)
  examiner               Acquires, seals and analyses evidence. Sees everything, raw.
  investigating_officer  Pursues the suspect. Needs real accounts and IP addresses to
                         do that, but not examiner-internal data (file-system paths,
                         collection metadata, geolocation database details).
  prosecutor             Builds the case from the findings and the chain of custody.
                         Does not need third parties' accounts or IP addresses, so they
                         are replaced by consistent pseudonyms (the same account always
                         gets the same token, so the story can still be followed), and
                         the coordinates inferred for an IP address are withheld.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterator


class Role(str, Enum):
    EXAMINER = "examiner"
    INVESTIGATING_OFFICER = "investigating_officer"
    PROSECUTOR = "prosecutor"


class Resource(str, Enum):
    EVIDENCE = "evidence"
    TIMELINE = "timeline"
    FINDINGS = "findings"
    CUSTODY_LOG = "custody_log"


class Action(str, Enum):
    VIEW = "view"
    EDIT = "edit"
    EXPORT = "export"


class AccessError(Exception):
    """Base class for every refusal from the access layer."""


class UnknownRoleError(AccessError, ValueError):
    """The role is not one of the three defined roles. Never guessed or defaulted."""


class AccessDenied(AccessError):
    """The role may not perform this action on this resource."""


def parse_role(value) -> Role:
    """Exact match only: 'Prosecutor', ' prosecutor', None and 'admin' are all refused.
    A role that is not recognised must never silently become a permissive one."""
    if isinstance(value, Role):
        return value
    if isinstance(value, str):
        try:
            return Role(value)
        except ValueError:
            pass
    raise UnknownRoleError(f"Unknown role: {str(value)[:64]!r}. Expected one of {[r.value for r in Role]}.")


# ---------------------------------------------------------------------------
# 1. Permissions matrix (default deny: anything not listed is refused)
# ---------------------------------------------------------------------------
_V, _E, _X = Action.VIEW, Action.EDIT, Action.EXPORT

PERMISSIONS: dict[Role, dict[Resource, frozenset[Action]]] = {
    Role.EXAMINER: {
        Resource.EVIDENCE: frozenset({_V, _E, _X}),
        Resource.TIMELINE: frozenset({_V, _X}),
        Resource.FINDINGS: frozenset({_V, _E, _X}),
        Resource.CUSTODY_LOG: frozenset({_V, _X}),     # the log is append-only: nobody edits it
    },
    Role.INVESTIGATING_OFFICER: {
        Resource.EVIDENCE: frozenset({_V}),
        Resource.TIMELINE: frozenset({_V, _X}),
        Resource.FINDINGS: frozenset({_V, _X}),
        Resource.CUSTODY_LOG: frozenset({_V, _X}),
    },
    Role.PROSECUTOR: {
        Resource.EVIDENCE: frozenset({_V}),
        Resource.TIMELINE: frozenset({_V}),
        Resource.FINDINGS: frozenset({_V, _X}),
        Resource.CUSTODY_LOG: frozenset({_V, _X}),
    },
}


def can(role, resource: Resource, action: Action) -> bool:
    """Boolean form for the UI (e.g. to hide a button). An unknown role is simply False.
    This is a convenience only: the data-access functions enforce it themselves."""
    try:
        return action in PERMISSIONS[parse_role(role)].get(resource, frozenset())
    except (UnknownRoleError, KeyError):
        return False


def require(role, resource: Resource, action: Action) -> Role:
    """Raise AccessDenied / UnknownRoleError unless allowed. Returns the parsed Role."""
    parsed = parse_role(role)
    if action not in PERMISSIONS[parsed].get(resource, frozenset()):
        raise AccessDenied(f"Role '{parsed.value}' may not {action.value} {resource.value}.")
    return parsed


# ---------------------------------------------------------------------------
# 1b. Pages: a role is only offered, and only allowed to open, the pages it needs
# ---------------------------------------------------------------------------
# Each page lists what it READS. "all": the role needs every listed permission; "any": at least one.
# Default deny: a page that is not listed here cannot be opened by any role. This only decides what the UI
# shows and which page functions run; the data functions in access/data.py still enforce the permissions
# above on every read, so skipping this check never widens what a role can see.
PAGE_ACCESS: dict[str, tuple[str, tuple[tuple[Resource, Action], ...]]] = {
    "case_overview": ("all", ((Resource.EVIDENCE, _V), (Resource.FINDINGS, _V))),
    "timeline": ("all", ((Resource.TIMELINE, _V),)),
    "findings": ("all", ((Resource.FINDINGS, _V),)),
    "custody_history": ("all", ((Resource.CUSTODY_LOG, _V),)),
    # The tamper-detection demo is a tool for people who work on evidence: only roles that may edit it.
    "verification": ("all", ((Resource.EVIDENCE, _E),)),
    "reports": ("any", ((Resource.FINDINGS, _X), (Resource.TIMELINE, _X), (Resource.CUSTODY_LOG, _X))),
}


def can_open_page(role, page: str) -> bool:
    """True if `role` needs and may use `page`. An unknown role or an unlisted page is simply False."""
    entry = PAGE_ACCESS.get(page)
    if entry is None:
        return False
    mode, needs = entry
    checks = [can(role, resource, action) for resource, action in needs]
    return all(checks) if mode == "all" else any(checks)


# ---------------------------------------------------------------------------
# 2. Field policy (allow-list)
# ---------------------------------------------------------------------------
class Vis(str, Enum):
    FULL = "full"            # the stored value
    PSEUDONYM = "pseudonym"  # a keyed, consistent token (see access/masking.py)
    HIDDEN = "hidden"        # the field is absent from the result


@dataclass(frozen=True)
class Rule:
    examiner: Vis
    officer: Vis
    prosecutor: Vis
    kind: str | None = None          # what a PSEUDONYM is of: account | ip | by_grouped_by | text
    container_ok: bool = False       # may carry a nested value (only for plain configuration)

    def vis(self, role: Role) -> Vis:
        return {Role.EXAMINER: self.examiner,
                Role.INVESTIGATING_OFFICER: self.officer,
                Role.PROSECUTOR: self.prosecutor}[role]


@dataclass(frozen=True)
class ListOf:
    """A list whose items follow `inner` (a Rule, a dict spec, or a callable returning one,
    which lets a spec refer to itself)."""
    inner: object

    def resolve(self):
        return self.inner() if callable(self.inner) else self.inner


F, P, H = Vis.FULL, Vis.PSEUDONYM, Vis.HIDDEN

ALL = Rule(F, F, F)                                  # every role, as stored
ALL_STRUCT = Rule(F, F, F, container_ok=True)        # plain rule configuration (numbers); nested value allowed
NOT_PROSECUTOR = Rule(F, F, H)
EXAMINER_ONLY = Rule(F, H, H)
ACCOUNT = Rule(F, F, P, kind="account")              # prosecutor sees acct-xxxxxxxxxx
IP = Rule(F, F, P, kind="ip")                        # prosecutor sees ip-xxxxxxxxxx
KEY = Rule(F, F, P, kind="by_grouped_by")            # a finding's "key" is an account OR an IP, per "grouped_by"
TEXT = Rule(F, F, P, kind="text")                    # free text: known identifiers replaced, any IP address removed

SOURCE_EVENT = {"event_id": ALL, "evidence_id": ALL, "raw_ref": ALL}
_LOGIN = {"event_id": ALL, "timestamp_utc": ALL, "source_ip": IP, "lat": NOT_PROSECUTOR, "lon": NOT_PROSECUTOR}


def _finding_details() -> dict:
    return FINDING_DETAILS


# What a finding carries (details_json merged with its database columns). Large-access findings embed
# the FULL triggering findings under "triggered_by", so this spec refers to itself.
FINDING_DETAILS: dict = {
    "finding_id": ALL, "source_evidence_id": ALL, "artifact_id": ALL, "rule_id": ALL, "created_at": ALL,
    "finding_hash": ALL, "input_hash": ALL,
    "rule_name": ALL, "rule_version": ALL, "config": ALL_STRUCT, "severity": ALL,
    "grouped_by": ALL, "key": KEY,
    "title": TEXT, "description": TEXT,
    "first_seen": ALL, "last_seen": ALL,
    "failure_count": ALL, "followed_by_success": ALL,
    "distance_km": ALL, "elapsed_seconds": ALL, "speed_kmh": ALL, "instantaneous": ALL,
    "logins": ListOf(_LOGIN),
    "login": {"event_id": ALL, "timestamp_utc": ALL, "source_ip": IP},
    "window": {"start": ALL, "end": ALL, "bytes": ALL, "event_count": ALL, "source_ips": ListOf(IP)},
    "baseline": {"lookback_seconds": ALL, "bucket_seconds": ALL, "n_buckets": ALL, "n_events": ALL,
                 "mean_bytes_per_bucket": ALL, "std_bytes_per_bucket": ALL, "threshold_bytes": ALL,
                 "window_multiple_of_mean": ALL, "events_hash": ALL, "evidence_ids": ListOf(ALL)},
    "source_events": ListOf(SOURCE_EVENT),
    "triggered_by": ListOf(_finding_details),
    "geo_source": EXAMINER_ONLY,       # names the geolocation database file
    "details_json": EXAMINER_ONLY,     # the raw stored text; the parsed, projected form is "details"
}

EVIDENCE_FIELDS: dict = {
    "evidence_id": ALL, "content_hash": ALL, "source": ALL, "collector": ALL,
    "captured_at": ALL, "sealed_at": ALL,
    "original_name": NOT_PROSECUTOR,   # a file name can itself name a person or a device
    "sealed_path": EXAMINER_ONLY,      # internal file-system layout
    "metadata_json": EXAMINER_ONLY,    # free-form collection metadata supplied by the collector
}

FINDING_FIELDS: dict = {
    "finding_id": ALL, "source_evidence_id": ALL, "artifact_id": ALL, "rule_id": ALL, "severity": ALL,
    "created_at": ALL, "title": TEXT, "description": TEXT,
    "details_json": EXAMINER_ONLY,
    "details": FINDING_DETAILS,
}

EVENT_DETAILS: dict = {
    "event_id": ALL, "evidence_id": ALL, "raw_ref": ALL, "timestamp_utc": ALL, "event_type": ALL,
    "outcome": ALL, "service": ALL, "bytes_out": ALL, "account": ACCOUNT, "source_ip": IP,
}

TIMELINE_ITEM: dict = {
    "entry_type": ALL, "id": ALL, "timestamp_utc": ALL, "event_type": ALL, "outcome": ALL,
    "severity": ALL, "service": ALL,
    "account": ACCOUNT, "source_ip": IP, "summary": TEXT,
    "provenance": {"evidence_id": ALL, "raw_ref": ALL, "event_id": ALL, "finding_id": ALL,
                   "artifact_id": ALL, "rule_id": ALL, "input_hash": ALL,
                   "evidence_ids": ListOf(ALL), "source_events": ListOf(SOURCE_EVENT)},
    # "details" is added per entry type (an event and a finding carry different details)
}


def timeline_spec(entry_type) -> dict:
    return {**TIMELINE_ITEM, "details": EVENT_DETAILS if entry_type == "event" else FINDING_DETAILS}


# Custody-log "details": only keys the application is known to write. Paths and error text are examiner-only.
CUSTODY_DETAILS: dict = {
    "reason": ALL, "note": ALL, "content_hash": ALL,
    "tool_name": ALL, "tool_version": ALL, "events_count": ALL, "ignored_count": ALL, "unparsed_count": ALL,
    "rule_id": ALL, "input_hash": ALL, "finding_hash": ALL, "severity": ALL,
    "source_events": ListOf(SOURCE_EVENT), "triggered_by": ListOf(ALL),
    "anchor_id": ALL, "anchored_entry_id": ALL, "anchored_entry_hash": ALL, "seq": ALL,
    "location_assurance": ALL,
    "sealed_path": EXAMINER_ONLY, "attempted_path": EXAMINER_ONLY, "error": EXAMINER_ONLY,
    # written by the access layer itself (access/data.py); never contains identifiers
    "dataset": ALL, "resource": ALL, "action": ALL, "count": ALL, "ids": ListOf(ALL), "ids_truncated": ALL,
    "filters": {"evidence_id": ALL, "finding_id": ALL}, "identifiers": ALL, "export_sha256": ALL,
    "export_bytes": ALL, "events": ALL, "findings": ALL, "evidence_ids": ListOf(ALL),
    "first_entry_id": ALL, "last_entry_id": ALL,
    "attempted_role": EXAMINER_ONLY,
}

CUSTODY_FIELDS: dict = {
    "entry_id": ALL, "timestamp_utc": ALL, "actor": ALL, "role": ALL, "action": ALL,
    "evidence_id": ALL, "artifact_id": ALL, "prev_hash": ALL, "entry_hash": ALL,
    "details_json": EXAMINER_ONLY,     # raw text needed to recompute the hash chain
    "details": CUSTODY_DETAILS,
}

# Who a user is, for DISPLAY only (Issue: friendly names). `display_name` is the staff member's name as shown
# in audit and access views; like the custody-log `actor` it is shown to every role. It is never written into a
# custody entry and never hashed. `active` and `created_at` are not listed, so they stay examiner-only.
USER_FIELDS: dict = {"user_id": ALL, "display_name": ALL, "role": ALL}

DATASETS: dict[str, dict] = {
    "evidence": EVIDENCE_FIELDS, "findings": FINDING_FIELDS, "users": USER_FIELDS,
    "timeline.event": {**TIMELINE_ITEM, "details": EVENT_DETAILS},
    "timeline.finding": {**TIMELINE_ITEM, "details": FINDING_DETAILS},
    "custody_log": CUSTODY_FIELDS,
}


def _walk(spec, prefix: str = "", _seen: frozenset = frozenset()) -> Iterator[tuple[str, Rule]]:
    if isinstance(spec, Rule):
        yield prefix, spec
    elif isinstance(spec, ListOf):
        yield from _walk(spec.resolve(), prefix + "[]", _seen)
    elif isinstance(spec, dict):
        if id(spec) in _seen:                      # a spec that refers to itself: stop at the second visit
            return
        for key, inner in spec.items():
            yield from _walk(inner, f"{prefix}.{key}" if prefix else key, _seen | {id(spec)})


def policy_table() -> list[tuple[str, str, str, str, str]]:
    """(dataset, field path, examiner, investigating_officer, prosecutor) for every listed field.
    The documentation test uses this so docs/access-control.md cannot silently go stale."""
    rows = []
    for dataset, spec in DATASETS.items():
        for path, rule in _walk(spec):
            rows.append((dataset, path, rule.examiner.value, rule.officer.value, rule.prosecutor.value))
    return rows


def examiner_only_fields(dataset: str) -> set[str]:
    """Field names hidden from BOTH other roles in a dataset (the 'examiner-only' fields)."""
    return {path.split(".")[-1].replace("[]", "")
            for path, rule in _walk(DATASETS[dataset]) if rule.officer is H and rule.prosecutor is H}


def hidden_for(role: Role, spec: dict) -> set[str]:
    """Top-level field names of `spec` that `role` must not receive."""
    return {k for k, r in spec.items() if isinstance(r, Rule) and r.vis(role) is H}