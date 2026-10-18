"""
Every function here takes the caller's role and actor, and does four things, in this order:

  1. AUTHORIZE   the role must be allowed to view / export this resource (default deny).
                 A refusal is itself written to the custody log ('access_denied').
  2. FETCH       selects only the columns the role may see where it can, and
  3. PROJECT     rebuilds every record from the allow-list in access/roles.py, so a field
                 the role may not see is ABSENT from the returned object, not merely
                 hidden when drawn. Calling these functions directly, with no UI, returns
                 the same restricted data.
  4. LOG         writes a custody entry for the read or export BEFORE the data is
                 returned. If that entry cannot be written, no data is returned.

WHAT THE LOG ENTRY CONTAINS: who, which role, which dataset, how many records and their
ids (hashes), the filters used, and for exports the SHA-256 of exactly what was handed
over. It never contains account names, IP addresses or other identifiers: the custody
log is append-only and cannot be corrected, so personal data must not be written into it.

The data functions below need a WRITABLE connection with no transaction open (they
commit the audit entry themselves, and refuse to run inside someone else's transaction
rather than let a rollback silently erase the record that a read happened).

Roles are TRUSTED INPUT here: this layer enforces the role it is given. Binding a login to a
role (so it is not simply a drop-down in the browser) is resolve_role(), which reads the
users table and refuses unknown or inactive users.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from access.masking import Pseudonymizer, project_records, role_pseudonymizes
from access.roles import (CUSTODY_FIELDS, EVIDENCE_FIELDS, FINDING_FIELDS, AccessDenied, AccessError, Action,
                          Resource, Role, UnknownRoleError, can, parse_role, timeline_spec)
from ingest.timeline import build_timeline, load_findings_from_db
from seal.custody_log import append_entry

MAX_LOGGED_IDS = 100
INVALID_ROLE_LABEL = "invalid"

_EVIDENCE_COLUMNS = ("evidence_id", "content_hash", "source", "collector", "original_name",
                     "captured_at", "sealed_at", "sealed_path", "metadata_json")
_FINDING_COLUMNS = ("finding_id", "source_evidence_id", "artifact_id", "rule_id", "severity",
                    "title", "description", "created_at", "details_json")
_CUSTODY_COLUMNS = ("entry_id", "timestamp_utc", "actor", "role", "action", "evidence_id",
                    "artifact_id", "details_json", "prev_hash", "entry_hash")


class AccessLogError(AccessError):
    """The custody entry for this access could not be written, so the data was NOT released."""


@dataclass(frozen=True)
class ExportResult:
    dataset: str
    role: str
    content: str            # the exact text handed over (canonical JSON)
    sha256: str             # SHA-256 of `content` encoded as UTF-8; the same value is in the custody entry
    row_count: int


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------
def _clean_actor(actor) -> str:
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor must be a non-empty string: an access with no named actor cannot be recorded.")
    return actor


def _ensure_idle(conn: sqlite3.Connection) -> None:
    if conn.in_transaction:
        raise AccessError("Data-access functions must be called with no transaction open on the connection.")


def _dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _log(conn, actor: str, role_label: str, action: str, *, evidence_id=None, artifact_id=None, details: dict) -> None:
    try:
        append_entry(conn, actor, role_label, action, evidence_id=evidence_id,
                     artifact_id=artifact_id, details=details)
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise AccessLogError(f"Could not record '{action}' in the custody log; no data was released "
                             f"({type(exc).__name__}).") from exc


def _deny(conn, actor: str, role_label: str, resource, action, reason: str, error: AccessError,
          attempted_role=None):
    """Record the refusal, then raise `error`. A refusal that cannot be logged is still a refusal."""
    details = {"resource": getattr(resource, "value", str(resource)),
               "action": getattr(action, "value", str(action)), "reason": reason}
    if attempted_role is not None:
        details["attempted_role"] = str(attempted_role)[:64]
    try:
        _log(conn, actor, role_label, "access_denied", details=details)
    except AccessLogError as log_error:
        raise error from log_error
    raise error


def authorize(conn: sqlite3.Connection, actor: str, role, resource: Resource, action: Action) -> Role:
    """Check that `role` may perform `action` on `resource`; log and raise if not. Returns the parsed Role.
    Write paths (sealing evidence, recording findings) should call this with Action.EDIT first."""
    actor = _clean_actor(actor)
    _ensure_idle(conn)
    try:
        parsed = parse_role(role)
    except UnknownRoleError as err:
        _deny(conn, actor, INVALID_ROLE_LABEL, resource, action, "unknown_role", err, attempted_role=role)
    if not can(parsed, resource, action):
        _deny(conn, actor, parsed.value, resource, action, "not_permitted",
              AccessDenied(f"Role '{parsed.value}' may not {action.value} {resource.value}."))
    return parsed


def resolve_role(conn: sqlite3.Connection, user_id: str) -> Role:
    """The role of a registered, active user, read from the users table. Unknown, inactive or
    unrecognised-role users are refused (and the refusal is logged)."""
    actor = _clean_actor(user_id)
    _ensure_idle(conn)
    row = conn.execute("SELECT role, active FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        _deny(conn, actor, INVALID_ROLE_LABEL, Resource.EVIDENCE, Action.VIEW, "unknown_user", AccessDenied("Unknown user."))
    if not row[1]:
        _deny(conn, actor, INVALID_ROLE_LABEL, Resource.EVIDENCE, Action.VIEW, "inactive_user",
              AccessDenied("This user's access is disabled."))
    try:
        return parse_role(row[0])
    except UnknownRoleError as err:
        _deny(conn, actor, INVALID_ROLE_LABEL, Resource.EVIDENCE, Action.VIEW, "unknown_role", err, attempted_role=row[0])


def _filter(name: str, value):
    if value is not None and not isinstance(value, str):
        raise TypeError(f"{name} must be a string or None")
    return value


def _cap(ids: list) -> tuple[list, bool]:
    return ids[:MAX_LOGGED_IDS], len(ids) > MAX_LOGGED_IDS


def _label(role: Role) -> str:
    return "pseudonymized" if role_pseudonymizes(role) else "raw"


def _visible_columns(columns, spec: dict, role: Role, always=()):
    """Only the columns this role may receive (plus `always`, which are read only to be projected)."""
    return [c for c in columns if c in always or c not in spec or spec[c].vis(role).value != "hidden"]


def _rows(conn, table: str, columns: list[str], where: str, params: tuple, order: str) -> list[dict]:
    sql = f"SELECT {', '.join(columns)} FROM {table}{where} ORDER BY {order}"       # names come from constants above
    return [dict(zip(columns, row)) for row in conn.execute(sql, params).fetchall()]


def _parsed(text):
    try:
        value = json.loads(text) if isinstance(text, str) else None
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


# ---------------------------------------------------------------------------
# Dataset builders: raw rows -> projected rows + what to record in the log
# ---------------------------------------------------------------------------
def _build_evidence(conn, role: Role, pz, *, evidence_id=None, **_):
    cols = _visible_columns(_EVIDENCE_COLUMNS, EVIDENCE_FIELDS, role)
    where, params = (" WHERE evidence_id = ?", (evidence_id,)) if evidence_id else ("", ())
    rows = project_records(_rows(conn, "evidence", cols, where, params, "sealed_at, evidence_id"),
                           EVIDENCE_FIELDS, role, pz)
    ids, truncated = _cap([r["evidence_id"] for r in rows if "evidence_id" in r])
    return rows, {"ids": ids, "ids_truncated": truncated}


def _fetch_findings(conn, role: Role, evidence_id, finding_id) -> list[dict]:
    clauses, params = [], []
    if evidence_id:
        clauses.append("source_evidence_id = ?")
        params.append(evidence_id)
    if finding_id:
        clauses.append("finding_id = ?")
        params.append(finding_id)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    # details_json is read for EVERY role because it is the input to the projection; it is only
    # RETURNED to a role whose policy lists it (the examiner).
    cols = _visible_columns(_FINDING_COLUMNS, FINDING_FIELDS, role, always=("details_json",))
    raw = _rows(conn, "findings", cols, where, tuple(params), "created_at, finding_id")
    for record in raw:
        record["details"] = _parsed(record.get("details_json"))
    return raw


def _build_findings(conn, role: Role, pz, *, evidence_id=None, finding_id=None, **_):
    rows = project_records(_fetch_findings(conn, role, evidence_id, finding_id), FINDING_FIELDS, role, pz)
    ids, truncated = _cap([r["finding_id"] for r in rows if "finding_id" in r])
    return rows, {"ids": ids, "ids_truncated": truncated}


def _event_evidence_id(event):
    return event.get("evidence_id") if isinstance(event, dict) else getattr(event, "evidence_id", None)


def _build_timeline(conn, role: Role, pz, *, events=(), evidence_id=None, **_):
    events = [e for e in events if evidence_id is None or _event_evidence_id(e) == evidence_id]
    raw = build_timeline(events, load_findings_from_db(conn, evidence_id))
    rows = project_records(raw, lambda item: timeline_spec(item.get("entry_type")), role, pz)
    n_events = sum(1 for r in rows if r.get("entry_type") == "event")
    touched = sorted({str(i) for r in rows for i in
                      ([r.get("provenance", {}).get("evidence_id")] + list(r.get("provenance", {}).get("evidence_ids", [])))
                      if i})
    ids, truncated = _cap(touched)
    return rows, {"events": n_events, "findings": len(rows) - n_events, "evidence_ids": ids, "ids_truncated": truncated}


def _build_custody(conn, role: Role, pz, *, evidence_id=None, **_):
    cols = _visible_columns(_CUSTODY_COLUMNS, CUSTODY_FIELDS, role, always=("details_json",))
    where, params = (" WHERE evidence_id = ?", (evidence_id,)) if evidence_id else ("", ())
    raw = _rows(conn, "custody_log", cols, where, params, "entry_id")
    for record in raw:
        record["details"] = _parsed(record.get("details_json"))
    rows = project_records(raw, CUSTODY_FIELDS, role, pz)
    meta = {}
    if rows:
        meta = {"first_entry_id": rows[0].get("entry_id"), "last_entry_id": rows[-1].get("entry_id")}
    return rows, meta


# ---------------------------------------------------------------------------
# The two generic paths: view and export
# ---------------------------------------------------------------------------
def _view(conn, role, actor, resource: Resource, dataset: str, builder, pz, **filters):
    actor = _clean_actor(actor)
    for name in ("evidence_id", "finding_id"):
        _filter(name, filters.get(name))
    parsed = authorize(conn, actor, role, resource, Action.VIEW)
    rows, meta = builder(conn, parsed, pz, **filters)
    meta.update(dataset=dataset, count=len(rows), identifiers=_label(parsed),
                filters={k: v for k, v in filters.items() if k in ("evidence_id", "finding_id") and v})
    _log(conn, actor, parsed.value, f"viewed_{dataset}", evidence_id=filters.get("evidence_id"),
         artifact_id=filters.get("finding_id"), details=meta)
    return rows


def _export(conn, role, actor, resource: Resource, dataset: str, builder, pz, **filters) -> ExportResult:
    actor = _clean_actor(actor)
    for name in ("evidence_id", "finding_id"):
        _filter(name, filters.get(name))
    parsed = authorize(conn, actor, role, resource, Action.EXPORT)
    rows, meta = builder(conn, parsed, pz, **filters)
    content = _dumps({"dataset": dataset, "role": parsed.value, "identifiers": _label(parsed),
                      "exported_at": datetime.now(timezone.utc).isoformat(),
                      "row_count": len(rows), "rows": rows})
    encoded = content.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    meta.update(dataset=dataset, count=len(rows), identifiers=_label(parsed), export_sha256=digest,
                export_bytes=len(encoded),
                filters={k: v for k, v in filters.items() if k in ("evidence_id", "finding_id") and v})
    _log(conn, actor, parsed.value, f"exported_{dataset}", evidence_id=filters.get("evidence_id"),
         artifact_id=filters.get("finding_id"), details=meta)
    return ExportResult(dataset, parsed.value, content, digest, len(rows))


# ---------------------------------------------------------------------------
# Public API: what the Streamlit UI calls
# ---------------------------------------------------------------------------
def get_evidence(conn, role, actor, *, evidence_id=None, pseudonymizer: Pseudonymizer | None = None) -> list[dict]:
    return _view(conn, role, actor, Resource.EVIDENCE, "evidence", _build_evidence, pseudonymizer,
                 evidence_id=evidence_id)


def get_findings(conn, role, actor, *, evidence_id=None, finding_id=None,
                 pseudonymizer: Pseudonymizer | None = None) -> list[dict]:
    return _view(conn, role, actor, Resource.FINDINGS, "findings", _build_findings, pseudonymizer,
                 evidence_id=evidence_id, finding_id=finding_id)


def get_timeline(conn, role, actor, events, *, evidence_id=None,
                 pseudonymizer: Pseudonymizer | None = None) -> list[dict]:
    """`events` are the NormalizedEvents the parsers produced. They are raw: hand them to the UI only
    through this function, never directly."""
    return _view(conn, role, actor, Resource.TIMELINE, "timeline", _build_timeline, pseudonymizer,
                 events=events, evidence_id=evidence_id)


def get_custody_log(conn, role, actor, *, evidence_id=None, pseudonymizer: Pseudonymizer | None = None) -> list[dict]:
    return _view(conn, role, actor, Resource.CUSTODY_LOG, "custody_log", _build_custody, pseudonymizer,
                 evidence_id=evidence_id)


def export_findings(conn, role, actor, *, evidence_id=None, finding_id=None,
                    pseudonymizer: Pseudonymizer | None = None) -> ExportResult:
    return _export(conn, role, actor, Resource.FINDINGS, "findings", _build_findings, pseudonymizer,
                   evidence_id=evidence_id, finding_id=finding_id)


def export_timeline(conn, role, actor, events, *, evidence_id=None,
                    pseudonymizer: Pseudonymizer | None = None) -> ExportResult:
    return _export(conn, role, actor, Resource.TIMELINE, "timeline", _build_timeline, pseudonymizer,
                   events=events, evidence_id=evidence_id)


def export_custody_log(conn, role, actor, *, evidence_id=None,
                       pseudonymizer: Pseudonymizer | None = None) -> ExportResult:
    return _export(conn, role, actor, Resource.CUSTODY_LOG, "custody_log", _build_custody, pseudonymizer,
                   evidence_id=evidence_id)