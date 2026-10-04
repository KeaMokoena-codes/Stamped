import json
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256

GENESIS_PREV_HASH = "0" * 64


def _canonical_json(fields: dict) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def _compute_entry_hash(fields: dict, prev_hash: str) -> str:
    payload = _canonical_json(fields) + prev_hash
    return sha256(payload.encode("utf-8")).hexdigest()


def _get_last_entry_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT entry_hash FROM custody_log ORDER BY entry_id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else GENESIS_PREV_HASH


def append_entry(
        conn: sqlite3.Connection,
        actor: str,
        role: str,
        action: str,
        evidence_id: str | None = None,
        artifact_id: str | None = None,
        details: dict | None = None,
) -> str:
    """
    Append one entry to the custody log. Returns the new entry's hash.

    Deliberately does NOT call conn.commit() — the caller controls the
    transaction boundary. This matters for callers like seal_evidence(),
    which need the evidence row and its first custody entry to commit
    (or roll back) together as one atomic unit; auto-committing here
    would make that impossible.

    This function deliberately exposes no way to update or delete an
    existing entry — that is intentional, not an oversight. Do not add
    update_entry / delete_entry functions to this file (see AI Guardrails
    in Issue #1.2 and the CI guardrail check that enforces this).
    """
    timestamp_utc = datetime.now(timezone.utc).isoformat()
    prev_hash = _get_last_entry_hash(conn)

    fields = {
        "timestamp_utc": timestamp_utc,
        "actor": actor,
        "role": role,
        "action": action,
        "evidence_id": evidence_id,
        "artifact_id": artifact_id,
        "details_json": _canonical_json(details or {}),
    }
    entry_hash = _compute_entry_hash(fields, prev_hash)

    conn.execute(
        """
        INSERT INTO custody_log
        (timestamp_utc, actor, role, action, evidence_id, artifact_id,
         details_json, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp_utc, actor, role, action, evidence_id, artifact_id,
            fields["details_json"], prev_hash, entry_hash,
        ),
    )
    return entry_hash


def recompute_and_verify_chain(conn: sqlite3.Connection) -> tuple[bool, int | None]:
    """
    Walk the whole log in order and recompute each entry_hash from its
    stored fields plus the previous entry's hash. Returns (True, None) if
    every entry matches, or (False, entry_id) for the first entry whose
    recomputed hash doesn't match what's stored.

    This is a basic, in-module check — the real independent verifier
    (Issue #1.5) must not import this function, since it has to stay
    independent of the app's own code.
    """
    rows = conn.execute(
        """
        SELECT entry_id, timestamp_utc, actor, role, action, evidence_id,
            artifact_id, details_json, prev_hash, entry_hash
        FROM custody_log ORDER BY entry_id ASC
        """
    ).fetchall()

    expected_prev = GENESIS_PREV_HASH
    for row in rows:
        (entry_id, timestamp_utc, actor, role, action, evidence_id,
         artifact_id, details_json, prev_hash, stored_hash) = row

        if prev_hash != expected_prev:
            return False, entry_id

        fields = {
            "timestamp_utc": timestamp_utc,
            "actor": actor,
            "role": role,
            "action": action,
            "evidence_id": evidence_id,
            "artifact_id": artifact_id,
            "details_json": details_json,
        }
        recomputed = _compute_entry_hash(fields, prev_hash)
        if recomputed != stored_hash:
            return False, entry_id

        expected_prev = stored_hash

    return True, None