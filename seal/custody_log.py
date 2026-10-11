import json
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256

GENESIS_PREV_HASH = "0" * 64


def _canonical_json(fields: dict) -> str:
    # Every setting that affects the output is spelled out on purpose, so the
    # format never depends on library defaults. ensure_ascii=True makes the
    # output pure ASCII (non-ASCII becomes \uXXXX); allow_nan=False rejects
    # NaN/Infinity, which have no valid JSON form and would hash differently
    # across implementations.
    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


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

    # Pure computation first: if `details` cannot be serialised (e.g. NaN), we
    # fail before touching the database or taking any lock.
    details_json = _canonical_json(details or {})

    # Serialise writers. Reading the chain head and inserting the next entry
    # must happen under ONE write lock, otherwise two writers (e.g. the capture
    # listener and the dashboard) can read the same head and fork the chain,
    # which would later look exactly like tampering. If the caller already has
    # a transaction open (as seal_evidence does, having written the evidence
    # row first) it already holds the write lock, so we do not start another.
    opened_here = not conn.in_transaction
    if opened_here:
        conn.execute("BEGIN IMMEDIATE")

    try:
        timestamp_utc = datetime.now(timezone.utc).isoformat()
        prev_hash = _get_last_entry_hash(conn)

        fields = {
            "timestamp_utc": timestamp_utc,
            "actor": actor,
            "role": role,
            "action": action,
            "evidence_id": evidence_id,
            "artifact_id": artifact_id,
            "details_json": details_json,
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
                details_json, prev_hash, entry_hash,
            ),
        )
    except BaseException:
        # Never leave a write lock held because of a failed append that WE
        # started. A transaction the caller started stays the caller's to roll back.
        if opened_here:
            conn.rollback()
        raise
    return entry_hash


def recompute_and_verify_chain(conn: sqlite3.Connection) -> tuple[bool, int | None]:
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