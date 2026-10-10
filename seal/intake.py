import json
import shutil
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from seal.custody_log import append_entry

DEFAULT_SEALED_DIR = Path(__file__).resolve().parent.parent / "data" / "sealed"


class IntakeError(Exception):
    """Raised when a file cannot be sealed. Callers should expect this —
    it is not a crash, it's a documented, loggable failure mode."""


def _hash_file_bytes(file_path: Path) -> str:
    """Hash the file's actual bytes, read in chunks so large files don't
    need to be loaded into memory all at once. This must operate on raw
    bytes — never on a string representation, filename, or dict."""
    hasher = sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def seal_evidence(
        conn: sqlite3.Connection,
        file_path: str | Path,
        metadata: dict | None = None,
        actor: str = "system",
        role: str = "examiner",
        sealed_dir: Path = DEFAULT_SEALED_DIR,
) -> str:
    """
    Seal a file: hash it, store a read-only copy, register it, and log
    the first custody entry. Returns the evidence_id (the content hash).

    Raises IntakeError if the file can't be read. On failure, a
    "seal_failed" custody entry is written (sealing failure is itself
    a loggable event) and no partial evidence row is left behind.
    """
    file_path = Path(file_path)
    metadata = metadata or {}

    if not file_path.is_file():
        append_entry(
            conn, actor=actor, role=role, action="seal_failed",
            details={"reason": "file_not_found", "attempted_path": str(file_path)},
        )
        conn.commit()
        raise IntakeError(f"Cannot seal: '{file_path}' is not a file or does not exist.")

    try:
        content_hash = _hash_file_bytes(file_path)
    except OSError as e:
        append_entry(
            conn, actor=actor, role=role, action="seal_failed",
            details={"reason": "read_error", "error": str(e), "attempted_path": str(file_path)},
        )
        conn.commit()
        raise IntakeError(f"Cannot seal '{file_path}': {e}") from e

    evidence_id = content_hash

    # Duplicate intake: same content hash already sealed. Per this
    # ticket's Definition of Done, we treat this as a logged re-intake
    # rather than silently no-op'ing or raising — the fact that someone
    # attempted to re-seal the same evidence is itself worth recording.
    existing = conn.execute(
        "SELECT evidence_id FROM evidence WHERE evidence_id = ?", (evidence_id,)
    ).fetchone()
    if existing:
        append_entry(
            conn, actor=actor, role=role, action="re_intake",
            evidence_id=evidence_id,
            details={"note": "content_hash already sealed; no new file copy made"},
        )
        conn.commit()
        return evidence_id

    sealed_dir.mkdir(parents=True, exist_ok=True)
    sealed_path = sealed_dir / content_hash

    try:
        if sealed_path.exists():
            # A sealed copy with this hash already exists but has no evidence row:
            # a previous seal failed after the copy and was rolled back. The copy is
            # read-only, so re-copying over it would fail and block every retry.
            # The path is content-addressed, so it is safe to reuse ONLY if its bytes
            # really hash to the expected value. Never trust it on name alone.
            if _hash_file_bytes(sealed_path) != content_hash:
                append_entry(
                    conn, actor=actor, role=role, action="seal_failed",
                    details={"reason": "existing_sealed_copy_hash_mismatch",
                             "sealed_path": str(sealed_path)},
                )
                conn.commit()
                raise IntakeError(
                    f"Cannot seal '{file_path}': a file already at '{sealed_path}' does "
                    "not match its content hash. Investigate before retrying."
                )
        else:
            shutil.copy2(file_path, sealed_path)
            sealed_path.chmod(0o444)  # read-only, best-effort (platform dependent)
    except OSError as e:
        append_entry(
            conn, actor=actor, role=role, action="seal_failed",
            details={"reason": "copy_error", "error": str(e)},
        )
        conn.commit()
        raise IntakeError(f"Cannot seal '{file_path}': failed to store sealed copy: {e}") from e

    sealed_at = datetime.now(timezone.utc).isoformat()

    # Evidence registration and its first custody entry are written in the
    # same transaction and committed together. Neither call above commits
    # on its own, so if either statement below fails, rolling back undoes
    # both — there is no state where sealing "succeeded" but the custody
    # entry didn't, or vice versa.
    try:
        conn.execute(
            """
            INSERT INTO evidence
            (evidence_id, content_hash, sealed_path, source, collector,
             original_name, captured_at, sealed_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id, content_hash, str(sealed_path),
                metadata.get("source"), metadata.get("collector"),
                file_path.name, metadata.get("captured_at"), sealed_at,
                json.dumps(metadata, sort_keys=True),
            ),
        )
        append_entry(
            conn, actor=actor, role=role, action="sealed",
            evidence_id=evidence_id,
            details={"content_hash": content_hash, "sealed_path": str(sealed_path)},
        )
        conn.commit()
    except Exception:
        conn.rollback()
        # The sealed file copy on disk is orphaned at this point, which is
        # safer than a DB row with no custody entry — it can be cleaned up
        # or re-sealed, whereas a logged-but-unregistered seal cannot.
        raise

    return evidence_id