"""
External anchoring of the custody log chain head (Issue #7).

An anchor is a small, hybrid-signed record of "the log looked like THIS at
time T": the id and hash of the newest entry, how many entries existed, and a
link to the previous anchor. It is written to a location OUTSIDE the
application's own tree. Later, anyone can compare the live log to the stored
anchors, which exposes two attacks the hash chain alone cannot:

  * deleting the newest entries (a shorter chain is still self-consistent)
  * rewriting an entry and recomputing every later hash

IMPORTANT, plainly stated:
  * The protection comes from WHERE the anchor is stored, not from the
    signature. The app holds the signing keys, so an attacker who controls the
    app can sign new anchors. They cannot alter anchors already sitting on
    storage they cannot write to. See docs/anchoring.md for exactly what that
    storage must look like and what this does NOT protect against.
  * `anchored_at` is the application's clock, not a trusted timestamp.
  * Entries added after the newest anchor are unprotected until the next one.

Verification is deliberately NOT in this module. It lives in
verifier/anchor_check.py, which imports nothing from `seal`, so it cannot share
a bug with the code that created the anchors.

CLI:
    python -m seal.anchor create --db DB --case CASE --anchor-dir DIR
    python -m seal.anchor watch  --db DB --case CASE --anchor-dir DIR --interval 300
"""

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from seal import signing
from seal.custody_log import (
    GENESIS_PREV_HASH,
    append_entry,
    fetch_chain_rows,
    verify_chain_rows,
)

ANCHOR_FORMAT = "stamped-anchor/1"
ANCHOR_TYPE = "signed-file"
ANCHOR_FILE_RE = re.compile(r"^anchor_(\d{6})\.json$")
REPO_ROOT = Path(__file__).resolve().parent.parent


class AnchorError(Exception):
    """Raised when an anchor cannot be created. Callers should expect this."""


# ---------------------------------------------------------------------------
# Canonical bytes (same pinned settings as the custody log; see
# docs/custody-log-format.md and docs/anchoring.md)
# ---------------------------------------------------------------------------
def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def payload_bytes(payload: dict) -> bytes:
    return canonical_json(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# Location checks: "outside the application's write path" must be enforced,
# not just documented
# ---------------------------------------------------------------------------
def _db_file_path(conn: sqlite3.Connection) -> Path | None:
    for _, name, file in conn.execute("PRAGMA database_list").fetchall():
        if name == "main" and file:
            return Path(file).resolve()
    return None  # in-memory database


def _is_within(a: Path, b: Path) -> bool:
    """True if a is b or lies inside b."""
    return a == b or b in a.parents


def check_anchor_location(anchor_dir: Path, db_path: Path | None) -> str:
    """Refuse anchor locations that defeat the purpose; classify the rest.

    Raises AnchorError if anchor_dir is inside, contains, or equals the
    application's own tree (repo root) or the directory holding the database,
    which is exactly the "different file in the same writable directory"
    anti-pattern. Otherwise returns an assurance label that is recorded with
    the anchor:  "separate_device" or "same_device".
    """
    anchor_dir = anchor_dir.resolve()
    app_trees = {"the application directory": REPO_ROOT}
    if db_path is not None:
        app_trees["the database directory"] = db_path.parent

    for label, tree in app_trees.items():
        if _is_within(anchor_dir, tree) or _is_within(tree, anchor_dir):
            raise AnchorError(
                f"Refusing to anchor into '{anchor_dir}': it overlaps {label} ('{tree}'). "
                "An anchor the application can rewrite alongside the data it protects "
                "proves nothing. Use a separate medium, mount, or machine."
            )

    if db_path is not None and os.stat(anchor_dir).st_dev == os.stat(db_path.parent).st_dev:
        return "same_device"
    return "separate_device"


# ---------------------------------------------------------------------------
# The anchor sink: write-once files, one per anchor, never overwritten
# ---------------------------------------------------------------------------
def _list_anchor_files(anchor_dir: Path) -> list[tuple[int, Path]]:
    found = []
    for p in anchor_dir.iterdir():
        m = ANCHOR_FILE_RE.match(p.name)
        if m:
            found.append((int(m.group(1)), p))
    return sorted(found)


def _read_anchor_payload(path: Path) -> dict:
    """Read one anchor file's payload. A file that is merely still being written
    by another process (possible on filesystems without hard links) gets a short
    grace period before it is treated as damaged."""
    last_exc: Exception | None = None
    for _ in range(10):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            payload = dict(record["payload"])
            payload["_anchor_hash"] = record["anchor_hash"]
            int(payload["head_entry_id"])
            return payload
        except (OSError, ValueError, KeyError, TypeError) as exc:
            last_exc = exc
            time.sleep(0.05)
    raise AnchorError(
        f"The anchor file '{path.name}' is unreadable or malformed "
        f"({type(last_exc).__name__}). Investigate before anchoring further."
    ) from last_exc


def _read_previous_anchor(anchor_dir: Path) -> tuple[int, str, int]:
    """Return (last_seq, last_anchor_hash, last_head_entry_id); (0, genesis, 0) if
    none yet. Refuses to build on top of a damaged previous anchor."""
    files = _list_anchor_files(anchor_dir)
    if not files:
        return 0, GENESIS_PREV_HASH, 0
    seq, path = files[-1]
    payload = _read_anchor_payload(path)
    return seq, payload["_anchor_hash"], int(payload["head_entry_id"])


def _assert_log_matches_existing_anchors(anchor_dir: Path, rows: list[tuple]) -> None:
    """Refuse to anchor a log that CONTRADICTS an anchor already on record.

    A perfectly rewritten chain recomputes cleanly, so "the chain is not broken"
    is not enough: anchoring it would add a new anchor over forged history. Every
    earlier anchor's entry must still be in the log with the same hash.
    (Signatures are not re-checked here; verifier/anchor_check.py does the full check.)
    """
    live_hash_by_id = {r[0]: r[9] for r in rows}
    for seq, path in _list_anchor_files(anchor_dir):
        payload = _read_anchor_payload(path)
        head_id = int(payload["head_entry_id"])
        if head_id not in live_hash_by_id:
            raise AnchorError(
                f"Refusing to anchor: {path.name} covers entry #{head_id}, which is no longer in the "
                "log. Entries were deleted after that anchor was made."
            )
        if live_hash_by_id[head_id] != payload["head_entry_hash"]:
            raise AnchorError(
                f"Refusing to anchor: entry #{head_id} no longer has the hash recorded in {path.name}. "
                "History was rewritten after that anchor was made."
            )


def _write_new_file(path: Path, data: bytes) -> None:
    """Publish `path` atomically, and never overwrite an existing file.

    The data is written and flushed to a temporary file first, then linked into
    place in a single step. A reader therefore sees either no file or the
    complete file, never a half-written anchor. os.link fails with
    FileExistsError if `path` already exists, which is the no-overwrite guarantee.

    On a filesystem without hard links (e.g. FAT/exFAT USB sticks) we fall back
    to exclusive-create; there a reader could briefly see a partial file, which
    _read_previous_anchor tolerates.
    """
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    with open(tmp, "xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    try:
        try:
            os.link(tmp, path)
        except FileExistsError:
            raise
        except OSError:
            with open(path, "xb") as f:  # "x": still never overwrites
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    os.chmod(path, 0o444)


# ---------------------------------------------------------------------------
# create_anchor
# ---------------------------------------------------------------------------
def create_anchor(
        conn: sqlite3.Connection,
        *,
        case_id: str,
        anchor_dir: str | Path,
        keys_dir: str | Path = signing.DEFAULT_KEYS_DIR,
        actor: str = "anchor-service",
        role: str = "examiner",
) -> dict:
    """
    Sign the current custody-log head and write the record to `anchor_dir`.

    Steps: (1) read the whole chain in one snapshot and REFUSE if it is already
    broken (anchoring a tampered chain would bless the tampering); (2) refuse
    unsuitable locations;
    (3) sign the payload with both Ed25519 and ML-DSA; (4) write a new
    write-once file externally; (5) record it in the anchors table and the
    custody log in one transaction.

    The external file is authoritative. If step 5 fails the external anchor
    still stands (and is still valid); the error says where it is.

    Returns the anchor record dict that was written.
    """
    anchor_dir = Path(anchor_dir)
    if not anchor_dir.is_dir():
        raise AnchorError(
            f"Anchor directory '{anchor_dir}' does not exist. It is not created "
            "automatically: if it is a USB stick or mount that is not attached, a new "
            "local folder would silently defeat the purpose."
        )
    location_assurance = check_anchor_location(anchor_dir, _db_file_path(conn))

    ed_priv, mldsa_priv = signing.load_private_keys(case_id, Path(keys_dir))

    last_error = None
    stale_rereads = 0
    for _ in range(20):
        # Re-read the chain on every attempt. If another process anchored while we
        # were working, our snapshot may now be OLDER than the newest anchor, and
        # writing it would make the anchors appear to go backwards.
        rows = fetch_chain_rows(conn)
        if not rows:
            raise AnchorError("The custody log is empty; there is nothing to anchor.")
        ok, bad_entry = verify_chain_rows(rows)
        if not ok:
            raise AnchorError(
                f"Refusing to anchor: the custody chain is already broken at entry {bad_entry}. "
                "Anchoring it would certify a tampered log."
            )
        head_entry_id, head_entry_hash = rows[-1][0], rows[-1][9]
        entry_count = len(rows)

        last_seq, prev_anchor_hash, prev_head_id = _read_previous_anchor(anchor_dir)
        if prev_head_id > head_entry_id and stale_rereads < 3:
            # Our snapshot is older than the newest anchor. That is normally a race
            # with another process, which a fresh read cures. If fresh reads are
            # STILL shorter than an anchor it is not a race: fall through, and the
            # check below reports the truncation.
            stale_rereads += 1
            continue
        _assert_log_matches_existing_anchors(anchor_dir, rows)
        seq = last_seq + 1
        payload = {
            "format": ANCHOR_FORMAT,
            "case_id": case_id,
            "seq": seq,
            "anchored_at": datetime.now(timezone.utc).isoformat(),
            "head_entry_id": head_entry_id,
            "head_entry_hash": head_entry_hash,
            "entry_count": entry_count,
            "prev_anchor_hash": prev_anchor_hash,
        }
        message = payload_bytes(payload)
        sig_classical, sig_pq = signing.sign_hybrid(message, ed_priv, mldsa_priv)

        record = {
            "format": ANCHOR_FORMAT,
            "payload": payload,
            "anchor_hash": hashlib.sha256(message).hexdigest(),
            "signatures": {
                "ed25519": base64.b64encode(sig_classical).decode("ascii"),
                "ml_dsa_65": base64.b64encode(sig_pq).decode("ascii"),
            },
            # Unsigned, informational: where this was written relative to the DB.
            "meta": {"location_assurance": location_assurance},
        }
        path = anchor_dir / f"anchor_{seq:06d}.json"
        try:
            _write_new_file(path, json.dumps(record, indent=2, sort_keys=True).encode("utf-8"))
            break
        except FileExistsError as exc:
            last_error = exc  # another writer took this number; retry with fresh state
        except OSError as exc:
            # Do not leave a half-written anchor behind for the verifier to trip over.
            if path.exists():
                with contextlib.suppress(OSError):  # best-effort cleanup; the real error is raised below
                    os.chmod(path, 0o644)
                    path.unlink()
            raise AnchorError(f"Could not write anchor to '{anchor_dir}': {exc}") from exc
    else:
        raise AnchorError("Could not claim an anchor sequence number after 20 attempts.") from last_error

    anchor_id = "anc-" + record["anchor_hash"][:20]
    try:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")  # one lock for the anchors row AND the custody entry
        conn.execute(
            "INSERT INTO anchors (anchor_id, entry_hash, anchor_type, anchored_at, "
            "external_reference, proof_json) VALUES (?, ?, ?, ?, ?, ?)",
            (anchor_id, head_entry_hash, ANCHOR_TYPE, payload["anchored_at"],
             str(path), canonical_json(record)),
        )
        append_entry(
            conn, actor=actor, role=role, action="anchored",
            details={
                "anchor_id": anchor_id,
                "anchored_entry_id": head_entry_id,
                "anchored_entry_hash": head_entry_hash,
                "seq": seq,
                "location_assurance": location_assurance,
            },
        )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise AnchorError(
            f"The anchor WAS written externally ('{path}') and is valid, but recording it "
            f"in the database failed: {exc}"
        ) from exc

    record["anchor_id"] = anchor_id
    record["path"] = str(path)
    return record


# ---------------------------------------------------------------------------
# Periodic anchoring
# ---------------------------------------------------------------------------
def has_unanchored_entries(conn: sqlite3.Connection) -> bool:
    """True if a real (non-'anchored') entry exists that no anchor covers yet.
    Anchoring writes its own 'anchored' entry; ignoring those stops the
    periodic job from re-anchoring forever because of its own bookkeeping."""
    newest_real = conn.execute(
        "SELECT MAX(entry_id) FROM custody_log WHERE action != 'anchored'"
    ).fetchone()[0]
    if newest_real is None:
        return False
    last_anchored = conn.execute(
        "SELECT MAX(c.entry_id) FROM custody_log c "
        "JOIN anchors a ON a.entry_hash = c.entry_hash"
    ).fetchone()[0]
    return last_anchored is None or newest_real > last_anchored


def watch(
        db_path: str | Path,
        *,
        case_id: str,
        anchor_dir: str | Path,
        keys_dir: str | Path = signing.DEFAULT_KEYS_DIR,
        interval_seconds: float = 300,
        stop_event: threading.Event | None = None,
        max_rounds: int | None = None,
        log=print,
) -> int:
    """Anchor every `interval_seconds` if anything new happened. Returns the
    number of anchors created. Stops on stop_event / max_rounds / Ctrl-C."""
    stop_event = stop_event or threading.Event()
    created = 0
    rounds = 0
    try:
        while not stop_event.is_set():
            conn = sqlite3.connect(db_path, timeout=30)
            try:
                if has_unanchored_entries(conn):
                    record = create_anchor(conn, case_id=case_id, anchor_dir=anchor_dir, keys_dir=keys_dir)
                    created += 1
                    log(f"anchored entry {record['payload']['head_entry_id']} -> {record['path']}")
                else:
                    log("no new entries since the last anchor; skipping")
            finally:
                conn.close()
            rounds += 1
            if max_rounds is not None and rounds >= max_rounds:
                break
            stop_event.wait(interval_seconds)
    except KeyboardInterrupt:
        log("stopped")
    return created


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    # A fixed string, NOT __doc__: docstrings are stripped under `python -OO` (or if a
    # tool removes them), and a CLI must not crash because of that.
    parser = argparse.ArgumentParser(
        prog="python -m seal.anchor",
        description="Sign the current custody-log head and write the anchor to separate storage.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name, helptext in (("create", "anchor the current chain head once"),
                           ("watch", "anchor repeatedly on an interval")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--db", required=True, help="path to the Stamped SQLite database")
        p.add_argument("--case", required=True, help="case id whose keys sign the anchor")
        p.add_argument("--anchor-dir", required=True, help="EXISTING directory on separate storage")
        p.add_argument("--keys-dir", default=str(signing.DEFAULT_KEYS_DIR))
        if name == "watch":
            p.add_argument("--interval", type=float, default=300, help="seconds between checks")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "create":
            conn = sqlite3.connect(args.db, timeout=30)
            try:
                record = create_anchor(conn, case_id=args.case, anchor_dir=args.anchor_dir, keys_dir=args.keys_dir)
            finally:
                conn.close()
            p = record["payload"]
            print(f"Anchor created:   {record['path']}")
            print(f"  anchored entry: #{p['head_entry_id']}  ({p['head_entry_hash'][:16]}...)")
            print(f"  entries covered: {p['entry_count']}   sequence: {p['seq']}")
            assurance = record["meta"]["location_assurance"]
            print(f"  location:       {assurance}")
            if assurance == "same_device":
                print("  WARNING: the anchor is on the SAME device as the database. This is only "
                      "acceptable for development. Use separate storage for real evidence.")
            return 0
        watch(args.db, case_id=args.case, anchor_dir=args.anchor_dir,
              keys_dir=args.keys_dir, interval_seconds=args.interval)
        return 0
    except (AnchorError, signing.KeyManagementError, sqlite3.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())