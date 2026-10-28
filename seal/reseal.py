"""
The problem
    Every signature in Stamped will one day be weaker than it is today. A
    case sealed in 2026 may be challenged in 2041, when Ed25519 (and perhaps
    ML-DSA-65) is no longer trusted. Re-sealing lets the custodian wrap an old
    stretch of the custody log in a NEW checkpoint signed with a newer or
    stronger suite, without touching the historical record.

What a re-seal is
    One new custody-log entry, appended at the end of the chain like any other,
    with action "resealed". Its details contain a signed payload that
    REFERENCES a range of earlier entries:

        from_entry_id / to_entry_id   the range being wrapped
        entry_count                   how many entries that range holds
        first_entry_prev_hash         the prev_hash of the first entry in it
        last_entry_hash               the entry_hash of the last entry in it
        range_digest                  SHA-256 over the ordered entry hashes

    and carries two signatures over that payload made with the RENEWAL suite:
    Ed448 AND ML-DSA-87 (both must verify; the same "both, not either" rule as
    the original anchors). The renewal keys are separate from the case's
    original signing keys.

What it does NOT do
    * It never rewrites, re-hashes or re-signs an original entry. Doing so would
      change that entry's hash and look exactly like tampering. The new entry
      only points at the old hashes. Old entries, old anchors and old
      signatures stay byte for byte as they were and remain verifiable.
    * It does not add trust that the keys do not have. The application holds the
      renewal private keys, so an attacker who controls the application can
      sign a new re-seal. As with anchors, the protection comes from the
      re-seal being recorded in the hash chain and exported outside the
      application. See docs/reseal.md.

Verification is deliberately NOT in this module. verifier/verify.py
re-implements the rules from docs/reseal.md and imports nothing from `seal`.

CLI:
    python -m seal.reseal create-keys --case CASE
    python -m seal.reseal reseal --db DB --case CASE --from 1 --to 40
"""

import argparse
import base64
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey

import oqs  # real liboqs binding; ImportError/RuntimeError here is intentional

from seal import signing
from seal.custody_log import append_entry, fetch_chain_rows, verify_chain_rows

RESEAL_FORMAT = "stamped-reseal/1"
RESEAL_KEY_FORMAT = "stamped-reseal-key/1"
RESEAL_ACTION = "resealed"
CLASSICAL_ALGORITHM = "Ed448"
PQ_ALGORITHM = "ML-DSA-87"
RESEAL_KEY_DIR = "reseal"  # keys/<case>/reseal/<key_id>/ (private), keys/<case>/public/reseal/ (public)

_ED448_PRIV_FILE = "ed448_private.bin"
_MLDSA87_PRIV_FILE = "mldsa87_private.bin"


class ResealError(Exception):
    """Raised when a re-seal cannot be made. Callers should expect this."""


# ---------------------------------------------------------------------------
# Canonical bytes and the range digest (same pinned JSON settings as the
# custody log; see docs/custody-log-format.md and docs/reseal.md)
# ---------------------------------------------------------------------------
def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def payload_bytes(payload: dict) -> bytes:
    return canonical_json(payload).encode("utf-8")


def range_digest(entry_hashes: list[str]) -> str:
    """SHA-256 of the canonical JSON list of the range's entry hashes, in entry_id order."""
    return hashlib.sha256(canonical_json(list(entry_hashes)).encode("utf-8")).hexdigest()


def key_id_for(ed448_public: bytes, mldsa87_public: bytes) -> str:
    """A key set's identifier is a fingerprint of BOTH public keys, so it cannot be
    pointed at different keys without the identifier changing."""
    return hashlib.sha256(ed448_public + mldsa87_public).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Renewal keys
# ---------------------------------------------------------------------------
def create_reseal_keys(case_id: str, keys_dir: str | Path = signing.DEFAULT_KEYS_DIR) -> str:
    """Generate a renewal key set (Ed448 + ML-DSA-87) for a case and return its key id.

    Private keys go to keys/<case>/reseal/<key_id>/ (owner-only). The public keys
    go to keys/<case>/public/reseal/<key_id>.json, which is part of the exported
    public/ folder the independent verifier reads. Never overwrites existing keys.
    """
    try:
        signing._validate_case_id(case_id)
    except signing.KeyManagementError as exc:
        raise ResealError(str(exc)) from exc

    ed_priv = Ed448PrivateKey.generate()
    ed_priv_raw = ed_priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    ed_pub_raw = ed_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with oqs.Signature(PQ_ALGORITHM) as signer:
        pq_pub = signer.generate_keypair()
        pq_priv = signer.export_secret_key()

    key_id = key_id_for(ed_pub_raw, pq_pub)
    case_dir = Path(keys_dir) / case_id
    priv_dir = case_dir / RESEAL_KEY_DIR / key_id
    try:
        priv_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise ResealError(f"Renewal keys '{key_id}' already exist for case '{case_id}'; refusing to overwrite.") from exc
    priv_dir.chmod(0o700)
    signing._write_private(priv_dir / _ED448_PRIV_FILE, ed_priv_raw)
    signing._write_private(priv_dir / _MLDSA87_PRIV_FILE, pq_priv)

    pub_dir = case_dir / "public" / RESEAL_KEY_DIR
    pub_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "format": RESEAL_KEY_FORMAT,
        "key_id": key_id,
        "case_id": case_id,
        "classical": {"algorithm": CLASSICAL_ALGORITHM, "public_key_b64": base64.b64encode(ed_pub_raw).decode("ascii")},
        "post_quantum": {"algorithm": PQ_ALGORITHM, "public_key_b64": base64.b64encode(pq_pub).decode("ascii")},
        "rule": "A re-seal is valid only if BOTH signatures verify.",
    }
    (pub_dir / f"{key_id}.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return key_id


def _resolve_key_id(case_id: str, keys_dir: Path, key_id: str | None) -> str:
    root = keys_dir / case_id / RESEAL_KEY_DIR
    available = sorted(p.name for p in root.iterdir() if p.is_dir()) if root.is_dir() else []
    if key_id is not None:
        if key_id not in available:
            raise ResealError(f"No renewal keys '{key_id}' for case '{case_id}'.")
        return key_id
    if not available:
        raise ResealError(f"No renewal keys exist for case '{case_id}'. Run: python -m seal.reseal create-keys --case {case_id}")
    if len(available) > 1:
        raise ResealError(f"Several renewal key sets exist for case '{case_id}' ({', '.join(available)}); pass --key-id.")
    return available[0]


def _load_private_keys(case_id: str, keys_dir: Path, key_id: str) -> tuple[bytes, bytes]:
    priv_dir = keys_dir / case_id / RESEAL_KEY_DIR / key_id
    try:
        return (priv_dir / _ED448_PRIV_FILE).read_bytes(), (priv_dir / _MLDSA87_PRIV_FILE).read_bytes()
    except OSError as exc:
        raise ResealError(f"Cannot read renewal keys '{key_id}' for case '{case_id}': {type(exc).__name__}") from exc


# ---------------------------------------------------------------------------
# reseal_range
# ---------------------------------------------------------------------------
def reseal_range(
        conn: sqlite3.Connection,
        *,
        case_id: str,
        from_entry_id: int,
        to_entry_id: int | None = None,
        keys_dir: str | Path = signing.DEFAULT_KEYS_DIR,
        key_id: str | None = None,
        actor: str = "reseal-service",
        role: str = "examiner",
) -> dict:
    """
    Wrap custody entries `from_entry_id`..`to_entry_id` (default: through the
    current newest entry) in a new signed checkpoint and append it to the log.

    Steps: (1) take the write lock; (2) read the chain in one snapshot and
    REFUSE if it is already broken (re-sealing a tampered chain would certify
    the tampering); (3) summarise the range by reference to its existing
    hashes; (4) sign the summary with Ed448 AND ML-DSA-87; (5) append ONE new
    entry and commit. No existing row is read for modification, and none is
    modified.

    Returns {"entry_id", "entry_hash", "key_id", "payload"}.
    """
    keys_dir = Path(keys_dir)
    key_id = _resolve_key_id(case_id, keys_dir, key_id)
    ed_priv, pq_priv = _load_private_keys(case_id, keys_dir, key_id)

    opened_here = not conn.in_transaction
    if opened_here:
        conn.execute("BEGIN IMMEDIATE")  # the head we read must still be the head when we append
    try:
        rows = fetch_chain_rows(conn)
        if not rows:
            raise ResealError("The custody log is empty; there is nothing to re-seal.")
        ok, bad_entry = verify_chain_rows(rows)
        if not ok:
            raise ResealError(
                f"Refusing to re-seal: the custody chain is already broken at entry {bad_entry}. "
                "Re-sealing it would certify a tampered log."
            )

        if to_entry_id is None:
            to_entry_id = rows[-1][0]
        ids = {r[0] for r in rows}
        if from_entry_id not in ids or to_entry_id not in ids:
            raise ResealError(f"Entries #{from_entry_id} and #{to_entry_id} must both exist in the log.")
        if from_entry_id > to_entry_id:
            raise ResealError("The first entry of the range must not come after the last one.")

        segment = [r for r in rows if from_entry_id <= r[0] <= to_entry_id]
        payload = {
            "format": RESEAL_FORMAT,
            "case_id": case_id,
            "seq": 1 + sum(1 for r in rows if r[4] == RESEAL_ACTION),
            "resealed_at": datetime.now(timezone.utc).isoformat(),
            "from_entry_id": from_entry_id,
            "to_entry_id": to_entry_id,
            "entry_count": len(segment),
            "first_entry_prev_hash": segment[0][8],
            "last_entry_hash": segment[-1][9],
            "range_digest": range_digest([r[9] for r in segment]),
            "key_id": key_id,
            "suite": {"classical": CLASSICAL_ALGORITHM, "post_quantum": PQ_ALGORITHM},
            "renews": {"classical": "Ed25519", "post_quantum": signing.MLDSA_ALGORITHM},
        }
        message = payload_bytes(payload)
        sig_classical = Ed448PrivateKey.from_private_bytes(ed_priv).sign(message)
        with oqs.Signature(PQ_ALGORITHM, secret_key=pq_priv) as signer:
            sig_pq = signer.sign(message)

        entry_hash = append_entry(
            conn, actor=actor, role=role, action=RESEAL_ACTION,
            details={
                "format": RESEAL_FORMAT,
                "payload": payload,
                "payload_hash": hashlib.sha256(message).hexdigest(),
                "signatures": {
                    "ed448": base64.b64encode(sig_classical).decode("ascii"),
                    "ml_dsa_87": base64.b64encode(sig_pq).decode("ascii"),
                },
            },
        )
        entry_id = conn.execute("SELECT entry_id FROM custody_log WHERE entry_hash = ?", (entry_hash,)).fetchone()[0]
        if opened_here:
            conn.commit()
    except BaseException:
        if opened_here:
            conn.rollback()
        raise
    return {"entry_id": entry_id, "entry_hash": entry_hash, "key_id": key_id, "payload": payload}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    # A fixed string, NOT __doc__: docstrings are stripped under `python -OO`.
    parser = argparse.ArgumentParser(
        prog="python -m seal.reseal",
        description="Wrap an old stretch of the custody log in a new checkpoint signed with Ed448 + ML-DSA-87.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keys = sub.add_parser("create-keys", help="generate the renewal key set for a case")
    keys.add_argument("--case", required=True)
    keys.add_argument("--keys-dir", default=str(signing.DEFAULT_KEYS_DIR))

    rs = sub.add_parser("reseal", help="append a re-seal covering a range of entries")
    rs.add_argument("--db", required=True, help="path to the Stamped SQLite database")
    rs.add_argument("--case", required=True)
    rs.add_argument("--from", dest="from_entry", type=int, required=True, help="first entry id to cover")
    rs.add_argument("--to", dest="to_entry", type=int, default=None, help="last entry id to cover (default: newest)")
    rs.add_argument("--key-id", default=None, help="renewal key set to use (needed only if several exist)")
    rs.add_argument("--keys-dir", default=str(signing.DEFAULT_KEYS_DIR))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "create-keys":
            key_id = create_reseal_keys(args.case, args.keys_dir)
            print(f"Renewal keys created: {key_id}")
            print(f"  suite: {CLASSICAL_ALGORITHM} + {PQ_ALGORITHM}")
            print(f"  public keys: {Path(args.keys_dir) / args.case / 'public' / RESEAL_KEY_DIR / (key_id + '.json')}")
            print("  Include that public/ folder in every case export so the verifier can check re-seals.")
            return 0
        conn = sqlite3.connect(args.db, timeout=30)
        try:
            result = reseal_range(
                conn, case_id=args.case, from_entry_id=args.from_entry, to_entry_id=args.to_entry,
                keys_dir=args.keys_dir, key_id=args.key_id,
            )
        finally:
            conn.close()
        p = result["payload"]
        print(f"Re-seal appended as entry #{result['entry_id']}")
        print(f"  covers entries #{p['from_entry_id']} to #{p['to_entry_id']} ({p['entry_count']} entries)")
        print(f"  signed with {CLASSICAL_ALGORITHM} + {PQ_ALGORITHM}, key set {result['key_id']}")
        return 0
    except (ResealError, signing.KeyManagementError, sqlite3.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())