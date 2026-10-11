#!/usr/bin/env python3
import argparse
import base64
import binascii
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ANCHOR_FORMAT = "stamped-anchor/1"
GENESIS = "0" * 64
ANCHOR_FILE_RE = re.compile(r"^anchor_(\d{6})\.json$")
ED25519_PUB_FILE = "ed25519_public.bin"
MLDSA_PUB_FILE = "mldsa65_public.bin"
MLDSA_ALG = "ML-DSA-65"

REQUIRED_PAYLOAD_TYPES = {
    "format": str, "case_id": str, "seq": int, "anchored_at": str,
    "head_entry_id": int, "head_entry_hash": str, "entry_count": int,
    "prev_anchor_hash": str,
}


class CheckerError(Exception):
    """The check could not be run at all (not the same as 'tampering found')."""


# ---------------------------------------------------------------------------
# Spec re-implementation (do not import these from the app)
# ---------------------------------------------------------------------------
def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _entry_hash(fields: dict, prev_hash: str) -> str:
    return hashlib.sha256((_canonical(fields) + prev_hash).encode("utf-8")).hexdigest()


def verify_chain(rows: list[tuple]) -> tuple[bool, int | None]:
    """rows: (entry_id, timestamp_utc, actor, role, action, evidence_id,
    artifact_id, details_json, prev_hash, entry_hash), oldest first."""
    expected_prev = GENESIS
    for (entry_id, ts, actor, role, action, ev, art, details, prev, stored) in rows:
        if prev != expected_prev:
            return False, entry_id
        fields = {
            "timestamp_utc": ts, "actor": actor, "role": role, "action": action,
            "evidence_id": ev, "artifact_id": art, "details_json": details,
        }
        if _entry_hash(fields, prev) != stored:
            return False, entry_id
        expected_prev = stored
    return True, None


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
def read_chain_rows(db_path: str | Path) -> list[tuple]:
    """Read the log through a READ-ONLY connection: the checker never writes."""
    path = Path(db_path)
    if not path.is_file():
        raise CheckerError(f"Database file not found: {path}")
    uri = path.resolve().as_uri() + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
        try:
            return conn.execute(
                "SELECT entry_id, timestamp_utc, actor, role, action, evidence_id, "
                "artifact_id, details_json, prev_hash, entry_hash "
                "FROM custody_log ORDER BY entry_id ASC"
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise CheckerError(f"Could not read the custody log from {path}: {exc}") from exc


def load_public_keys(public_dir: str | Path) -> tuple[bytes, bytes]:
    public_dir = Path(public_dir)
    try:
        return (
            (public_dir / ED25519_PUB_FILE).read_bytes(),
            (public_dir / MLDSA_PUB_FILE).read_bytes(),
        )
    except OSError as exc:
        raise CheckerError(f"Could not read public keys from {public_dir}: {exc}") from exc


def _load_oqs():
    try:
        import oqs  # noqa: PLC0415  (lazy on purpose: report a clear error, not an ImportError trace)
        return oqs
    except Exception as exc:
        raise CheckerError(
            "liboqs (ML-DSA) is not available, so post-quantum signatures cannot be "
            f"checked ({type(exc).__name__}). Refusing to report a result."
        ) from exc


def _verify_ed25519(msg: bytes, sig: bytes, pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _verify_mldsa(oqs, msg: bytes, sig: bytes, pub: bytes) -> bool:
    try:
        with oqs.Signature(MLDSA_ALG) as verifier:
            return bool(verifier.verify(msg, sig, pub))
    except Exception:  # a malformed signature or key means "invalid", never a crash
        return False


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------
def check_anchors(
        db_path: str | Path,
        anchor_dir: str | Path,
        public_dir: str | Path,
        *,
        require_anchor: bool = True,
) -> dict:
    """Return a result dict. result["ok"] is True ONLY if the chain recomputes
    cleanly AND at least one anchor exists AND every anchor is authentic,
    correctly linked, and consistent with the live chain."""
    anchor_dir = Path(anchor_dir)
    if not anchor_dir.is_dir():
        raise CheckerError(f"Anchor directory not found: {anchor_dir}")

    oqs = _load_oqs()
    ed_pub, mldsa_pub = load_public_keys(public_dir)
    rows = read_chain_rows(db_path)

    failures: list[dict] = []
    warnings: list[str] = []

    def fail(code: str, message: str, **extra):
        failures.append({"code": code, "message": message, **extra})

    # 1) the chain must recompute cleanly on its own
    chain_ok, bad_entry = verify_chain(rows)
    if not chain_ok:
        fail("chain_broken", f"The hash chain is broken at entry {bad_entry}.", entry_id=bad_entry)

    live_hash_by_id = {r[0]: r[9] for r in rows}
    live_ids_sorted = sorted(live_hash_by_id)

    # 2) read the anchor files
    found: dict[int, Path] = {}
    for p in sorted(anchor_dir.iterdir()):
        m = ANCHOR_FILE_RE.match(p.name)
        if m:
            found[int(m.group(1))] = p
        elif p.is_file():
            warnings.append(f"Ignored unexpected file in anchor directory: {p.name}")

    if not found:
        if require_anchor:
            fail("no_anchors", "No anchors found. The log cannot be checked against anything external.")
        else:
            warnings.append("No anchors found; nothing external was checked.")

    if found:
        missing = [n for n in range(1, max(found) + 1) if n not in found]
        if missing:
            fail("anchor_sequence_gap",
                 f"Anchor file(s) missing from the sequence: {missing}. An anchor may have been removed.",
                 missing=missing)

    # 3) check each anchor, oldest first
    prev_hash_seen = GENESIS
    prev_payload = None
    latest = None
    checked = 0
    for seq in sorted(found):
        path = found[seq]
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            payload = record["payload"]
            sigs = record["signatures"]
            claimed_hash = record["anchor_hash"]
            if record.get("format") != ANCHOR_FORMAT:
                raise KeyError("format")
            for key, typ in REQUIRED_PAYLOAD_TYPES.items():
                if not isinstance(payload[key], typ) or isinstance(payload[key], bool):
                    raise TypeError(key)
            if payload["format"] != ANCHOR_FORMAT:
                raise KeyError("payload.format")
            sig_c = base64.b64decode(sigs["ed25519"], validate=True)
            sig_pq = base64.b64decode(sigs["ml_dsa_65"], validate=True)
        except (OSError, ValueError, KeyError, TypeError, binascii.Error) as exc:
            fail("anchor_unreadable",
                 f"{path.name} is unreadable or malformed ({type(exc).__name__}: {exc}).", anchor_seq=seq)
            continue

        checked += 1
        message = _canonical(payload).encode("utf-8")

        if hashlib.sha256(message).hexdigest() != claimed_hash:
            fail("anchor_hash_mismatch", f"{path.name}: stored anchor_hash does not match its contents.", anchor_seq=seq)
        if payload["seq"] != seq:
            fail("anchor_seq_mismatch", f"{path.name}: file number {seq} disagrees with its signed sequence {payload['seq']}.", anchor_seq=seq)

        ed_ok = _verify_ed25519(message, sig_c, ed_pub)
        pq_ok = _verify_mldsa(oqs, message, sig_pq, mldsa_pub)
        if not (ed_ok and pq_ok):
            which = [n for n, ok in (("Ed25519", ed_ok), ("ML-DSA", pq_ok)) if not ok]
            fail("anchor_signature_invalid",
                 f"{path.name}: signature check failed for {' and '.join(which)}. Both must verify.", anchor_seq=seq)

        if payload["prev_anchor_hash"] != prev_hash_seen:
            fail("anchor_link_broken",
                 f"{path.name}: does not link to the previous anchor (an anchor was altered, replaced or removed).",
                 anchor_seq=seq)
        prev_hash_seen = claimed_hash

        if prev_payload is not None:
            if payload["head_entry_id"] < prev_payload["head_entry_id"] or payload["entry_count"] < prev_payload["entry_count"]:
                fail("anchor_regression", f"{path.name}: covers LESS of the log than the previous anchor.", anchor_seq=seq)
            if payload["anchored_at"] < prev_payload["anchored_at"]:
                warnings.append(f"{path.name}: anchored_at is earlier than the previous anchor (clock change?).")
        prev_payload = payload

        # 4) compare with the LIVE chain
        head_id = payload["head_entry_id"]
        if head_id not in live_hash_by_id:
            fail("anchored_entry_missing",
                 f"{path.name}: anchored entry #{head_id} is not in the live log "
                 f"(live log ends at #{live_ids_sorted[-1] if live_ids_sorted else 'nothing'}). "
                 "Entries were deleted after this anchor was made.",
                 anchor_seq=seq, entry_id=head_id)
        else:
            if live_hash_by_id[head_id] != payload["head_entry_hash"]:
                fail("anchored_hash_mismatch",
                     f"{path.name}: entry #{head_id} no longer has the hash that was anchored. "
                     "History was rewritten after this anchor was made.",
                     anchor_seq=seq, entry_id=head_id)
            covered = sum(1 for i in live_ids_sorted if i <= head_id)
            if covered != payload["entry_count"]:
                fail("anchored_entry_count_mismatch",
                     f"{path.name}: {payload['entry_count']} entries existed up to #{head_id} when anchored, "
                     f"but {covered} do now.", anchor_seq=seq)
        latest = payload

    unanchored = 0
    if latest is not None:
        unanchored = sum(1 for i in live_ids_sorted if i > latest["head_entry_id"])
        if unanchored:
            warnings.append(
                f"{unanchored} {'entry' if unanchored == 1 else 'entries'} after the newest anchor "
                f"(#{latest['head_entry_id']}) {'is' if unanchored == 1 else 'are'} not externally protected yet."
            )

    return {
        "ok": not failures,
        "failures": failures,
        "warnings": warnings,
        "anchors_checked": checked,
        "latest_anchor": None if latest is None else {
            "seq": latest["seq"], "head_entry_id": latest["head_entry_id"],
            "anchored_at": latest["anchored_at"],
        },
        "unanchored_entries": unanchored,
        "chain": {"ok": chain_ok, "first_bad_entry": bad_entry, "entries": len(rows)},
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def render_report(result: dict) -> str:
    lines = ["ANCHOR CHECK: " + ("PASS" if result["ok"] else "FAIL"), ""]
    lines.append(f"  chain entries recomputed : {result['chain']['entries']} "
                 f"({'ok' if result['chain']['ok'] else 'BROKEN at #' + str(result['chain']['first_bad_entry'])})")
    lines.append(f"  anchors checked          : {result['anchors_checked']}")
    if result["latest_anchor"]:
        la = result["latest_anchor"]
        lines.append(f"  newest anchor            : #{la['seq']} covering entry #{la['head_entry_id']} at {la['anchored_at']}")
    for f in result["failures"]:
        lines.append(f"  FAIL [{f['code']}] {f['message']}")
    for w in result["warnings"]:
        lines.append(f"  note: {w}")
    if result["ok"]:
        lines += ["", "  This shows the log matches what was anchored. It does not cover entries added",
                  "  after the newest anchor, and it is only as strong as the storage the anchors sit on."]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a Stamped custody log against its external anchors.")
    parser.add_argument("--db", required=True)
    parser.add_argument("--anchors", required=True, help="directory holding anchor_NNNNNN.json files")
    parser.add_argument("--public-keys", required=True, help="the case's exported public/ folder")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--allow-no-anchors", action="store_true",
                        help="do not fail when there are no anchors (the result still says nothing external was checked)")
    args = parser.parse_args(argv)
    try:
        result = check_anchors(args.db, args.anchors, args.public_keys,
                               require_anchor=not args.allow_no_anchors)
    except CheckerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2) if args.json else render_report(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())