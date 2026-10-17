#!/usr/bin/env python3
"""
Checks an exported case package WITHOUT running, importing or trusting the
Stamped application. Anyone (a judge, a defence expert, opposing counsel) can
run it on their own machine:

    python verify.py --case-export <folder>

It performs three checks and prints one overall result:

  1. HASH CHAIN       every custody-log entry is recomputed from its stored
                      fields and must link to the entry before it.
  2. SIGNATURES       every external anchor (the signed checkpoints) must carry
                      a valid Ed25519 signature AND a valid ML-DSA-65 signature.
                      Both, not either.
  3. ANCHOR           each anchor must be correctly numbered and linked to the
     CONSISTENCY      previous one, and must match the live log: the entry it
                      names must still exist with the hash that was anchored.

Overall result and exit code:
  PASS  (0)  every check passed
  FAIL  (1)  tampering or inconsistency found; the broken entry is named
  ERROR (2)  the verification could not be completed (missing or unreadable
             file, missing liboqs, internal error). NEVER treated as a pass.

WHY THIS FILE REPEATS LOGIC THAT ALSO EXISTS IN seal/ AND verifier/anchor_check.py
  The verifier must not share a bug with the thing it verifies. The hashing and
  signature rules below are deliberately re-implemented from the written format
  (docs/custody-log-format.md, docs/anchoring.md), not imported. This module
  imports only `cryptography`, `oqs` (liboqs) and the Python standard library.
  Do not "fix the duplication" by importing from seal/, ingest/ or the app.

FAIL-CLOSED RULES
  * The overall result is PASS only if every check explicitly reports PASS.
    Anything else (including a check that crashed) is FAIL or ERROR.
  * main() converts every unexpected exception into ERROR / exit code 2.
  * The database is opened read-only; this tool never writes anything.
"""

import argparse
import base64
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError as _exc:  # report clearly instead of a traceback; exit code 2 = ERROR
    sys.stderr.write(
        "ERROR: the 'cryptography' package is required to verify signatures "
        f"({type(_exc).__name__}). Install it with: pip install cryptography\n"
    )
    sys.exit(2)

TOOL = "stamped-verify/1"
ANCHOR_FORMAT = "stamped-anchor/1"
GENESIS = "0" * 64
MLDSA_ALG = "ML-DSA-65"
ANCHOR_FILE_RE = re.compile(r"anchor_([0-9]{6})\.json")  # ASCII digits only; used with fullmatch
ED25519_PUB_FILE = "ed25519_public.bin"
MLDSA_PUB_FILE = "mldsa65_public.bin"
PUB_MANIFEST_FILE = "public_keys.json"
DEFAULT_DB_NAME = "stamped.db"

PASS, FAIL, ERROR, SKIPPED = "PASS", "FAIL", "ERROR", "SKIPPED"

REQUIRED_PAYLOAD_TYPES = {
    "format": str, "case_id": str, "seq": int, "anchored_at": str,
    "head_entry_id": int, "head_entry_hash": str, "entry_count": int,
    "prev_anchor_hash": str,
}


class VerifierError(Exception):
    """The verification could not be run (not the same as 'tampering found')."""


def _safe(text) -> str:
    """Printable ASCII only, so odd file names can never crash the report on a
    console with a narrow encoding (e.g. Windows cp1252)."""
    return str(text).encode("ascii", "backslashreplace").decode("ascii")


# ---------------------------------------------------------------------------
# Format rules, re-implemented from docs/custody-log-format.md
# ---------------------------------------------------------------------------
def canonical(obj) -> str:
    """Every setting is spelled out so the output never depends on library defaults."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def compute_entry_hash(fields: dict, prev_hash: str) -> str:
    # details_json inside `fields` is already a canonical JSON *string*; it gets
    # escaped a second time here. That double encoding is part of the format.
    return hashlib.sha256((canonical(fields) + prev_hash).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
def read_custody_log(db_path: Path) -> list[tuple]:
    """Read every entry, oldest first, through a READ-ONLY connection."""
    if not db_path.is_file():
        raise VerifierError(f"Database file not found: {_safe(db_path)}")
    try:
        conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            return conn.execute(
                "SELECT entry_id, timestamp_utc, actor, role, action, evidence_id, "
                "artifact_id, details_json, prev_hash, entry_hash "
                "FROM custody_log ORDER BY entry_id ASC"
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise VerifierError(
            f"Could not read the custody log from {_safe(db_path)}: {type(exc).__name__}: {_safe(exc)}"
        ) from exc


def read_public_keys(public_dir: Path) -> dict:
    if not public_dir.is_dir():
        raise VerifierError(f"Public key folder not found: {_safe(public_dir)}")
    try:
        ed_pub = (public_dir / ED25519_PUB_FILE).read_bytes()
        pq_pub = (public_dir / MLDSA_PUB_FILE).read_bytes()
    except OSError as exc:
        raise VerifierError(f"Could not read public keys from {_safe(public_dir)}: {type(exc).__name__}") from exc
    if not ed_pub or not pq_pub:
        raise VerifierError(f"A public key file in {_safe(public_dir)} is empty.")

    manifest_case_id, manifest_note = None, None
    manifest_path = public_dir / PUB_MANIFEST_FILE
    if manifest_path.is_file():
        try:
            value = json.loads(manifest_path.read_text(encoding="utf-8")).get("case_id")
            manifest_case_id = value if isinstance(value, str) else None
        except Exception as exc:  # noqa: BLE001  advisory file: a problem becomes a note, never a pass or a crash
            manifest_note = (f"{PUB_MANIFEST_FILE} could not be read ({type(exc).__name__}); "
                             "the case id of the keys was not checked.")
    return {
        "ed25519": ed_pub, "mldsa": pq_pub,
        "ed25519_sha256": hashlib.sha256(ed_pub).hexdigest(),
        "mldsa_sha256": hashlib.sha256(pq_pub).hexdigest(),
        "manifest_case_id": manifest_case_id, "manifest_note": manifest_note,
    }


def load_oqs():
    """Import liboqs and prove it really works before trusting any answer from it.

    A broken or half-built liboqs must produce ERROR, not a wall of 'invalid
    signature' results that look like tampering."""
    try:
        import oqs  # noqa: PLC0415  lazy on purpose
    except (Exception, SystemExit) as exc:  # liboqs-python may try to build itself and abort
        raise VerifierError(
            f"liboqs (ML-DSA) is not available ({type(exc).__name__}), so post-quantum "
            "signatures cannot be checked. Refusing to report a result."
        ) from exc
    try:
        msg = b"stamped-verifier-self-test"
        with oqs.Signature(MLDSA_ALG) as signer:
            pub = signer.generate_keypair()
            sig = signer.sign(msg)
        with oqs.Signature(MLDSA_ALG) as verifier:
            good = bool(verifier.verify(msg, sig, pub))
            bad = bool(verifier.verify(msg + b"x", sig, pub))
    except Exception as exc:  # noqa: BLE001
        raise VerifierError(
            f"liboqs is installed but {MLDSA_ALG} did not work ({type(exc).__name__}). Refusing to report a result."
        ) from exc
    if not good or bad:
        raise VerifierError(f"The liboqs {MLDSA_ALG} self-test gave wrong answers. Refusing to report a result.")
    return oqs


def verify_ed25519(msg: bytes, sig: bytes, pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False  # a malformed signature or key means "invalid", never a crash


def verify_mldsa(oqs, msg: bytes, sig: bytes, pub: bytes) -> bool:
    try:
        with oqs.Signature(MLDSA_ALG) as verifier:
            return bool(verifier.verify(msg, sig, pub))
    except Exception:  # noqa: BLE001  any failure here means "does not verify"
        return False


# ---------------------------------------------------------------------------
# Check 1: hash chain
# ---------------------------------------------------------------------------
def check_chain(rows: list[tuple]) -> dict:
    """Walk the log in entry_id order and report the FIRST entry that fails,
    using that row's own entry_id (never a list position, so gaps in ids cannot
    shift the answer).

    Which entry is blamed:
      * content or stored hash of an entry changed   -> that entry
      * an entry deleted or reordered                -> the entry AFTER the gap
        (it no longer links to the entry before it)
      * the newest entries deleted                   -> invisible here; anchors catch it
    """
    result = {"status": PASS, "entries": len(rows), "first_bad_entry": None, "reason": None, "detail": ""}

    def broken(entry_id, reason, detail):
        result.update(status=FAIL, first_bad_entry=entry_id, reason=reason, detail=detail)
        return result

    if not rows:
        return broken(None, "empty_log", "The custody log contains no entries, so there is nothing to verify.")

    expected_prev = GENESIS
    for row in rows:
        entry_id, ts, actor, role, action, evidence_id, artifact_id, details, prev, stored = row

        if prev != expected_prev:
            where = "the genesis value (it is the first entry)" if expected_prev == GENESIS else "the entry before it"
            return broken(entry_id, "prev_hash_mismatch",
                          f"Entry #{entry_id} does not link to {where}: an earlier entry was "
                          "removed, replaced or reordered, or this entry's prev_hash was altered.")
        fields = {
            "timestamp_utc": ts, "actor": actor, "role": role, "action": action,
            "evidence_id": evidence_id, "artifact_id": artifact_id, "details_json": details,
        }
        try:
            recomputed = compute_entry_hash(fields, prev)
        except (TypeError, ValueError, UnicodeError) as exc:
            return broken(entry_id, "malformed_entry",
                          f"Entry #{entry_id} holds values that cannot be hashed ({type(exc).__name__}); "
                          "it was not written by the application.")
        if recomputed != stored:
            return broken(entry_id, "entry_hash_mismatch",
                          f"Entry #{entry_id}: the stored hash does not match the hash recomputed "
                          "from its contents. The entry (or its stored hash) was altered.")
        expected_prev = stored

    result["detail"] = f"All {len(rows)} entries recompute and link to each other."
    return result


# ---------------------------------------------------------------------------
# Checks 2 and 3: anchors
# ---------------------------------------------------------------------------
def _parse_anchor(path: Path) -> dict:
    """Read and validate one anchor file. Raises ValueError with a short reason."""
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        payload = record["payload"]
        sigs = record["signatures"]
        claimed_hash = record["anchor_hash"]
        if record.get("format") != ANCHOR_FORMAT:
            raise ValueError("unknown or missing format")
        for key, typ in REQUIRED_PAYLOAD_TYPES.items():
            value = payload[key]
            if not isinstance(value, typ) or isinstance(value, bool):
                raise ValueError(f"payload field '{key}' has the wrong type")
        if payload["format"] != ANCHOR_FORMAT:
            raise ValueError("payload has the wrong format")
        if not isinstance(claimed_hash, str):
            raise ValueError("anchor_hash is not text")
        sig_ed = base64.b64decode(sigs["ed25519"], validate=True)
        sig_pq = base64.b64decode(sigs["ml_dsa_65"], validate=True)
        message = canonical(payload).encode("utf-8")  # may raise ValueError (e.g. NaN): treated as malformed
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001  OSError, KeyError, TypeError, RecursionError, binascii.Error ...
        raise ValueError(type(exc).__name__) from exc
    return {"payload": payload, "claimed_hash": claimed_hash, "sig_ed": sig_ed, "sig_pq": sig_pq, "message": message}


def check_anchors(rows: list[tuple], anchor_dir: Path, keys: dict, *, allow_no_anchors: bool = False) -> dict:
    """Signature problems are filed under check 2; numbering, linking and
    agreement with the live log under check 3."""
    if not anchor_dir.is_dir():
        raise VerifierError(f"Anchor folder not found: {_safe(anchor_dir)}")

    sig_failures: list[dict] = []
    con_failures: list[dict] = []
    warnings: list[str] = []
    anchors_out: list[dict] = []
    oqs = None
    oqs_error = None

    live_hash_by_id = {r[0]: r[9] for r in rows}
    live_ids = sorted(live_hash_by_id)
    live_end = live_ids[-1] if live_ids else None

    found: dict[int, Path] = {}
    try:
        children = sorted(anchor_dir.iterdir())
    except OSError as exc:
        raise VerifierError(f"Could not list {_safe(anchor_dir)}: {type(exc).__name__}") from exc
    for p in children:
        m = ANCHOR_FILE_RE.fullmatch(p.name)
        if m:
            found[int(m.group(1))] = p
        else:
            warnings.append(f"Ignored unexpected item in the anchor folder: {_safe(p.name)}")

    def sfail(code, message, **extra):
        sig_failures.append({"code": code, "message": message, **extra})

    def cfail(code, message, **extra):
        con_failures.append({"code": code, "message": message, **extra})

    limited = False
    if not found:
        if allow_no_anchors:
            limited = True
            warnings.append("No anchors were found and --allow-no-anchors was given: nothing external was checked.")
        else:
            msg = "No anchors found. The log cannot be checked against anything outside the database."
            sfail("no_anchors", msg)
            cfail("no_anchors", msg)
    else:
        missing = [n for n in range(1, max(found) + 1) if n not in found]
        if missing:
            cfail("anchor_sequence_gap",
                  f"Anchor file(s) missing from the sequence: {missing}. An anchor may have been removed.",
                  missing=missing)

    prev_hash_seen = GENESIS      # None after an unreadable anchor (its hash is unknown)
    prev_payload = None
    latest = None
    last_good_head = 0            # newest entry id proven intact by an anchor that matched the log
    case_ids = set()
    ok_sig_count = 0

    for seq in sorted(found):
        path = found[seq]
        try:
            a = _parse_anchor(path)
        except ValueError as exc:
            sfail("anchor_unreadable", f"{_safe(path.name)} is unreadable or malformed ({_safe(exc)}).", anchor_seq=seq)
            anchors_out.append({"seq": seq, "file": path.name, "readable": False})
            prev_hash_seen = None
            continue

        payload, message = a["payload"], a["message"]
        head_id = payload["head_entry_id"]
        case_ids.add(payload["case_id"])
        info = {"seq": seq, "file": path.name, "readable": True, "head_entry_id": head_id,
                "entry_count": payload["entry_count"], "anchored_at": payload["anchored_at"],
                "ed25519": None, "ml_dsa_65": None, "matches_log": None}
        anchors_out.append(info)

        # -- check 2: is this record authentic? ------------------------------------------------
        if hashlib.sha256(message).hexdigest() != a["claimed_hash"]:
            sfail("anchor_hash_mismatch",
                  f"{_safe(path.name)}: the stored anchor_hash does not match its contents.", anchor_seq=seq)

        if oqs is None and oqs_error is None:
            try:
                oqs = load_oqs()
            except VerifierError as exc:
                oqs_error = str(exc)
        if oqs is not None:
            ed_ok = verify_ed25519(message, a["sig_ed"], keys["ed25519"])
            pq_ok = verify_mldsa(oqs, message, a["sig_pq"], keys["mldsa"])
            info["ed25519"], info["ml_dsa_65"] = ed_ok, pq_ok
            if ed_ok and pq_ok:
                ok_sig_count += 1
            else:
                which = [n for n, ok in (("Ed25519", ed_ok), (MLDSA_ALG, pq_ok)) if not ok]
                sfail("anchor_signature_invalid",
                      f"{_safe(path.name)}: signature check failed for {' and '.join(which)}. Both must verify "
                      "(the record was altered, or these are not the keys that signed it).", anchor_seq=seq)

        # -- check 3: numbering, linking, agreement with the live log --------------------------
        if payload["seq"] != seq:
            cfail("anchor_seq_mismatch",
                  f"{_safe(path.name)}: file number {seq} disagrees with its signed sequence {payload['seq']}.",
                  anchor_seq=seq)
        if prev_hash_seen is not None and payload["prev_anchor_hash"] != prev_hash_seen:
            cfail("anchor_link_broken",
                  f"{_safe(path.name)}: does not link to the previous anchor "
                  "(an anchor was altered, replaced or removed).", anchor_seq=seq)
        prev_hash_seen = a["claimed_hash"]

        if prev_payload is not None:
            if head_id < prev_payload["head_entry_id"] or payload["entry_count"] < prev_payload["entry_count"]:
                cfail("anchor_regression",
                      f"{_safe(path.name)}: covers LESS of the log than the previous anchor.", anchor_seq=seq)
            if payload["anchored_at"] < prev_payload["anchored_at"]:
                warnings.append(f"{_safe(path.name)}: anchored_at is earlier than the previous anchor (clock change?).")
        prev_payload = payload

        if head_id not in live_hash_by_id:
            info["matches_log"] = False
            end_text = f"#{live_end}" if live_end is not None else "nothing"
            cfail("anchored_entry_missing",
                  f"{_safe(path.name)}: anchored entry #{head_id} is not in the log (the log ends at {end_text}). "
                  "Entries were deleted after this anchor was made.", anchor_seq=seq, entry_id=head_id)
        else:
            good = True
            low = last_good_head + 1
            if live_hash_by_id[head_id] != payload["head_entry_hash"]:
                good = False
                cfail("anchored_hash_mismatch",
                      f"{_safe(path.name)}: entry #{head_id} no longer has the hash that was anchored. History was "
                      f"rewritten after this anchor was made; the altered entry lies between #{low} and #{head_id}.",
                      anchor_seq=seq, entry_id=head_id, suspect_range=[low, head_id])
            covered = sum(1 for i in live_ids if i <= head_id)
            if covered != payload["entry_count"]:
                good = False
                cfail("anchored_entry_count_mismatch",
                      f"{_safe(path.name)}: {payload['entry_count']} entries existed up to #{head_id} when anchored, "
                      f"but {covered} do now (entries were removed or inserted).",
                      anchor_seq=seq, entry_id=head_id, suspect_range=[low, head_id])
            info["matches_log"] = good
            if good:
                last_good_head = head_id
        latest = payload

    if len(case_ids) > 1:
        cfail("anchor_case_mismatch", f"The anchors name different cases: {sorted(_safe(c) for c in case_ids)}.")
    case_id = next(iter(case_ids)) if len(case_ids) == 1 else None
    if case_id is not None and keys["manifest_case_id"] is not None and keys["manifest_case_id"] != case_id:
        sfail("keys_case_mismatch",
              f"The public keys belong to case '{_safe(keys['manifest_case_id'])}' "
              f"but the anchors are for case '{_safe(case_id)}'.")
    if keys["manifest_note"]:
        warnings.append(keys["manifest_note"])

    unanchored = unanchored_real = 0
    if latest is not None:
        later = [r for r in rows if r[0] > latest["head_entry_id"]]
        unanchored = len(later)
        unanchored_real = sum(1 for r in later if r[4] != "anchored")  # 'anchored' rows are the anchor service's bookkeeping

    if sig_failures:
        sig_status = FAIL
    elif limited:
        sig_status = SKIPPED
    elif oqs_error:
        sig_status = ERROR
        sig_failures.append({"code": "liboqs_unavailable", "message": oqs_error})
    else:
        sig_status = PASS
    con_status = FAIL if con_failures else (SKIPPED if limited else PASS)

    return {
        "signatures": {"status": sig_status, "checked": len(found), "valid": ok_sig_count, "failures": sig_failures},
        "consistency": {"status": con_status, "failures": con_failures},
        "anchors": anchors_out, "warnings": warnings, "limited": limited, "case_id": case_id,
        "latest_anchor": None if latest is None else {
            "seq": latest["seq"], "head_entry_id": latest["head_entry_id"], "anchored_at": latest["anchored_at"]},
        "unanchored_entries": unanchored, "unanchored_real_entries": unanchored_real,
    }


# ---------------------------------------------------------------------------
# Putting it together
# ---------------------------------------------------------------------------
def decide(chain_status: str, sig_status: str, con_status: str, limited: bool) -> str:
    """PASS only when every check explicitly says PASS. Anything unexpected is ERROR."""
    statuses = (chain_status, sig_status, con_status)
    if FAIL in statuses:
        return FAIL
    if all(s == PASS for s in statuses):
        return PASS
    if limited and chain_status == PASS and all(s in (PASS, SKIPPED) for s in statuses):
        return PASS
    return ERROR


def resolve_paths(case_export: Path, db=None, anchors=None, public_keys=None) -> tuple[Path, Path, Path]:
    """Layout of an exported case package:

        <case-export>/stamped.db   (or the only *.db file in the folder)
        <case-export>/anchors/     anchor_000001.json, anchor_000002.json, ...
        <case-export>/public/      ed25519_public.bin, mldsa65_public.bin, public_keys.json
    """
    if not case_export.is_dir():
        raise VerifierError(f"Case export folder not found: {_safe(case_export)}")
    if db:
        db_path = Path(db)
    else:
        default = case_export / DEFAULT_DB_NAME
        candidates = sorted(case_export.glob("*.db"))
        if default.is_file():
            db_path = default
        elif len(candidates) == 1:
            db_path = candidates[0]
        else:
            raise VerifierError(
                f"Expected {DEFAULT_DB_NAME} (or exactly one .db file) in {_safe(case_export)}; "
                f"found {len(candidates)}. Use --db to name the database."
            )
    anchor_dir = Path(anchors) if anchors else case_export / "anchors"
    public_dir = Path(public_keys) if public_keys else case_export / "public"
    return db_path, anchor_dir, public_dir


def verify_case(db_path: Path, anchor_dir: Path, public_dir: Path, *, allow_no_anchors: bool = False) -> dict:
    keys = read_public_keys(public_dir)
    rows = read_custody_log(db_path)

    try:
        chain = check_chain(rows)
    except Exception as exc:  # noqa: BLE001  a crashed check is an ERROR, never a pass
        chain = {"status": ERROR, "entries": len(rows), "first_bad_entry": None, "reason": "internal_error",
                 "detail": f"The chain check crashed ({type(exc).__name__}: {_safe(exc)})."}
    try:
        anc = check_anchors(rows, anchor_dir, keys, allow_no_anchors=allow_no_anchors)
    except VerifierError:
        raise
    except Exception as exc:  # noqa: BLE001
        failure = [{"code": "internal_error",
                    "message": f"The anchor check crashed ({type(exc).__name__}: {_safe(exc)})."}]
        anc = {"signatures": {"status": ERROR, "checked": 0, "valid": 0, "failures": failure},
               "consistency": {"status": ERROR, "failures": []}, "anchors": [], "warnings": [], "limited": False,
               "case_id": None, "latest_anchor": None, "unanchored_entries": 0, "unanchored_real_entries": 0}

    overall = decide(chain["status"], anc["signatures"]["status"], anc["consistency"]["status"], anc["limited"])
    suspect = [f["suspect_range"] for f in anc["consistency"]["failures"] if "suspect_range" in f]
    return {
        "tool": TOOL, "overall": overall, "limited": anc["limited"], "case_id": anc["case_id"],
        "broken_entry_id": chain["first_bad_entry"], "suspect_range": suspect[0] if suspect else None,
        "checks": {"chain": chain, "signatures": anc["signatures"], "anchors": anc["consistency"]},
        "anchors": anc["anchors"], "latest_anchor": anc["latest_anchor"],
        "unanchored_entries": anc["unanchored_entries"], "unanchored_real_entries": anc["unanchored_real_entries"],
        "warnings": anc["warnings"],
        "keys": {"ed25519_sha256": keys["ed25519_sha256"], "mldsa65_sha256": keys["mldsa_sha256"]},
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def _mark(value) -> str:
    return "not checked" if value is None else ("ok" if value else "INVALID")


def render_report(report: dict, paths: dict) -> str:
    chain, sigs, cons = report["checks"]["chain"], report["checks"]["signatures"], report["checks"]["anchors"]
    overall = report["overall"]
    out = ["STAMPED INDEPENDENT VERIFICATION", "=" * 32,
           f"  database     : {_safe(paths['db'])}",
           f"  anchors      : {_safe(paths['anchors'])}",
           f"  public keys  : {_safe(paths['public'])}",
           f"  case id      : {_safe(report['case_id']) if report['case_id'] else '(none found)'}",
           f"  Ed25519 key  : sha256 {report['keys']['ed25519_sha256']}",
           f"  ML-DSA key   : sha256 {report['keys']['mldsa65_sha256']}",
           "  (compare these fingerprints with a copy you obtained separately from this package)", ""]

    headline = f"RESULT: {overall}"
    if overall == PASS and report["limited"]:
        headline += "  (CHAIN ONLY - no anchors, so nothing outside the database was checked)"
    out.append(headline)
    if report["broken_entry_id"] is not None:
        out.append(f"  The chain first breaks at entry #{report['broken_entry_id']}.")
    elif chain["reason"] == "empty_log":
        out.append("  The custody log is empty.")
    if report["suspect_range"]:
        lo, hi = report["suspect_range"]
        out.append(f"  An anchored entry was rewritten somewhere between entry #{lo} and entry #{hi}.")
    if overall == ERROR:
        out.append("  The verification could not be completed. This is NOT a pass.")
    out.append("")

    out.append("CHECKS")
    if chain["status"] == PASS:
        chain_text = chain["detail"]
    elif chain["first_bad_entry"] is not None:
        chain_text = f"breaks at entry #{chain['first_bad_entry']} (see details below)"
    else:
        chain_text = "see details below"
    out.append(f"  [1] Hash chain, entry to entry ........ {chain['status']:<7} {chain_text}")
    if sigs["status"] == SKIPPED:
        sig_text = "no anchors to check"
    else:
        sig_text = f"{sigs['valid']} of {sigs['checked']} anchor(s) carry valid Ed25519 AND {MLDSA_ALG} signatures"
    out.append(f"  [2] Hybrid signatures on anchors ...... {sigs['status']:<7} {sig_text}")
    if cons["status"] == PASS:
        la = report["latest_anchor"]
        con_text = (f"stored entry hashes match every anchor; newest is #{la['seq']} covering entry #{la['head_entry_id']}"
                    if la else "ok")
    elif cons["status"] == SKIPPED:
        con_text = "no anchors to check"
    else:
        con_text = "see details below"
    out.append(f"  [3] Consistency with anchors .......... {cons['status']:<7} {con_text}")

    if report["anchors"]:
        out += ["", "ANCHORS (oldest first)"]
        for a in report["anchors"]:
            if not a.get("readable"):
                out.append(f"  #{a['seq']:<3} {_safe(a['file'])}: UNREADABLE")
                continue
            log_text = "matches" if a["matches_log"] else ("DOES NOT MATCH" if a["matches_log"] is False else "not checked")
            out.append(f"  #{a['seq']:<3} entry #{a['head_entry_id']:<5} Ed25519 {_mark(a['ed25519']):<11} "
                       f"{MLDSA_ALG} {_mark(a['ml_dsa_65']):<11} log {log_text}")

    details = []
    if chain["status"] in (FAIL, ERROR):
        details.append(f"  {chain['status']} [chain:{chain['reason']}] {chain['detail']}")
    for f in sigs["failures"]:
        label = "ERROR" if f["code"] in ("liboqs_unavailable", "internal_error") else "FAIL"
        details.append(f"  {label} [{f['code']}] {f['message']}")
    for f in cons["failures"]:
        label = "ERROR" if f["code"] == "internal_error" else "FAIL"
        details.append(f"  {label} [{f['code']}] {f['message']}")
    if details:
        out += ["", "DETAILS"] + details

    notes = list(report["warnings"])
    if report["unanchored_entries"]:
        if report["unanchored_real_entries"]:
            n = report["unanchored_real_entries"]
            notes.append(f"{n} {'entry was' if n == 1 else 'entries were'} added after the newest anchor and "
                         f"{'is' if n == 1 else 'are'} not externally protected yet (the anchors do not cover "
                         f"{'it' if n == 1 else 'them'}).")
        else:
            notes.append("Only the anchor service's own bookkeeping entry follows the newest anchor.")
    if notes:
        out += ["", "NOTES"] + [f"  - {n}" for n in notes]

    out += ["", "WHAT THIS RESULT MEANS"]
    if overall == PASS:
        out += ["  The log recomputes cleanly, the anchors are authentic, and the log matches them.",
                "  It does not cover entries added after the newest anchor, it cannot detect that the newest",
                "  anchor file was deleted, and it is only as strong as (a) where the anchors were stored and",
                "  (b) whether the public keys above are the real ones. Custody entries are not individually",
                "  signed; the signed checkpoints are the anchors."]
    else:
        out += ["  Do not rely on this log until the reported problem is explained."]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
EXIT_CODES = {PASS: 0, FAIL: 1, ERROR: 2}


def build_parser() -> argparse.ArgumentParser:
    # Fixed strings, not __doc__: docstrings vanish under `python -OO`.
    p = argparse.ArgumentParser(
        prog="verify.py",
        description="Independently verify an exported Stamped case: hash chain, hybrid signatures, anchors. "
                    "Exit code 0 = PASS, 1 = FAIL, 2 = ERROR (could not verify).",
    )
    p.add_argument("--case-export", required=True, metavar="DIR",
                   help="exported case folder containing stamped.db, anchors/ and public/")
    p.add_argument("--db", help="override: path to the database file")
    p.add_argument("--anchors", help="override: folder of anchor files (use this for a separately held copy)")
    p.add_argument("--public-keys", help="override: folder with ed25519_public.bin and mldsa65_public.bin")
    p.add_argument("--allow-no-anchors", action="store_true",
                   help="do not fail when there are no anchors; the result is then labelled CHAIN ONLY")
    p.add_argument("--json", action="store_true", help="print the full result as JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        db_path, anchor_dir, public_dir = resolve_paths(Path(args.case_export), args.db, args.anchors, args.public_keys)
        report = verify_case(db_path, anchor_dir, public_dir, allow_no_anchors=args.allow_no_anchors)
        if not args.anchors and report["checks"]["anchors"]["status"] == PASS and not report["limited"]:
            report["warnings"].append(
                "The anchors were read from inside the case package. If you hold a separately stored copy "
                "(USB, prosecutor, second machine), re-run with --anchors <that copy>.")
        rc = EXIT_CODES.get(report["overall"], 2)
        text = (json.dumps(report, indent=2) if args.json
                else render_report(report, {"db": db_path, "anchors": anchor_dir, "public": public_dir}))
        print(text)
        return rc
    except VerifierError as exc:
        print(f"ERROR: {_safe(exc)}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001  last line of defence: an unexpected crash is ERROR, never PASS
        print(f"ERROR: unexpected internal error ({type(exc).__name__}: {_safe(exc)}). "
              "No result can be reported.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())