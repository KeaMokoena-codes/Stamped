"""
Demo for Issue #10: "show an old record, re-seal it, then run the verifier to
confirm history is intact".

    python scripts/reseal_demo.py                       # clean demo
    python scripts/reseal_demo.py --tamper              # ...then also show a forged history being caught
    python scripts/reseal_demo.py --demo-dir DIR        # keep everything in DIR (must be outside this repo)

Everything happens in a disposable synthetic case. The verifier is run as a
separate process on exported copies, exactly as a third party would run it.

  1. Build a small case sealed the original way (hash chain + Ed25519/ML-DSA-65 anchor).
  2. Show one OLD record and verify the case: PASS.
  3. Re-seal the whole history with the renewal suite (Ed448 + ML-DSA-87).
  4. Show the old record again: identical hash. Verify again: PASS, now with the re-seal listed.
  5. (--tamper) Rewrite the old record AND recompute every later hash so the chain
     looks perfect. The verifier must still say FAIL.
"""
import argparse
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schemas.init_db import SCHEMA_PATH                                # noqa: E402
from seal import anchor, reseal, signing                               # noqa: E402
from seal.custody_log import _compute_entry_hash, append_entry          # noqa: E402

CASE_ID = "demo-reseal"
OLD_RECORD_ID = 3
COLUMNS = ("entry_id, timestamp_utc, actor, role, action, evidence_id, "
           "artifact_id, details_json, prev_hash, entry_hash")


def say(text: str = "") -> None:
    print(text, flush=True)


def build_case(demo: Path) -> tuple[Path, Path, Path]:
    """Original-style case: 6 custody entries and one anchor signed with Ed25519 + ML-DSA-65."""
    work, usb, keys = demo / "work", demo / "usb", demo / "keys"
    for folder in (work, usb):
        folder.mkdir(parents=True)
    signing.create_case_keys(CASE_ID, keys_dir=keys)

    conn = sqlite3.connect(work / "stamped.db")
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        steps = [("collector", "sealed"), ("examiner", "parsed_auth_log"), ("examiner", "detections_run"),
                 ("investigating_officer", "viewed_timeline"), ("examiner", "report_exported"),
                 ("prosecutor", "viewed_report")]
        for number, (role, action) in enumerate(steps, start=1):
            append_entry(conn, actor=f"demo-{role}", role=role, action=action,
                         evidence_id="DEMO-ONLY", details={"demo_case": True, "step": number})
        conn.commit()
        anchor.create_anchor(conn, case_id=CASE_ID, anchor_dir=usb, keys_dir=keys)
    finally:
        conn.close()
    return work / "stamped.db", usb, keys


def export(db: Path, usb: Path, keys: Path, target: Path) -> Path:
    """An exported case package: stamped.db, anchors/, public/ (what a judge would receive)."""
    target.mkdir(parents=True)
    shutil.copyfile(db, target / "stamped.db")
    shutil.copytree(usb, target / "anchors", copy_function=shutil.copyfile)
    shutil.copytree(keys / CASE_ID / "public", target / "public")
    return target


def read_rows(db: Path) -> list[tuple]:
    conn = sqlite3.connect(db)
    try:
        return conn.execute(f"SELECT {COLUMNS} FROM custody_log ORDER BY entry_id").fetchall()
    finally:
        conn.close()


def show_record(db: Path, entry_id: int, label: str) -> str:
    row = next(r for r in read_rows(db) if r[0] == entry_id)
    say(f"  {label}: entry #{row[0]}  action={row[4]!r}  actor={row[2]!r}")
    say(f"      entry_hash {row[9]}")
    return row[9]


def run_verifier(case: Path, *, full: bool) -> int:
    proc = subprocess.run([sys.executable, str(ROOT / "verifier" / "verify.py"), "--case-export", str(case)],
                          capture_output=True, text=True)
    lines = proc.stdout.splitlines()
    if not full:
        lines = [ln for ln in lines if ln.startswith("RESULT") or ln.startswith("  [")]
    for line in lines:
        say("  | " + line)
    if proc.stderr.strip():
        say("  | " + proc.stderr.strip())
    return proc.returncode


def forge_history(source: Path, target: Path) -> None:
    """The perfect forgery: change entry #3, then recompute prev_hash/entry_hash for every later
    entry so the chain is internally consistent again. Written as a fresh database (no edits in place)."""
    rows = read_rows(source / "stamped.db")
    target.mkdir(parents=True)
    shutil.copytree(source / "anchors", target / "anchors", copy_function=shutil.copyfile)
    shutil.copytree(source / "public", target / "public")
    conn = sqlite3.connect(target / "stamped.db")
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        prev = "0" * 64
        for entry_id, ts, actor, role, action, evidence_id, artifact_id, details, _old_prev, _old_hash in rows:
            if entry_id == OLD_RECORD_ID:
                actor = "someone-else"
            fields = {"timestamp_utc": ts, "actor": actor, "role": role, "action": action,
                      "evidence_id": evidence_id, "artifact_id": artifact_id, "details_json": details}
            new_hash = _compute_entry_hash(fields, prev)
            conn.execute(f"INSERT INTO custody_log ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (entry_id, ts, actor, role, action, evidence_id, artifact_id, details, prev, new_hash))
            prev = new_hash
        conn.commit()
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Re-sealing demo (Issue #10).")
    parser.add_argument("--demo-dir", type=Path, default=None,
                        help="new, empty directory outside this repo (default: a temporary one)")
    parser.add_argument("--tamper", action="store_true", help="also show a forged history being caught")
    args = parser.parse_args(argv)

    demo = args.demo_dir or Path(tempfile.mkdtemp(prefix="stamped-reseal-demo-"))
    if args.demo_dir is not None and demo.exists() and any(demo.iterdir()):
        say(f"ERROR: {demo} is not empty; refusing to overwrite.")
        return 1
    demo.mkdir(parents=True, exist_ok=True)
    say(f"Demo case folder: {demo}\n")

    try:
        db, usb, keys = build_case(demo)
        key_id = reseal.create_reseal_keys(CASE_ID, keys)
    except (anchor.AnchorError, reseal.ResealError, signing.KeyManagementError) as exc:
        say(f"ERROR: {exc}")
        return 1

    say("STEP 1  An old record, sealed the original way (SHA-256 chain, anchor signed Ed25519 + ML-DSA-65)")
    old_hash_before = show_record(db, OLD_RECORD_ID, "old record")
    before = export(db, usb, keys, demo / "export_before")
    say("\nSTEP 2  Verify the case as it stands today")
    if run_verifier(before, full=False) != 0:
        say("UNEXPECTED: the clean case did not pass.")
        return 1

    say("\nSTEP 3  Re-seal the whole history with the renewal suite (Ed448 + ML-DSA-87)")
    conn = sqlite3.connect(db)
    try:
        result = reseal.reseal_range(conn, case_id=CASE_ID, from_entry_id=1, keys_dir=keys, key_id=key_id)
    finally:
        conn.close()
    p = result["payload"]
    say(f"  appended entry #{result['entry_id']}: covers #{p['from_entry_id']}-#{p['to_entry_id']} "
        f"({p['entry_count']} entries), renewal key {key_id}")

    say("\nSTEP 4  The old record is untouched, and the verifier confirms history is intact")
    after = export(db, usb, keys, demo / "export_after")
    old_hash_after = show_record(after / "stamped.db", OLD_RECORD_ID, "old record")
    unchanged = read_rows(before / "stamped.db") == read_rows(after / "stamped.db")[:len(read_rows(before / "stamped.db"))]
    say(f"  original entries byte-for-byte unchanged: {'YES' if unchanged else 'NO'};  "
        f"old record hash identical: {'YES' if old_hash_before == old_hash_after else 'NO'}")
    rc = run_verifier(after, full=True)
    if rc != 0 or not unchanged or old_hash_before != old_hash_after:
        say("UNEXPECTED: re-sealing disturbed the record or the verifier did not pass.")
        return 1

    if args.tamper:
        say("\nSTEP 5  Now forge history: change the old record and recompute every later hash so the chain looks perfect")
        forged = demo / "export_forged"
        forge_history(after, forged)
        rc = run_verifier(forged, full=False)
        if rc != 1:
            say("UNEXPECTED: the forged history was not rejected.")
            return 1
        say("  The verifier rejected the forgery: the anchor AND the re-seal each pin the exact hashes they covered.")

    say("\nDone. The re-seal wrapped the old record in a stronger signature without rewriting it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())