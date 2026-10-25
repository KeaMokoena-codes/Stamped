"""Create a disposable synthetic case with one altered custody entry."""

import argparse
import json
import sqlite3
from pathlib import Path

from schemas.init_db import SCHEMA_PATH
from seal.custody_log import append_entry

TAMPERED_ENTRY_ID = 2


def prepare_demo_case(case_dir: Path) -> None:
    if case_dir.exists():
        raise FileExistsError(f"Refusing to overwrite existing demo case: {case_dir}")
    case_dir.mkdir(parents=True)

    seed = sqlite3.connect(":memory:")
    try:
        seed.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        for sequence in range(1, 4):
            append_entry(
                seed,
                actor="demo-operator",
                role="examiner",
                action=f"demo_action_{sequence}",
                evidence_id="DEMO-ONLY",
                details={"demo_case": True, "sequence": sequence},
            )
        seed.commit()
        entries = seed.execute(
            "SELECT entry_id, timestamp_utc, actor, role, action, evidence_id, "
            "artifact_id, details_json, prev_hash, entry_hash "
            "FROM custody_log ORDER BY entry_id"
        ).fetchall()
    finally:
        seed.close()

    demo_db = case_dir / "stamped.db"
    connection = sqlite3.connect(demo_db)
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        for entry in entries:
            row = list(entry)
            if row[0] == TAMPERED_ENTRY_ID:
                row[2] = "tampered-demo-actor"
            connection.execute(
                "INSERT INTO custody_log "
                "(entry_id, timestamp_utc, actor, role, action, evidence_id, "
                "artifact_id, details_json, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
        connection.commit()
    finally:
        connection.close()

    (case_dir / "anchors").mkdir()
    public_dir = case_dir / "public"
    public_dir.mkdir()
    (public_dir / "ed25519_public.bin").write_bytes(
        b"DEMO ONLY - NOT AN ED25519 PUBLIC KEY"
    )
    (public_dir / "mldsa65_public.bin").write_bytes(
        b"DEMO ONLY - NOT AN ML-DSA PUBLIC KEY"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case-dir",
        type=Path,
        required=True,
        help="new directory where the disposable demo case will be created",
    )
    args = parser.parse_args(argv)

    prepare_demo_case(args.case_dir)
    print(
        json.dumps(
            {
                "case_type": "synthetic-demo-only",
                "tampered_entry_id": TAMPERED_ENTRY_ID,
                "case_dir": str(args.case_dir),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
