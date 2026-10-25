"""Create a disposable synthetic case with one altered custody entry."""

import argparse
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

from schemas.init_db import SCHEMA_PATH
from seal.custody_log import append_entry

GUARD_TRIGGERS = (
    "custody_log_no_update",
    "custody_log_no_delete",
    "custody_log_no_replace",
)
TAMPERED_ENTRY_ID = 2


def prepare_demo_case(case_dir: Path) -> None:
    if case_dir.exists():
        raise FileExistsError(f"Refusing to overwrite existing demo case: {case_dir}")
    case_dir.mkdir(parents=True)

    with tempfile.TemporaryDirectory(prefix="stamped-demo-seed-") as seed_dir:
        seed_db = Path(seed_dir) / "stamped.db"
        connection = sqlite3.connect(seed_db)
        try:
            connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            for sequence in range(1, 4):
                append_entry(
                    connection,
                    actor="demo-operator",
                    role="examiner",
                    action=f"demo_action_{sequence}",
                    evidence_id="DEMO-ONLY",
                    details={"demo_case": True, "sequence": sequence},
                )
            connection.commit()
        finally:
            connection.close()

        demo_db = case_dir / "stamped.db"
        shutil.copyfile(seed_db, demo_db)

    (case_dir / "anchors").mkdir()
    public_dir = case_dir / "public"
    public_dir.mkdir()
    (public_dir / "ed25519_public.bin").write_bytes(
        b"DEMO ONLY - NOT AN ED25519 PUBLIC KEY"
    )
    (public_dir / "mldsa65_public.bin").write_bytes(
        b"DEMO ONLY - NOT AN ML-DSA PUBLIC KEY"
    )

    connection = sqlite3.connect(demo_db)
    try:
        for trigger in GUARD_TRIGGERS:
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        cursor = connection.execute(
            "UPDATE custody_log SET actor = ? WHERE entry_id = ?",
            ("tampered-demo-actor", TAMPERED_ENTRY_ID),
        )
        if cursor.rowcount != 1:
            raise RuntimeError(
                f"Expected to alter demo entry #{TAMPERED_ENTRY_ID}, "
                f"but changed {cursor.rowcount} rows."
            )
        connection.commit()
    finally:
        connection.close()


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
