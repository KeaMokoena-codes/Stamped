"""
Demo: "pick any finding and show it can be reproduced".

  python scripts/repro_demo.py build  DEMO_DIR [--log PATH] [--year 2015] [--geo-db city.mmdb]
  python -m detect.reproduce --db DEMO_DIR/stamped.db --all [--geo-db city.mmdb]
  python -m detect.reproduce --db DEMO_DIR/stamped.db <finding_id>
  python scripts/repro_demo.py tamper  DEMO_DIR      # flips one byte of the sealed evidence
  python -m detect.reproduce --db DEMO_DIR/stamped.db --all     # now: MISMATCH at evidence_sealed
  python scripts/repro_demo.py restore DEMO_DIR      # puts the original byte back

`build` seals a log, parses it with the real parser, runs the real rules and records the findings in
DEMO_DIR/stamped.db. The reproduce command then reads ONLY that database and the sealed file.
The default log is the public Loghub OpenSSH 2k sample in data/public_samples (year 2015, an
assumption the log does not state; see docs/validation/brute_force_fp.md).
"""
import argparse
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detect.findings import detect_and_record, detect_travel_and_record      # noqa: E402
from ingest.parsers.auth_log import parse_and_record_auth_log                # noqa: E402
from schemas.init_db import SCHEMA_PATH                                      # noqa: E402
from seal.intake import seal_evidence                                        # noqa: E402


def _sealed(demo: Path) -> Path:
    conn = sqlite3.connect(demo / "stamped.db")
    try:
        return Path(conn.execute("SELECT sealed_path FROM evidence").fetchone()[0])
    finally:
        conn.close()


def build(a):
    demo = Path(a.demo_dir)
    if (demo / "stamped.db").exists():
        sys.exit(f"{demo / 'stamped.db'} already exists; choose a new folder")
    demo.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(demo / "stamped.db")
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    ev_id = seal_evidence(conn, a.log, {"source": "demo"}, sealed_dir=demo / "sealed")
    sealed = Path(conn.execute("SELECT sealed_path FROM evidence").fetchone()[0])
    _, events, stats = parse_and_record_auth_log(conn, sealed, ev_id, base_year=a.year)
    conn.commit()
    n = detect_and_record(conn, events)
    if a.geo_db:
        from detect.geo import open_geo
        geolocate, info = open_geo(a.geo_db)
        n += detect_travel_and_record(conn, events, geolocate, info)
    ids = [r[0] for r in conn.execute("SELECT finding_id FROM findings ORDER BY created_at, finding_id")]
    conn.close()
    print(f"sealed {ev_id[:16]}..  parsed {stats['parsed_events']} events  recorded {n} findings")
    print(f"database: {demo / 'stamped.db'}")
    print("first finding ids:", *[i[:16] + ".." for i in ids[:3]])
    print(f"\nnext:  python -m detect.reproduce --db {demo / 'stamped.db'} --all"
          + (f" --geo-db {a.geo_db}" if a.geo_db else ""))


def tamper(a):
    p = _sealed(Path(a.demo_dir))
    backup = p.with_name(p.name + ".orig")
    if backup.exists():
        sys.exit("already tampered; run restore first")
    data = bytearray(p.read_bytes())
    shutil.copy2(p, backup)
    backup.chmod(0o666)             # copy2 keeps the read-only flag; Windows cannot delete a read-only file
    data[10] ^= 0x01
    p.chmod(0o666)
    p.write_bytes(bytes(data))
    print(f"flipped one bit of the sealed evidence ({p.name[:16]}..). Now run reproduce again.")


def restore(a):
    p = _sealed(Path(a.demo_dir))
    backup = p.with_name(p.name + ".orig")
    if not backup.exists():
        sys.exit("nothing to restore")
    p.chmod(0o666)
    shutil.copy2(backup, p)
    p.chmod(0o444)
    backup.chmod(0o666)
    backup.unlink()
    print("original evidence restored")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("demo_dir")
    b.add_argument("--log", default=str(ROOT / "data" / "public_samples" / "OpenSSH_2k.log"))
    b.add_argument("--year", type=int, default=2015)
    b.add_argument("--geo-db")
    for name in ("tamper", "restore"):
        sub.add_parser(name).add_argument("demo_dir")
    a = ap.parse_args()
    {"build": build, "tamper": tamper, "restore": restore}[a.cmd](a)


if __name__ == "__main__":
    main()