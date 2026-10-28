#!/usr/bin/env python3
"""
scripts/run_e2e.py  --  first end-to-end pipeline run (Issue #28)

    python scripts/run_e2e.py [--keep-dir DIR] [--strict]

Drives sample incidents through all five stages using the REAL modules, in a
throwaway environment, and fails fast:

  1 CAPTURE  real capture listener over real HTTP (POST /alert)
  2 SEAL     seal_evidence via the listener; evidence row, sealed bytes and custody entry checked
  3 INGEST   real parsers (auth_log / cloudtrail_json) on the SEALED copy
  4 DETECT   real rules; findings are persisted and recorded in the custody log
  5 REPORT   python -m report.export_report
  + REPRODUCE every finding from stored records alone (detect.reproduce)
  + VERIFY   the independent verifier (chain-only), then hostile tampering that must be caught

WHAT A GREEN RUN DOES AND DOES NOT MEAN
  Every check below compares output with values worked out independently from the raw input bytes
  (expected line numbers, outcomes, timestamps, counts, titles). A run that merely finishes without
  an exception proves nothing, and this driver does not treat it as a pass.
  It is NOT the human review the issue requires: two team members must still read the report and
  the custody log (use --keep-dir to keep them) and judge whether they make sense.

NOT EXERCISED BY THIS DRIVER (and reported as such at the end)
  * Anchoring / hybrid signatures: the verifier runs chain-only (--allow-no-anchors) with placeholder
    key files, exactly like the dashboard's tamper demo. Run tests/test_anchor.py and
    scripts/check_liboqs.py for those.
  * Impossible travel runs only when geoip2, mmdb-writer and netaddr are installed (they are in
    requirements.txt). The geolocation database is a tiny SYNTHETIC .mmdb built here. It exercises the
    wiring, not geolocation accuracy. Without those packages the scenario is SKIPPED and says so;
    use --strict to make a skip a failure.
  * large_access: no parser emits its data_access events yet.

Exit code: 0 every check that ran passed (see the summary for anything skipped), 1 a check failed or the run crashed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from markupsafe import escape  # noqa: E402  (installed with jinja2)

from detect.findings import detect_and_record, detect_travel_and_record  # noqa: E402
from ingest.parsers.auth_log import TOOL_NAME as AUTH_TOOL, parse_and_record_auth_log  # noqa: E402
from ingest.parsers.cloudtrail_json import TOOL_NAME as CT_TOOL, parse_and_record_cloudtrail  # noqa: E402

CASE_ID = "CASE-E2E-001"
BASE_YEAR = 2026
SYNTHETIC_GEO_NAME = "SYNTHETIC-e2e-city.mmdb"


class E2EFailure(Exception):
    """A pipeline check failed. The message says what was expected and what was found."""


def check(condition, message: str) -> None:
    """Not `assert`: this must still fire under `python -O`."""
    if not condition:
        raise E2EFailure(message)


def stage(text: str) -> None:
    print(f"\n=== {text} ===")


def ok(text: str) -> None:
    print(f"  [ok] {text}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------------------------------
# Scenarios. Every expected value is derived here from the input, never from the pipeline's output.
# --------------------------------------------------------------------------------------------------
@dataclass
class Expected:
    rule_name: str
    grouped_by: str
    key: str
    severity: str
    title: str
    refs: dict          # raw_ref -> "failure" | "success": exactly the events the finding must cite
    failure_count: int | None = None
    followed_by_success: bool | None = None


@dataclass
class Scenario:
    source: str
    kind: str                                   # auth_log | cloudtrail_json
    raw: bytes
    expected: list = field(default_factory=list)
    needs_geo: bool = False
    evidence_id: str = ""

    @property
    def sha(self) -> str:
        return sha256_hex(self.raw)

    def bundle(self) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        entry = {"name": f"{self.source}.{'log' if self.kind == 'auth_log' else 'json'}",
                 "kind": self.kind,
                 "content_b64": base64.b64encode(self.raw).decode("ascii")}
        if self.kind == "auth_log":
            entry["base_year"] = BASE_YEAR
        return {"format_version": "stamped-bundle/1", "bundle_id": f"bndl_{self.source}",
                "source_system": self.source, "alert_type": "e2e_test", "alert_timestamp": now,
                "captured_at": now, "collector": "e2e_driver", "files": [entry]}


def build_scenarios() -> list[Scenario]:
    # 1. Control: 4 failures is below the threshold of 5, so the rule must stay silent.
    control = "".join(
        f"Oct 27 21:00:{s:02d} server sshd[123]: Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        for s in range(1, 5)
    ) + "Oct 27 21:10:00 server sshd[125]: Disconnected from user admin 192.168.1.50 port 22\n"

    # 2. Brute force: 8 failures in 7 seconds, then a success. The rule groups by account AND by
    #    source IP, so the same attack yields two findings. Each cites the 8 failures plus the success.
    brute = "".join(
        f"Oct 27 21:00:{s:02d} server sshd[123]: Failed password for admin from 192.168.1.100 port 22 ssh2\n"
        for s in range(1, 9)
    ) + "Oct 27 21:00:15 server sshd[123]: Accepted password for admin from 192.168.1.100 port 22 ssh2\n"
    brute_refs = {f"line:{i}": "failure" for i in range(1, 9)} | {"line:9": "success"}
    brute_title = "8 failed logins for {dim} {key}, followed by a success"

    # 3. Impossible travel: two console logins five minutes apart from public IPs that the
    #    synthetic database places in California and Frankfurt (~9,100 km apart).
    travel = json.dumps({"Records": [
        {"eventTime": "2026-10-27T21:00:00Z", "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
         "sourceIPAddress": "8.8.8.8", "userIdentity": {"userName": "dev"}},
        {"eventTime": "2026-10-27T21:05:00Z", "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
         "sourceIPAddress": "9.9.9.9", "userIdentity": {"userName": "dev"}},
    ]}, indent=2) + "\n"

    return [
        Scenario("e2e_control", "auth_log", control.encode(), expected=[]),
        Scenario("e2e_brute", "auth_log", brute.encode(), expected=[
            Expected("brute_force_login", "account", "admin", "high",
                     brute_title.format(dim="account", key="admin"), brute_refs, 8, True),
            Expected("brute_force_login", "source_ip", "192.168.1.100", "high",
                     brute_title.format(dim="source_ip", key="192.168.1.100"), brute_refs, 8, True),
        ]),
        Scenario("e2e_travel", "cloudtrail_json", travel.encode(), needs_geo=True, expected=[
            Expected("impossible_travel", "account", "dev", "medium", "",
                     {"record:0": "success", "record:1": "success"}),
        ]),
    ]


def build_synthetic_geo_db(path: Path) -> bool:
    """A tiny SYNTHETIC city database (same recipe as tests/test_geo.py). False if the packages are missing."""
    try:
        import geoip2  # noqa: F401
        import mmdb_writer
        import netaddr
    except ImportError:
        return False
    w = mmdb_writer.MMDBWriter(ip_version=4, database_type="GeoIP2-City", languages=["en"],
                               description={"en": "stamped e2e SYNTHETIC test db"})
    w.insert_network(netaddr.IPSet(["8.8.8.0/24"]), {"location": {"latitude": 37.386, "longitude": -122.0838}})
    w.insert_network(netaddr.IPSet(["9.9.9.0/24"]), {"location": {"latitude": 50.1109, "longitude": 8.6821}})
    w.to_db_file(str(path))
    return True


# --------------------------------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------------------------------
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_post_json(url: str, payload: dict, timeout: float = 15):
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except ValueError:
            return exc.code, {}


def wait_for_listener(proc: subprocess.Popen, url: str, log_path: Path, seconds: float = 20) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if proc.poll() is not None:
            raise E2EFailure(f"listener exited during start-up (code {proc.returncode}):\n{tail(log_path)}")
        try:
            urllib.request.urlopen(url, timeout=1)
        except urllib.error.HTTPError:
            return                      # any HTTP answer (405 for GET) means it is serving
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
        else:
            return
    raise E2EFailure(f"listener did not start within {seconds:.0f}s:\n{tail(log_path)}")


def tail(path: Path, n: int = 20) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-n:])
    except OSError:
        return "(no log)"


def run(cmd: list, env: dict, what: str, expect_rc: int | None = 0) -> subprocess.CompletedProcess:
    proc = subprocess.run([str(c) for c in cmd], env=env, cwd=REPO_ROOT, capture_output=True, text=True)
    if expect_rc is not None and proc.returncode != expect_rc:
        raise E2EFailure(f"{what}: expected exit code {expect_rc}, got {proc.returncode}\n"
                         f"--- stdout ---\n{proc.stdout[-2000:]}\n--- stderr ---\n{proc.stderr[-2000:]}")
    return proc


def db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------------------------------------------------------------------------
# Raw-input oracle: what the sealed bytes say, worked out without the parsers
# --------------------------------------------------------------------------------------------------
AUTH_EVENT_LINE = re.compile(r"sshd\[\d+\]: (Failed password|Accepted (?:password|publickey)) for (?:invalid user )?(\S+) from (\S+) port")


def raw_auth_events(raw: bytes) -> dict:
    """line number -> (outcome, account, ip, utc iso timestamp), from the raw text only."""
    events = {}
    for number, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        m = AUTH_EVENT_LINE.search(line)
        if m:
            stamp = datetime.strptime(f"{BASE_YEAR} {line[:15]}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            outcome = "failure" if m.group(1).startswith("Failed") else "success"
            events[number] = (outcome, m.group(2), m.group(3), stamp.isoformat())
    return events


def raw_cloudtrail_events(raw: bytes) -> dict:
    events = {}
    for index, rec in enumerate(json.loads(raw)["Records"]):
        stamp = datetime.fromisoformat(rec["eventTime"].replace("Z", "+00:00")).astimezone(timezone.utc)
        outcome = "failure" if rec.get("errorCode") else "success"
        events[index] = (outcome, rec["userIdentity"]["userName"], rec["sourceIPAddress"], stamp.isoformat())
    return events


def oracle(sc: Scenario) -> dict:
    """raw_ref -> (outcome, account, ip, timestamp)"""
    if sc.kind == "auth_log":
        return {f"line:{n}": v for n, v in raw_auth_events(sc.raw).items()}
    return {f"record:{i}": v for i, v in raw_cloudtrail_events(sc.raw).items()}


# --------------------------------------------------------------------------------------------------
# Stages
# --------------------------------------------------------------------------------------------------
def stage_capture_and_seal(sc: Scenario, url: str, db_path: Path) -> None:
    status, body = http_post_json(url, sc.bundle())
    check(status == 201, f"{sc.source}: capture expected HTTP 201, got {status}: {body}")
    check(body.get("status") == "sealed" and len(body.get("files", [])) == 1,
          f"{sc.source}: unexpected capture response {body}")
    returned = body["files"][0]
    check(returned["status"] == "sealed", f"{sc.source}: file status {returned['status']!r}, expected 'sealed'")
    check(returned["evidence_id"] == sc.sha,
          f"{sc.source}: evidence_id {returned['evidence_id']} != sha256 of the bytes sent {sc.sha}")
    sc.evidence_id = sc.sha
    ok(f"captured over HTTP and sealed as {sc.evidence_id[:16]}...")

    conn = db(db_path)
    try:
        row = conn.execute("SELECT * FROM evidence WHERE evidence_id = ?", (sc.evidence_id,)).fetchone()
        check(row is not None, f"{sc.source}: no evidence row for {sc.evidence_id}")
        check(row["content_hash"] == sc.sha, f"{sc.source}: stored content_hash differs from the input hash")
        check(row["source"] == sc.source and row["collector"] == "e2e_driver",
              f"{sc.source}: source/collector not stored as sent ({row['source']!r}, {row['collector']!r})")
        sealed = Path(row["sealed_path"]).read_bytes()
        check(sealed == sc.raw, f"{sc.source}: the sealed file's bytes differ from the bytes that were sent")
        first = conn.execute("SELECT action FROM custody_log WHERE evidence_id = ? ORDER BY entry_id LIMIT 1",
                             (sc.evidence_id,)).fetchone()
        check(first and first["action"] == "sealed", f"{sc.source}: first custody entry is {first and first['action']!r}")
    finally:
        conn.close()
    ok("evidence row, sealed bytes and first custody entry match the input")


def stage_ingest(sc: Scenario, db_path: Path):
    """Parse the SEALED copy with the real parser. Returns the parsed events."""
    conn = db(db_path)
    try:
        row = conn.execute("SELECT sealed_path, metadata_json FROM evidence WHERE evidence_id = ?",
                           (sc.evidence_id,)).fetchone()
        meta = json.loads(row["metadata_json"])
        check(meta.get("kind") == sc.kind, f"{sc.source}: capture recorded kind {meta.get('kind')!r}, expected {sc.kind!r}")
        if sc.kind == "auth_log":
            art_id, events, stats = parse_and_record_auth_log(conn, row["sealed_path"], sc.evidence_id,
                                                              base_year=meta.get("base_year", BASE_YEAR))
            tool, unparsed = AUTH_TOOL, stats["unparsed_lines"]
        else:
            art_id, events, stats = parse_and_record_cloudtrail(conn, row["sealed_path"], sc.evidence_id)
            tool, unparsed = CT_TOOL, stats["unparsed_records"]
        conn.commit()

        art = conn.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (art_id,)).fetchone()
        check(art["tool_name"] == tool and art["source_evidence_id"] == sc.evidence_id,
              f"{sc.source}: parser artifact does not link to the sealed evidence")
        check(art["input_hash"] == sc.sha, f"{sc.source}: parser input_hash is not the sealed file's hash")

        want = oracle(sc)
        check(len(events) == len(want) == stats["parsed_events"],
              f"{sc.source}: ingest leak: the raw input has {len(want)} login events, the parser produced "
              f"{len(events)} (stats say {stats['parsed_events']})")
        check(unparsed == 0, f"{sc.source}: parser reported {unparsed} unparseable lines/records in a clean sample")
        for ev in map(asdict, events):
            expected = want.get(ev["raw_ref"])
            check(expected is not None, f"{sc.source}: parsed event cites {ev['raw_ref']}, which is not a login in the raw input")
            got = (ev["outcome"], ev["account"], ev["source_ip"], ev["timestamp_utc"])
            check(got == expected, f"{sc.source}: {ev['raw_ref']} parsed as {got}, raw input says {expected}")
            check(ev["evidence_id"] == sc.evidence_id and
                  ev["event_id"] == sha256_hex(f"{sc.evidence_id}:{ev['raw_ref']}".encode()),
                  f"{sc.source}: {ev['raw_ref']} has broken provenance (evidence_id/event_id)")
        entry = conn.execute("SELECT 1 FROM custody_log WHERE artifact_id = ? AND action LIKE 'parsed_%'", (art_id,)).fetchone()
        check(entry, f"{sc.source}: no custody entry for the parse")
    finally:
        conn.close()
    ok(f"parsed {len(events)} events; every event matches its raw line/record (outcome, account, IP, UTC time)")
    return events


def stage_detect(sc: Scenario, events, db_path: Path, geo) -> None:
    conn = db(db_path)
    try:
        detect_and_record(conn, events)
        if geo is not None:
            detect_travel_and_record(conn, events, geo[0], geo[1])
        rows = conn.execute("SELECT finding_id, rule_id, severity, title, details_json FROM findings "
                            "WHERE source_evidence_id = ?", (sc.evidence_id,)).fetchall()

        # The geolocation rule only runs when its database is available, so a scenario that needs it
        # is judged only when it ran; otherwise the caller has already skipped it.
        expected = sc.expected
        check(len(rows) == len(expected),
              f"{sc.source}: expected exactly {len(expected)} finding(s), found {len(rows)}: "
              f"{[r['title'] for r in rows]}")
        by_key = {}
        for r in rows:
            d = json.loads(r["details_json"])
            by_key[(d["rule_name"], d["grouped_by"], d["key"])] = (r, d)

        want_refs_outcome = oracle(sc)
        for exp in expected:
            hit = by_key.get((exp.rule_name, exp.grouped_by, exp.key))
            check(hit is not None, f"{sc.source}: expected {exp.rule_name} for {exp.grouped_by}={exp.key}; "
                                   f"found {sorted(by_key)}")
            row, d = hit
            check(row["severity"] == exp.severity, f"{sc.source}: severity {row['severity']!r}, expected {exp.severity!r}")
            if exp.title:
                check(row["title"] == exp.title, f"{sc.source}: title {row['title']!r}, expected {exp.title!r}")
            else:
                check(row["title"].startswith(f"Impossible travel for account {exp.key}"),
                      f"{sc.source}: unexpected title {row['title']!r}")
            if exp.failure_count is not None:
                check(d["failure_count"] == exp.failure_count, f"{sc.source}: failure_count {d['failure_count']}, expected {exp.failure_count}")
                check(d["followed_by_success"] is exp.followed_by_success, f"{sc.source}: followed_by_success is {d['followed_by_success']}")
            # Provenance: the finding cites exactly the events the input says it should, and each cited
            # raw_ref really is a line/record with the outcome the finding relies on.
            cited = {e["raw_ref"] for e in d["source_events"]}
            check(len(cited) == len(d["source_events"]), f"{sc.source}: a finding cites the same event twice")
            check(cited == set(exp.refs), f"{sc.source}: finding cites {sorted(cited)}, expected {sorted(exp.refs)}")
            for ref, outcome in exp.refs.items():
                check(want_refs_outcome[ref][0] == outcome,
                      f"{sc.source}: FALSE PROVENANCE: {ref} is a {want_refs_outcome[ref][0]} in the raw input, finding needs a {outcome}")
            check(all(e["evidence_id"] == sc.evidence_id for e in d["source_events"]), f"{sc.source}: finding cites another evidence item")
            if exp.rule_name == "impossible_travel":
                check(d["geo_source"]["source"] == SYNTHETIC_GEO_NAME, "travel finding does not record which geo database it used")
                check(8000 < d["distance_km"] < 10000 and d["speed_kmh"] > 800,
                      f"travel finding has implausible numbers: {d['distance_km']} km, {d['speed_kmh']} km/h")
            # Stored finding is self-consistent (same invariant the reproduce harness relies on).
            check(sha256_hex(row["details_json"].encode()) == row["finding_id"], f"{sc.source}: finding_id is not the hash of its details")

        actions = [r[0] for r in conn.execute("SELECT action FROM custody_log WHERE evidence_id = ? ORDER BY entry_id",
                                              (sc.evidence_id,))]
        want_actions = ["sealed", "parsed_auth_log" if sc.kind == "auth_log" else "parsed_cloudtrail_log"] \
                       + ["finding_created"] * len(expected)
        check(actions == want_actions, f"{sc.source}: custody sequence {actions}, expected {want_actions}")
    finally:
        conn.close()
    ok(f"{len(sc.expected)} finding(s), each matching the independent expectation; custody sequence is exact")


def stage_duplicate_intake(sc: Scenario, url: str, db_path: Path) -> None:
    status, body = http_post_json(url, sc.bundle())
    check(status == 201 and body["files"][0]["status"] == "re_intake",
          f"re-sending identical evidence should be logged as re_intake, got HTTP {status} {body}")
    conn = db(db_path)
    try:
        n = conn.execute("SELECT COUNT(*) FROM evidence WHERE evidence_id = ?", (sc.evidence_id,)).fetchone()[0]
        check(n == 1, f"duplicate intake created {n} evidence rows")
        last = conn.execute("SELECT action FROM custody_log WHERE evidence_id = ? ORDER BY entry_id DESC LIMIT 1",
                            (sc.evidence_id,)).fetchone()
        check(last["action"] == "re_intake", "duplicate intake was not recorded in the custody log")
    finally:
        conn.close()
    ok("re-sending identical evidence is recorded as re_intake, not re-sealed")


def stage_report(scenarios, db_path: Path, out_dir: Path, env: dict, label: str) -> str:
    run([sys.executable, "-m", "report.export_report", "--db", db_path, "--out", out_dir, "--case-id", CASE_ID],
        env, "report export")
    path = out_dir / "custody_report.html"
    check(path.is_file(), "report export did not write custody_report.html")
    return path.read_text(encoding="utf-8")


def check_clean_report(html: str, scenarios, ran) -> None:
    check(CASE_ID in html, "report does not show the case id")
    for sc in scenarios:
        check(sc.evidence_id in html, f"report is missing evidence {sc.source} ({sc.evidence_id[:16]}...)")
    shown = 0
    for sc in ran:
        for exp in sc.expected:
            title = exp.title or "Impossible travel for account dev"
            check(str(escape(title)) in html, f"report is missing finding {title!r}")
            shown += 1
    cited = re.findall(r"Src: ([0-9a-f]{64})", html)
    check(len(cited) == shown, f"report lists {len(cited)} findings, the pipeline produced {shown}")
    control = next(sc for sc in scenarios if sc.source == "e2e_control")
    check(control.evidence_id not in cited, "report attributes a finding to the control evidence (which must have none)")
    for cell in ("sealed", "parsed_auth_log", "finding_created"):
        check(f"<td>{cell}</td>" in html, f"custody table has no {cell!r} entry")
    check("Internal Database Check:</strong> PASS" in html, "report does not show a passing internal chain check on a clean database")
    m = re.search(r"recomputed over (\d+) custody entries", html)
    listed = len(re.findall(r"<td>\d+</td>\s*<td>\d{4}-", html))
    check(m and int(m.group(1)) == listed,
          f"report says the chain check covered {m and m.group(1)} entries but lists {listed}: a reviewer cannot reconcile them")
    check("N/A" not in html and "Unknown" not in html, "report contains placeholder text (N/A / Unknown): a field did not render")
    check("does not guarantee admissibility" in html, "report is missing its admissibility disclaimer")
    ok("report shows every evidence item, every finding (and none for the control), the custody trail and a real chain check")


def stage_reproduce(db_path: Path, geo_path: Path | None, total: int, env: dict) -> None:
    cmd = [sys.executable, "-m", "detect.reproduce", "--db", db_path, "--all", "--summary"]
    if geo_path:
        cmd += ["--geo-db", geo_path]
    proc = run(cmd, env, "reproduce all findings")
    check(f"{total} finding(s): {total} reproduced, 0 mismatch, 0 cannot reproduce" in proc.stdout,
          f"not every finding reproduced:\n{proc.stdout}")
    ok(f"all {total} finding(s) re-derived from the sealed files and stored records, identical")


def write_chain_only_case(case_dir: Path, db_path: Path) -> None:
    """A case export folder for the verifier. The key files are PLACEHOLDERS: in chain-only mode no signature is checked."""
    case_dir.mkdir(parents=True)
    shutil.copy2(db_path, case_dir / "stamped.db")
    (case_dir / "anchors").mkdir()
    (case_dir / "public").mkdir()
    (case_dir / "public" / "ed25519_public.bin").write_bytes(b"E2E PLACEHOLDER - NOT A KEY")
    (case_dir / "public" / "mldsa65_public.bin").write_bytes(b"E2E PLACEHOLDER - NOT A KEY")


def drop_custody_triggers(conn: sqlite3.Connection) -> None:
    """What a hostile editor with the database file does first: remove every guard on custody_log."""
    names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'custody_log'")]
    check(names, "custody_log has no triggers at all: the structural append-only guard is missing from the schema")
    for name in names:
        conn.execute(f'DROP TRIGGER "{name}"')


def verify(case_dir: Path, env: dict, expect_rc: int) -> subprocess.CompletedProcess:
    return run([sys.executable, REPO_ROOT / "verifier" / "verify.py", "--case-export", case_dir, "--allow-no-anchors"],
               env, "independent verifier", expect_rc=expect_rc)


def stage_verify_and_tamper(db_path: Path, work: Path, env: dict) -> None:
    clean = work / "case_clean"
    write_chain_only_case(clean, db_path)
    proc = verify(clean, env, 0)
    check("RESULT: PASS" in proc.stdout, f"verifier exit 0 without a PASS line:\n{proc.stdout}")
    ok("independent verifier: clean database PASSES (chain only)")

    # The schema's append-only triggers must refuse an ordinary edit...
    conn = db(db_path)
    try:
        try:
            conn.execute("UPDATE custody_log SET action = 'tampered' WHERE entry_id = 1")
            conn.commit()
        except sqlite3.DatabaseError as exc:
            check("append-only" in str(exc), f"UPDATE was refused for an unexpected reason: {exc}")
        else:
            raise E2EFailure("the custody log accepted an UPDATE: the append-only trigger is not working")
    finally:
        conn.close()
    ok("the append-only trigger refuses an UPDATE of a custody entry")

    # ...so a hostile editor works on the file directly (drops the trigger). The hash chain must still catch it.
    conn = db(db_path)
    ids = [r[0] for r in conn.execute("SELECT entry_id FROM custody_log ORDER BY entry_id")]
    conn.close()
    victim = ids[len(ids) // 2]

    edited = work / "case_edited"
    write_chain_only_case(edited, db_path)
    conn = db(edited / "stamped.db")
    drop_custody_triggers(conn)
    conn.execute("UPDATE custody_log SET action = 'tampered' WHERE entry_id = ?", (victim,))
    conn.commit()
    conn.close()
    proc = verify(edited, env, 1)
    check("RESULT: FAIL" in proc.stdout and f"The chain first breaks at entry #{victim}." in proc.stdout,
          f"verifier did not pinpoint edited entry #{victim}:\n{proc.stdout}")
    ok(f"hostile EDIT of entry #{victim} is detected and pinpointed")

    removed = work / "case_deleted"
    write_chain_only_case(removed, db_path)
    conn = db(removed / "stamped.db")
    drop_custody_triggers(conn)
    conn.execute("DELETE FROM custody_log WHERE entry_id = ?", (victim,))
    conn.commit()
    conn.close()
    after = ids[ids.index(victim) + 1]
    proc = verify(removed, env, 1)
    check(f"The chain first breaks at entry #{after}." in proc.stdout,
          f"after deleting #{victim} the verifier should blame the next entry #{after}:\n{proc.stdout}")
    ok(f"hostile DELETE of entry #{victim} is detected (blamed on the entry after the gap, #{after})")


def stage_sealed_file_tamper(db_path: Path, brute: Scenario, geo_path, env: dict) -> None:
    """The verifier checks the custody log, not evidence bytes; reproduce is what notices an altered sealed file."""
    conn = db(db_path)
    sealed = Path(conn.execute("SELECT sealed_path FROM evidence WHERE evidence_id = ?", (brute.evidence_id,)).fetchone()[0])
    conn.close()
    original = sealed.read_bytes()
    mode = sealed.stat().st_mode
    flipped = bytearray(original)
    flipped[10] ^= 0x01
    sealed.chmod(0o666)
    try:
        sealed.write_bytes(bytes(flipped))
        cmd = [sys.executable, "-m", "detect.reproduce", "--db", db_path, "--all", "--summary"]
        if geo_path:
            cmd += ["--geo-db", geo_path]
        proc = run(cmd, env, "reproduce with a tampered sealed file", expect_rc=1)
        check("MISMATCH" in proc.stdout and "evidence_sealed" in proc.stdout,
              f"an altered sealed file was not reported as a mismatch at evidence_sealed:\n{proc.stdout}")
    finally:
        sealed.write_bytes(original)
        sealed.chmod(mode & 0o777)
    check(sealed.read_bytes() == original, "could not restore the sealed file after the tamper check")
    ok("one flipped bit in a sealed file is caught (MISMATCH at evidence_sealed); file restored")


# --------------------------------------------------------------------------------------------------
def run_pipeline(args, base: Path) -> list[str]:
    skipped: list[str] = []
    case_dir = base / "case"
    sealed_dir = base / "sealed"
    case_dir.mkdir()
    sealed_dir.mkdir()
    db_path = case_dir / "stamped.db"

    env = os.environ.copy()
    env["STAMPED_DB_PATH"] = str(db_path)
    env["STAMPED_SEALED_DIR"] = str(sealed_dir)

    stage("Setup: throwaway database, listener on a free port")
    run([sys.executable, REPO_ROOT / "schemas" / "init_db.py", db_path], env, "init_db")
    port = free_port()
    url = f"http://127.0.0.1:{port}/alert"
    log_path = base / "listener.log"
    with open(log_path, "wb") as log_file:
        listener = subprocess.Popen(
            [sys.executable, "-m", "capture.listener", "--port", str(port), "--db", str(db_path),
             "--sealed-dir", str(sealed_dir)],
            env=env, cwd=REPO_ROOT, stdout=log_file, stderr=subprocess.STDOUT)
    try:
        wait_for_listener(listener, url, log_path)
        ok(f"listener up on 127.0.0.1:{port}")

        geo_path = base / SYNTHETIC_GEO_NAME
        geo = None
        if build_synthetic_geo_db(geo_path):
            from detect.geo import open_geo
            geo = open_geo(geo_path)
            ok(f"built a SYNTHETIC geolocation database ({SYNTHETIC_GEO_NAME}); tests wiring only")
        else:
            geo_path = None

        scenarios = build_scenarios()
        ran = []
        for sc in scenarios:
            stage(f"Scenario {sc.source}")
            if sc.needs_geo and geo is None:
                msg = f"{sc.source}: SKIPPED (needs geoip2, mmdb-writer and netaddr; pip install -r requirements.txt)"
                print(f"  [SKIP] {msg}")
                skipped.append(msg)
                continue
            stage_capture_and_seal(sc, url, db_path)
            events = stage_ingest(sc, db_path)
            stage_detect(sc, events, db_path, geo)
            ran.append(sc)

        stage("Duplicate intake")
        stage_duplicate_intake(ran[0], url, db_path)

        stage("Report")
        out_dir = Path(args.keep_dir).resolve() if args.keep_dir else base / "report"
        html = stage_report(ran, db_path, out_dir, env, "clean")
        check_clean_report(html, ran, ran)

        stage("Reproducibility")
        total = sum(len(sc.expected) for sc in ran)
        stage_reproduce(db_path, geo_path, total, env)

        stage("Independent verification and hostile tampering")
        stage_verify_and_tamper(db_path, base, env)
        stage_sealed_file_tamper(db_path, next(sc for sc in ran if sc.source == "e2e_brute"), geo_path, env)

        stage("Report on a tampered copy must say so")
        tampered_db = base / "case_edited" / "stamped.db"
        tampered_html = stage_report(ran, tampered_db, base / "report_tampered", env, "tampered")
        check("Internal Database Check:</strong> FAIL" in tampered_html,
              "the report on a tampered database still shows a passing internal check")
        ok("report on the tampered copy shows FAIL for the internal check (it no longer says 'Pass' unconditionally)")

        if args.keep_dir:
            keep = Path(args.keep_dir).resolve()
            shutil.copy2(db_path, keep / "stamped_e2e.db")
            print(f"\nKept for HUMAN REVIEW in {keep}: custody_report.html and stamped_e2e.db")
    except Exception:
        print(f"\n--- listener log (tail) ---\n{tail(log_path)}", file=sys.stderr)
        raise
    finally:
        listener.terminate()
        try:
            listener.wait(timeout=5)
        except subprocess.TimeoutExpired:
            listener.kill()
    return skipped


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="End-to-end pipeline run: capture, seal, ingest, detect, report, verify.")
    parser.add_argument("--keep-dir", help="write the custody report and database here so reviewers can read them")
    parser.add_argument("--strict", action="store_true", help="treat a skipped scenario as a failure")
    args = parser.parse_args(argv)

    print(">>> Stamped end-to-end run (real modules, throwaway environment)")
    if args.keep_dir:
        Path(args.keep_dir).mkdir(parents=True, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="stamped-e2e-"))
    try:
        skipped = run_pipeline(args, base)
    except E2EFailure as exc:
        print(f"\n[FATAL] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - a crash is a failed run, never a pass; show where
        import traceback
        traceback.print_exc()
        print(f"\n[FATAL] unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        for p in (base / "sealed").glob("*"):          # sealed copies are read-only; Windows cannot delete those
            p.chmod(0o666)
        shutil.rmtree(base, ignore_errors=True)

    print("\n" + "=" * 70)
    if skipped:
        print("PASSED WITH GAPS. These parts did NOT run:")
        for s in skipped:
            print(f"  - {s}")
    else:
        print("ALL AUTOMATED CHECKS PASSED.")
    print("Not exercised here: anchoring and hybrid signatures (verifier ran chain-only), large_access rule.")
    print("This is not the review sign-off: two team members must still read the report and custody log.")
    return 1 if (skipped and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())