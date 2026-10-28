"""
Reproduce a stored finding from the stored records alone  (Issue: reproducible findings).

CLAIM BEING TESTED: "pick any finding, and show it can be re-derived and gives the identical result."

    reproduce(conn, finding_id, geo_db=None) -> ReproResult

The harness receives ONLY a database connection and a finding id. It is never handed events,
a finding dict or a config, so it cannot "pass" by re-running a function on the variables the
finding was just computed from. Everything is read back from the stored records:

  1 stored_records     findings + artifacts rows exist; sha256(details_json) == finding_id ==
                       artifacts.output_hash; rule name/version agree in both tables; the stored
                       input_hash agrees in both tables.
  2 rule_version       THIS build contains the exact rule name@version that made the finding.
                       If not, the result is "cannot_reproduce". The current code is NEVER
                       silently used in place of the stored version.
  3 custody            the custody hash chain verifies and a finding_created entry exists for the
                       finding.
  4 evidence_sealed    every evidence file named by source_events still exists and still hashes
                       to its evidence_id (so it is the file that was sealed).
  5 events_rederived   the stored parser artifact is re-run (same parser name AND version) on the
                       sealed file and must reproduce the parser artifact's recorded output_hash
                       (the hash of ALL parsed events).
  6 input_hash         the events named in source_events are picked out of the re-derived events,
                       and their canonical hash must equal the stored input_hash.
  7 rule_rerun         the stored rule version is run with the STORED config on exactly those
                       events; the regenerated finding must equal the stored one, byte for byte.

Results
  reproduced        every step passed
  mismatch          something stored does not match what is re-derived (tampering, corruption, or
                    a rule / parser whose behaviour changed without a version bump)
  cannot_reproduce  the information needed is not available here (unknown rule version, missing
                    evidence file, missing geolocation database, no parser record). This is NOT a pass.

The harness never writes to the database (checked by a test).

NOT COVERED (stated honestly in docs/reproducibility.md)
  * Only the CURRENT version of each rule/parser is available. Findings from older versions report
    cannot_reproduce until frozen copies of those versions are kept.
  * large_access is not supported: no parser emits its data_access events yet.
  * The auth.log year is not stored by the parser, so it is inferred: the harness tries the years
    around the finding's own timestamps and accepts only one that reproduces the parser's recorded
    output_hash. It never guesses silently.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from detect.canon import canonical_hash, canonical_json
from detect.rules import brute_force, impossible_travel
from ingest.parsers import auth_log, cloudtrail_json
from schemas.init_db import SCHEMA_PATH
from seal.custody_log import recompute_and_verify_chain

REPRODUCED, MISMATCH, CANNOT = "reproduced", "mismatch", "cannot_reproduce"


@dataclass
class Step:
    name: str
    ok: bool
    detail: str


@dataclass
class ReproResult:
    finding_id: str
    status: str
    steps: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == REPRODUCED

    def failed_step(self):
        return next((s for s in self.steps if not s.ok), None)


class _Stop(Exception):
    def __init__(self, status):
        self.status = status


# ------------------------------------------------------------------ what this build can re-run
def _rules():
    return {
        (brute_force.RULE_NAME, brute_force.RULE_VERSION): {
            "config": brute_force.BruteForceConfig,
            "run": lambda events, cfg, stored, geo: brute_force.detect(events, cfg),
            "needs_geo": False,
        },
        (impossible_travel.RULE_NAME, impossible_travel.RULE_VERSION): {
            "config": impossible_travel.TravelConfig,
            "run": lambda events, cfg, stored, geo: impossible_travel.detect_impossible_travel(
                events, cfg, geo[0], stored["geo_source"]),
            "needs_geo": True,
        },
    }


def _parsers():
    return {
        auth_log.TOOL_NAME: (auth_log.TOOL_VERSION, "auth"),
        cloudtrail_json.TOOL_NAME: (cloudtrail_json.TOOL_VERSION, "cloudtrail"),
    }


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _scratch_conn():
    c = sqlite3.connect(":memory:")
    c.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return c


def _run_parser(kind, path, evidence_id, year=None):
    """Run the production parser on a file inside a THROWAWAY database; return (events, artifact output_hash)."""
    scratch = _scratch_conn()
    try:
        if kind == "auth":
            art_id, events, _ = auth_log.parse_and_record_auth_log(scratch, path, evidence_id, base_year=year)
        else:
            art_id, events, _ = cloudtrail_json.parse_and_record_cloudtrail(scratch, path, evidence_id)
        out = scratch.execute("SELECT output_hash FROM artifacts WHERE artifact_id=?", (art_id,)).fetchone()[0]
        return [asdict(e) for e in events], out
    finally:
        scratch.close()


# ------------------------------------------------------------------------------ the harness
def reproduce(conn, finding_id: str, geo_db=None) -> ReproResult:
    res = ReproResult(finding_id=finding_id, status=CANNOT)

    def step(name, ok, detail, status_if_fail=MISMATCH):
        res.steps.append(Step(name, ok, detail))
        if not ok:
            raise _Stop(status_if_fail)

    try:
        _run_steps(conn, finding_id, geo_db, step)
        res.status = REPRODUCED
    except _Stop as stop:
        res.status = stop.status
    return res


def _run_steps(conn, finding_id, geo_db, step):
    # 1 -- stored records ---------------------------------------------------------------
    row = conn.execute("SELECT details_json, rule_id FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
    art = conn.execute("SELECT tool_name, tool_version, input_hash, output_hash FROM artifacts "
                       "WHERE artifact_id = ?", (finding_id,)).fetchone()
    step("stored_records", row is not None and art is not None,
         "finding and artifact rows found" if row and art else "no stored finding / artifact with this id",
         CANNOT)
    text, rule_id = row
    tool_name, tool_version, input_hash, output_hash = art
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    step("stored_records", digest == finding_id == output_hash,
         "sha256(details_json) == finding_id == artifacts.output_hash"
         if digest == finding_id == output_hash else
         f"stored details do not hash to the finding id (sha256(details_json)={digest[:16]}.., "
         f"finding_id={finding_id[:16]}.., output_hash={output_hash[:16]}..)")
    body = json.loads(text)
    step("stored_records", canonical_json(body) == text and body.get("input_hash") == input_hash
         and rule_id == f"{body.get('rule_name')}@{body.get('rule_version')}"
         and (tool_name, tool_version) == (body.get("rule_name"), body.get("rule_version")),
         "rule name/version and input_hash agree in findings and artifacts")
    stored = dict(body, finding_hash=finding_id)

    # 2 -- exact rule version -----------------------------------------------------------
    rule = _rules().get((body["rule_name"], body["rule_version"]))
    have = sorted(f"{n}@{v}" for n, v in _rules())
    step("rule_version", rule is not None,
         f"this build can run {body['rule_name']}@{body['rule_version']}" if rule else
         f"this build cannot run {body['rule_name']}@{body['rule_version']} (available: {', '.join(have)}); "
         "it will not substitute a different version", CANNOT)

    # 3 -- custody ----------------------------------------------------------------------
    chain_ok, bad = recompute_and_verify_chain(conn)
    step("custody", chain_ok, "custody hash chain verifies" if chain_ok else f"custody chain broken at entry {bad}")
    n = conn.execute("SELECT COUNT(*) FROM custody_log WHERE artifact_id = ? AND action = 'finding_created'",
                     (finding_id,)).fetchone()[0]
    step("custody", n >= 1, f"{n} finding_created custody entries for this finding" if n else
         "no finding_created custody entry for this finding")

    # 4 -- evidence still sealed --------------------------------------------------------
    evidence_ids = sorted({e["evidence_id"] for e in body["source_events"]})
    paths = {}
    for ev_id in evidence_ids:
        ev = conn.execute("SELECT content_hash, sealed_path FROM evidence WHERE evidence_id = ?", (ev_id,)).fetchone()
        step("evidence_sealed", ev is not None, f"evidence {ev_id[:12]}.. registered" if ev else
             f"evidence {ev_id[:12]}.. is not registered", CANNOT)
        p = Path(ev[1])
        step("evidence_sealed", p.is_file(), f"sealed file present for {ev_id[:12]}.." if p.is_file() else
             f"sealed file missing: {p}", CANNOT)
        actual = _file_sha256(p)
        step("evidence_sealed", actual == ev_id == ev[0],
             f"sealed file for {ev_id[:12]}.. still hashes to its evidence_id" if actual == ev_id == ev[0] else
             f"sealed file for {ev_id[:12]}.. hashes to {actual[:16]}.., not its evidence_id")
        paths[ev_id] = p

    # 5 -- events re-derived by re-running the stored parser ----------------------------
    parsers = _parsers()
    derived = {}
    for ev_id in evidence_ids:
        recs = conn.execute("SELECT tool_name, tool_version, input_hash, output_hash FROM artifacts "
                            "WHERE source_evidence_id = ? AND tool_name IN (%s)" % ",".join("?" * len(parsers)),
                            (ev_id, *parsers)).fetchall()
        step("events_rederived", bool(recs), f"parser record found for {ev_id[:12]}.." if recs else
             f"no parser artifact recorded for evidence {ev_id[:12]}..", CANNOT)
        t_name, t_ver, t_in, t_out = recs[0]
        want_ver, kind = parsers[t_name]
        step("events_rederived", t_ver == want_ver,
             f"parser {t_name}@{t_ver} available" if t_ver == want_ver else
             f"stored parser {t_name}@{t_ver}, but this build has {t_name}@{want_ver}; will not substitute", CANNOT)
        step("events_rederived", t_in == ev_id, "parser input_hash equals the sealed file hash" if t_in == ev_id
             else "parser input_hash does not equal the sealed file hash")
        years = [None]
        if kind == "auth":
            y = int(str(body.get("first_seen") or body["logins"][0]["timestamp_utc"])[:4])
            years = [y, y - 1, y + 1]
        match = None
        for year in years:
            events, out = _run_parser(kind, paths[ev_id], ev_id, year)
            if out == t_out:
                match = (events, year)
                break
        step("events_rederived", match is not None,
             f"re-ran {t_name}@{t_ver} on the sealed file: events reproduce the recorded output_hash"
             + (f" (year inferred: {match[1]})" if match and match[1] else "") if match else
             f"re-running {t_name}@{t_ver} does NOT reproduce the recorded parser output_hash")
        for e in match[0]:
            derived[e["event_id"]] = e

    # 6 -- the exact input events, by hash ----------------------------------------------
    picked = []
    for s in body["source_events"]:
        e = derived.get(s["event_id"])
        step("input_hash", e is not None and e["evidence_id"] == s["evidence_id"] and e["raw_ref"] == s["raw_ref"],
             "event found at the recorded evidence and raw_ref" if e and e["raw_ref"] == s["raw_ref"] else
             f"event {s['event_id'][:12]}.. not found at {s['raw_ref']} in the re-derived events")
        picked.append(e)
    h = canonical_hash(picked)
    step("input_hash", h == input_hash, "canonical hash of the re-derived input events equals the stored input_hash"
         if h == input_hash else f"re-derived input events hash to {h[:16]}.., stored input_hash is {input_hash[:16]}..")

    # 7 -- re-run the stored rule version with the stored config ------------------------
    geo = None
    if rule["needs_geo"]:
        step("rule_rerun", geo_db is not None,
             "geolocation database supplied" if geo_db else
             f"needs the geolocation database (sha256 {body['geo_source']['sha256'][:16]}..); pass geo_db", CANNOT)
        from detect.geo import open_geo
        geo = open_geo(geo_db)
        same = geo[1]["sha256"] == body["geo_source"]["sha256"]
        step("rule_rerun", same, "geolocation database matches the stored sha256" if same else
             f"database sha256 {geo[1]['sha256'][:16]}.. differs from the stored {body['geo_source']['sha256'][:16]}..",
             CANNOT)
    cfg = rule["config"](**body["config"])
    regenerated = rule["run"](picked, cfg, stored, geo)
    same = [f for f in regenerated if f["finding_hash"] == finding_id]
    step("rule_rerun", bool(same) and canonical_json({k: v for k, v in same[0].items() if k != "finding_hash"}) == text,
         f"re-ran {body['rule_name']}@{body['rule_version']} with the stored config: identical finding "
         f"({finding_id[:16]}..)" if same else
         f"re-running {body['rule_name']}@{body['rule_version']} gives a different finding "
         f"({len(regenerated)} regenerated, none equal to the stored one)")


# ---------------------------------------------------------------------------------------- CLI
def _print(result: ReproResult):
    print(f"\nFinding {result.finding_id}")
    seen = set()
    for s in result.steps:
        if not s.ok or (s.name, s.detail) not in seen:
            print(f"  [{'OK  ' if s.ok else 'FAIL'}] {s.name:<16} {s.detail}")
            seen.add((s.name, s.detail))
    print(f"  => {result.status.upper()}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Reproduce stored findings from the stored records.")
    ap.add_argument("--db", required=True, help="path to the Stamped SQLite database (opened read-only)")
    ap.add_argument("--geo-db", help="the .mmdb used when impossible-travel findings were made")
    ap.add_argument("finding_id", nargs="?", help="finding id; omit with --all")
    ap.add_argument("--all", action="store_true", help="reproduce every stored finding")
    ap.add_argument("--summary", action="store_true", help="one line per finding instead of every step")
    a = ap.parse_args(argv)
    if not Path(a.db).is_file():
        sys.exit(f"database not found: {a.db}")
    conn = sqlite3.connect(Path(a.db).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        if a.all:
            ids = [r[0] for r in conn.execute("SELECT finding_id FROM findings ORDER BY created_at, finding_id")]
        elif a.finding_id:
            ids = [r[0] for r in conn.execute("SELECT finding_id FROM findings WHERE finding_id LIKE ? ESCAPE '\\'",
                                              (a.finding_id.replace("\\", "").replace("%", "").replace("_", "") + "%",))]
            if len(a.finding_id) < 8 or len(ids) != 1:
                sys.exit(f"finding id prefix must be at least 8 characters and match exactly one finding "
                         f"(matched {len(ids)})")
        else:
            sys.exit("give a finding_id or --all")
        if not ids:
            print("no findings stored")
            return 0
        results = [reproduce(conn, i, a.geo_db) for i in ids]
        for r in results:
            if a.summary:
                bad = r.failed_step()
                print(f"{r.finding_id[:16]}..  {r.status.upper():<17}" + (f" at {bad.name}: {bad.detail}" if bad else ""))
            else:
                _print(r)
        counts = {s: sum(r.status == s for r in results) for s in (REPRODUCED, MISMATCH, CANNOT)}
        print(f"\n{len(results)} finding(s): {counts[REPRODUCED]} reproduced, {counts[MISMATCH]} mismatch, "
              f"{counts[CANNOT]} cannot reproduce")
        return 0 if counts[REPRODUCED] == len(results) else 1
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())