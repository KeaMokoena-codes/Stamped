"""Reproducibility harness: a stored finding is re-derived from the STORED records only.

The world is built through the real path (seal -> parse -> detect -> record) into a database FILE,
then everything in memory is dropped. Each test reopens the file with a fresh connection and hands
the harness nothing but the connection and a finding id. The negative tests damage one stored
thing at a time and check the harness fails at the step that is meant to catch it.
"""
import hashlib
import inspect
import sqlite3
from pathlib import Path

import pytest

from detect import reproduce as repro
from detect.findings import detect_and_record, detect_travel_and_record
from detect.reproduce import CANNOT, MISMATCH, REPRODUCED, reproduce
from detect.rules import brute_force
from ingest.parsers import auth_log
from ingest.parsers.auth_log import parse_and_record_auth_log
from ingest.timeline import build_timeline, load_findings_from_db
from schemas.init_db import SCHEMA_PATH
from seal.intake import seal_evidence

AUTH_LOG = (
    # brute force against root from a US address, then a success (account + ip groupings both fire)
    "".join(f"Oct 12 10:00:{s:02d} srv sshd[1]: Failed password for root from 8.8.8.8 port 40{s:02d} ssh2\n"
            for s in range(6))
    + "Oct 12 10:00:30 srv sshd[1]: Accepted password for root from 8.8.8.8 port 4100 ssh2\n"
    # impossible travel: alice logs in from the US, then from Frankfurt five minutes later
    + "Oct 12 11:00:00 srv sshd[2]: Accepted publickey for alice from 8.8.8.8 port 5000 ssh2\n"
    + "Oct 12 11:05:00 srv sshd[2]: Accepted publickey for alice from 9.9.9.9 port 5001 ssh2\n"
)


def _build_mmdb(path, nine_lat=50.1109):
    mmdb_writer = pytest.importorskip("mmdb_writer")
    netaddr = pytest.importorskip("netaddr")
    pytest.importorskip("geoip2")
    w = mmdb_writer.MMDBWriter(ip_version=4, database_type="GeoIP2-City", languages=["en"],
                               description={"en": "stamped repro test db"})
    w.insert_network(netaddr.IPSet(["8.8.8.0/24"]), {"location": {"latitude": 37.386, "longitude": -122.0838}})
    w.insert_network(netaddr.IPSet(["9.9.9.0/24"]), {"location": {"latitude": nine_lat, "longitude": 8.6821}})
    w.to_db_file(str(path))
    return path


@pytest.fixture
def world(tmp_path):
    """A database FILE holding sealed evidence, parser artifacts and findings from all rules."""
    geo = _build_mmdb(tmp_path / "city.mmdb")
    db = tmp_path / "stamped.db"
    src = tmp_path / "auth.log"
    src.write_text(AUTH_LOG, encoding="utf-8")

    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    evidence_id = seal_evidence(conn, src, sealed_dir=tmp_path / "sealed")
    sealed = Path(conn.execute("SELECT sealed_path FROM evidence").fetchone()[0])
    _, events, _ = parse_and_record_auth_log(conn, sealed, evidence_id, base_year=2026)
    conn.commit()
    from detect.geo import open_geo
    geolocate, geo_info = open_geo(geo)
    detect_and_record(conn, events)
    detect_travel_and_record(conn, events, geolocate, geo_info)
    conn.close()                                 # everything in memory is now gone
    return {"db": db, "geo": geo, "sealed": sealed, "evidence_id": evidence_id, "tmp": tmp_path}


def open_db(world):
    return sqlite3.connect(world["db"])


def finding_ids(world, rule=None):
    c = open_db(world)
    try:
        sql = "SELECT finding_id FROM findings" + (" WHERE rule_id LIKE ?" if rule else "") + " ORDER BY finding_id"
        return [r[0] for r in c.execute(sql, (f"{rule}@%",) if rule else ())]
    finally:
        c.close()


def repro_one(world, fid, geo=True):
    c = open_db(world)
    try:
        return reproduce(c, fid, world["geo"] if geo else None)
    finally:
        c.close()


def step_names(result):
    return [s.name for s in result.steps]


# --------------------------------------------------------------- the claim, end to end
def test_world_has_findings_from_both_rules(world):
    assert len(finding_ids(world, "brute_force_login")) == 2        # account + source_ip groupings
    assert len(finding_ids(world, "impossible_travel")) == 1


def test_every_stored_finding_reproduces_from_a_fresh_connection(world):
    ids = finding_ids(world)
    assert len(ids) == 3
    for fid in ids:
        r = repro_one(world, fid)
        assert r.status == REPRODUCED, [(s.name, s.detail) for s in r.steps if not s.ok]
        assert set(step_names(r)) == {"stored_records", "rule_version", "custody", "evidence_sealed",
                                      "events_rederived", "input_hash", "rule_rerun"}
        assert all(s.ok for s in r.steps)


def test_the_harness_is_given_only_a_connection_and_a_finding_id():
    """No events, no finding dict, no config: it cannot just re-run on the variables it was handed."""
    assert list(inspect.signature(reproduce).parameters) == ["conn", "finding_id", "geo_db"]


def test_the_harness_never_writes_to_the_database(world):
    before = hashlib.sha256(world["db"].read_bytes()).hexdigest()
    c = open_db(world)
    changes = c.total_changes
    for fid in finding_ids(world):
        reproduce(c, fid, world["geo"])
    assert c.total_changes == changes
    c.close()
    assert hashlib.sha256(world["db"].read_bytes()).hexdigest() == before


def test_auth_year_is_inferred_and_reported_not_guessed_silently(world):
    r = repro_one(world, finding_ids(world, "brute_force_login")[0])
    assert any("year inferred: 2026" in s.detail for s in r.steps)


# ------------------------------------------------- tampering and drift: each must be caught
def _fail(result):
    s = result.failed_step()
    assert s is not None
    return s


def test_edited_stored_finding_is_caught_at_stored_records(world):
    fid = finding_ids(world, "brute_force_login")[0]
    c = open_db(world)
    c.execute("UPDATE findings SET details_json = replace(details_json, '\"severity\":\"high\"', '\"severity\":\"low\"') "
              "WHERE finding_id = ?", (fid,))
    c.commit()
    c.close()
    r = repro_one(world, fid)
    assert (r.status, _fail(r).name) == (MISMATCH, "stored_records")


def test_changed_tool_version_in_the_artifact_row_is_caught(world):
    fid = finding_ids(world, "brute_force_login")[0]
    c = open_db(world)
    c.execute("UPDATE artifacts SET tool_version = '9.9.9' WHERE artifact_id = ?", (fid,))
    c.commit()
    c.close()
    r = repro_one(world, fid)
    assert (r.status, _fail(r).name) == (MISMATCH, "stored_records")


def test_changed_input_hash_in_the_artifact_row_is_caught(world):
    fid = finding_ids(world, "brute_force_login")[0]
    c = open_db(world)
    c.execute("UPDATE artifacts SET input_hash = ? WHERE artifact_id = ?", ("0" * 64, fid))
    c.commit()
    c.close()
    assert repro_one(world, fid).status == MISMATCH


def test_tampered_sealed_evidence_is_caught_at_evidence_sealed(world):
    p = world["sealed"]
    p.chmod(0o666)
    p.write_bytes(p.read_bytes().replace(b"Failed password for root", b"Failed password for rooT"))
    r = repro_one(world, finding_ids(world, "brute_force_login")[0])
    assert (r.status, _fail(r).name) == (MISMATCH, "evidence_sealed")


def test_missing_sealed_evidence_is_cannot_reproduce_not_a_pass(world):
    p = world["sealed"]
    p.chmod(0o666)
    p.unlink()
    r = repro_one(world, finding_ids(world, "brute_force_login")[0])
    assert (r.status, _fail(r).name) == (CANNOT, "evidence_sealed")


def test_broken_custody_chain_is_caught(world):
    c = open_db(world)
    c.execute("DROP TRIGGER custody_log_no_update")        # an attacker with raw DB access
    c.execute("UPDATE custody_log SET actor = 'mallory' WHERE entry_id = 1")
    c.commit()
    c.close()
    r = repro_one(world, finding_ids(world, "brute_force_login")[0])
    assert (r.status, _fail(r).name) == (MISMATCH, "custody")


def test_unknown_finding_id_is_cannot_reproduce(world):
    r = repro_one(world, "f" * 64)
    assert (r.status, _fail(r).name) == (CANNOT, "stored_records")


def test_a_rule_version_this_build_does_not_have_is_never_substituted(world, monkeypatch):
    monkeypatch.setattr(brute_force, "RULE_VERSION", "9.9.9")       # the build now has a different version
    r = repro_one(world, finding_ids(world, "brute_force_login")[0])
    assert (r.status, _fail(r).name) == (CANNOT, "rule_version")
    assert "will not substitute" in _fail(r).detail


def test_a_rule_that_changed_without_a_version_bump_is_a_mismatch(world, monkeypatch):
    real = brute_force.detect

    def drifted(events, cfg=brute_force.BruteForceConfig()):
        out = real(events, cfg)
        for f in out:
            f["severity"] = "low"                                   # behaviour change, same version
            f["finding_hash"] = repro.canonical_hash({k: v for k, v in f.items() if k != "finding_hash"})
        return out

    monkeypatch.setattr(brute_force, "detect", drifted)
    r = repro_one(world, finding_ids(world, "brute_force_login")[0])
    assert (r.status, _fail(r).name) == (MISMATCH, "rule_rerun")


def test_a_parser_that_changed_without_a_version_bump_is_a_mismatch(world, monkeypatch):
    real = auth_log.parse_auth_line

    def drifted(raw_line, line_number, evidence_id, current_year):
        ev, unparsed, month = real(raw_line, line_number, evidence_id, current_year)
        if ev is not None:
            ev = type(ev)(**{**ev.__dict__, "account": ev.account.upper()})
        return ev, unparsed, month

    monkeypatch.setattr(auth_log, "parse_auth_line", drifted)
    r = repro_one(world, finding_ids(world, "brute_force_login")[0])
    assert (r.status, _fail(r).name) == (MISMATCH, "events_rederived")


def test_a_parser_version_this_build_does_not_have_is_cannot_reproduce(world, monkeypatch):
    monkeypatch.setattr(auth_log, "TOOL_VERSION", "9.9.9")
    r = repro_one(world, finding_ids(world, "brute_force_login")[0])
    assert (r.status, _fail(r).name) == (CANNOT, "events_rederived")


# ----------------------- forged but internally consistent findings (every hash recomputed)
def _forge(world, **changes):
    """Insert a finding through the normal recording path whose hashes all agree with each other
    but whose content is a lie. Only re-deriving from the evidence can expose it."""
    import json
    from detect.canon import canonical_hash
    from detect.findings import record_finding
    fid = finding_ids(world, "brute_force_login")[0]
    c = open_db(world)
    body = json.loads(c.execute("SELECT details_json FROM findings WHERE finding_id=?", (fid,)).fetchone()[0])
    body.update(changes)
    body["finding_hash"] = canonical_hash(body)
    assert record_finding(c, body) is True
    c.commit()
    c.close()
    return body["finding_hash"]


def test_forged_input_hash_is_caught_only_by_rederiving_the_events(world):
    forged = _forge(world, input_hash="0" * 64)
    r = repro_one(world, forged)
    assert (r.status, _fail(r).name) == (MISMATCH, "input_hash")
    assert all(s.ok for s in r.steps[:-1])           # it got past every stored-record check


def test_forged_pointer_to_the_wrong_source_line_is_caught_at_input_hash(world):
    import json
    fid = finding_ids(world, "brute_force_login")[0]
    c = open_db(world)
    src = json.loads(c.execute("SELECT details_json FROM findings WHERE finding_id=?", (fid,)).fetchone()[0])["source_events"]
    c.close()
    forged = _forge(world, source_events=[dict(src[0], raw_ref="line:999")] + src[1:])
    r = repro_one(world, forged)
    assert (r.status, _fail(r).name) == (MISMATCH, "input_hash")


def test_forged_claim_about_the_burst_is_caught_by_rerunning_the_rule(world):
    forged = _forge(world, failure_count=99)          # events and input_hash are the real ones
    r = repro_one(world, forged)
    assert (r.status, _fail(r).name) == (MISMATCH, "rule_rerun")


# ------------------------------------------------- impossible travel needs the same database
def test_travel_without_the_geolocation_database_is_cannot_reproduce(world):
    r = repro_one(world, finding_ids(world, "impossible_travel")[0], geo=False)
    assert (r.status, _fail(r).name) == (CANNOT, "rule_rerun")
    assert "geolocation database" in _fail(r).detail


def test_travel_with_a_different_database_is_cannot_reproduce(world):
    other = _build_mmdb(world["tmp"] / "other.mmdb", nine_lat=48.0)
    c = open_db(world)
    r = reproduce(c, finding_ids(world, "impossible_travel")[0], other)
    c.close()
    assert (r.status, _fail(r).name) == (CANNOT, "rule_rerun")
    assert "differs" in _fail(r).detail


# ---------------------------------------------------------------------- other rules / CLI
def test_large_access_is_reported_as_unsupported_not_passed():
    from detect.findings import detect_large_access_and_record, load_trigger_findings
    from tests.test_large_access import BF, CFG, scenario
    c = sqlite3.connect(":memory:")
    c.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    ev = scenario()
    detect_and_record(c, ev, BF)
    detect_large_access_and_record(c, ev, load_trigger_findings(c), CFG)
    fid = c.execute("SELECT finding_id FROM findings WHERE rule_id LIKE 'large_access@%'").fetchone()[0]
    r = reproduce(c, fid)
    assert (r.status, _fail(r).name) == (CANNOT, "rule_version")


def test_cli_reproduces_all_and_exits_zero(world, capsys):
    code = repro.main(["--db", str(world["db"]), "--geo-db", str(world["geo"]), "--all"])
    out = capsys.readouterr().out
    assert code == 0 and "3 reproduced" in out and "REPRODUCED" in out


def test_cli_summary_prints_one_line_per_finding(world, capsys):
    code = repro.main(["--db", str(world["db"]), "--geo-db", str(world["geo"]), "--all", "--summary"])
    lines = [l for l in capsys.readouterr().out.splitlines() if l.rstrip().endswith("REPRODUCED")]
    assert code == 0 and len(lines) == 3


def test_cli_accepts_a_unique_id_prefix_and_rejects_ambiguous_or_short_ones(world, capsys):
    fid = finding_ids(world, "impossible_travel")[0]
    assert repro.main(["--db", str(world["db"]), "--geo-db", str(world["geo"]), fid[:16]]) == 0
    assert "REPRODUCED" in capsys.readouterr().out
    for bad in (fid[:4], "zzzzzzzzzz", "%"):
        with pytest.raises(SystemExit):
            repro.main(["--db", str(world["db"]), bad])


def test_cli_exits_non_zero_on_tampering(world, capsys):
    p = world["sealed"]
    p.chmod(0o666)
    p.write_bytes(p.read_bytes() + b"\n")
    code = repro.main(["--db", str(world["db"]), "--geo-db", str(world["geo"]), "--all"])
    out = capsys.readouterr().out
    assert code == 1 and "FAIL" in out and "MISMATCH" in out


# ----------------------------------------------------------------------- timeline (#19)
def test_timeline_is_a_pure_function_of_stored_records(world):
    """The timeline has no hash or version of its own, so what can be shown is that it is rebuilt
    identically from stored findings and re-derived events, and that every finding entry points at a
    stored finding."""
    sealed, ev_id = world["sealed"], world["evidence_id"]
    events, _ = repro._run_parser("auth", sealed, ev_id, 2026)
    runs = []
    for _ in range(2):
        c = open_db(world)
        runs.append(build_timeline(events, load_findings_from_db(c)))
        stored = {r[0] for r in c.execute("SELECT finding_id FROM findings")}
        c.close()
    assert runs[0] == runs[1] and runs[0]
    finding_entries = [e for e in runs[0] if e["entry_type"] == "finding"]
    assert len(finding_entries) == 3
    assert all(e["provenance"]["finding_id"] in stored for e in finding_entries)