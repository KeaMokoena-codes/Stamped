"""DB-level tests: findings -> artifacts + findings rows + custody log."""
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from detect.findings import detect_and_record, record_finding
from detect.rules.brute_force import BruteForceConfig, detect
from seal.custody_log import recompute_and_verify_chain

SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "schema.sql"
BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
CFG = BruteForceConfig(threshold=5, window_seconds=60, success_follow_seconds=60)


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.executescript(SCHEMA.read_text(encoding="utf-8"))
    yield c
    c.close()


def _events():
    return [{
        "event_id": f"ev{i}", "evidence_id": "E1" if i % 2 == 0 else "E2",
        "raw_ref": f"line:{i}",
        "timestamp_utc": (BASE + timedelta(seconds=i)).isoformat(),
        "event_type": "auth", "outcome": "failure",
        "account": "alice", "source_ip": "10.0.0.1", "service": "ssh",
    } for i in range(5)]


def _finding():
    return [f for f in detect(_events(), CFG) if f["grouped_by"] == "account"][0]


def _count(conn, sql, *args):
    return conn.execute(sql, args).fetchone()[0]


def test_records_artifact_finding_and_one_custody_entry_per_evidence(conn):
    assert record_finding(conn, _finding()) is True
    conn.commit()
    assert _count(conn, "SELECT COUNT(*) FROM artifacts") == 1
    assert _count(conn, "SELECT COUNT(*) FROM findings") == 1
    assert _count(conn, "SELECT COUNT(*) FROM custody_log WHERE action='finding_created'") == 2
    assert recompute_and_verify_chain(conn) == (True, None)


def test_rerecording_the_same_finding_adds_nothing(conn):
    f = _finding()
    record_finding(conn, f)
    assert record_finding(conn, f) is False
    assert _count(conn, "SELECT COUNT(*) FROM findings") == 1
    assert _count(conn, "SELECT COUNT(*) FROM custody_log") == 2


def test_stored_finding_bytes_hash_to_output_hash(conn):
    f = _finding()
    record_finding(conn, f)
    text, out = conn.execute(
        "SELECT f.details_json, a.output_hash FROM findings f "
        "JOIN artifacts a ON a.artifact_id = f.artifact_id"
    ).fetchone()
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == out == f["finding_hash"]


def test_tampered_finding_is_rejected_and_nothing_written(conn):
    with pytest.raises(ValueError):
        record_finding(conn, dict(_finding(), key="mallory"))
    assert _count(conn, "SELECT COUNT(*) FROM findings") == 0
    assert _count(conn, "SELECT COUNT(*) FROM custody_log") == 0


def test_artifact_provenance_matches_the_finding(conn):
    f = _finding()
    record_finding(conn, f)
    tool, ver, inp = conn.execute(
        "SELECT tool_name, tool_version, input_hash FROM artifacts").fetchone()
    assert (tool, ver, inp) == (f["rule_name"], f["rule_version"], f["input_hash"])


def test_custody_entries_reference_the_finding_hash(conn):
    f = _finding()
    record_finding(conn, f)
    ids = {r[0] for r in conn.execute("SELECT artifact_id FROM custody_log")}
    assert ids == {f["finding_hash"]}


def test_detect_and_record_commits_once_and_is_idempotent(conn):
    first = detect_and_record(conn, _events(), CFG)
    assert first == 2                                   # account + source_ip findings
    assert detect_and_record(conn, _events(), CFG) == 0
    assert recompute_and_verify_chain(conn) == (True, None)


def test_failed_run_rolls_back_everything(conn, monkeypatch):
    import detect.findings as mod
    real, calls = mod.record_finding, {"n": 0}

    def flaky(c, f):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return real(c, f)

    monkeypatch.setattr(mod, "record_finding", flaky)
    with pytest.raises(RuntimeError):
        mod.detect_and_record(conn, _events(), CFG)
    assert _count(conn, "SELECT COUNT(*) FROM findings") == 0
    assert _count(conn, "SELECT COUNT(*) FROM custody_log") == 0