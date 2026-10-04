import sqlite3
from hashlib import sha256
from pathlib import Path

import pytest

from seal.custody_log import recompute_and_verify_chain
from seal.intake import IntakeError, seal_evidence

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "schema.sql"


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    connection.executescript(SCHEMA_PATH.read_text())
    yield connection
    connection.close()


@pytest.fixture
def sample_file(tmp_path):
    p = tmp_path / "sample_log.txt"
    p.write_bytes(b"2026-10-04T12:00:00Z user=root action=login result=success\n")
    return p


@pytest.fixture
def sealed_dir(tmp_path):
    d = tmp_path / "sealed"
    d.mkdir()
    return d


def test_seal_evidence_hashes_actual_bytes_not_a_string_repr(conn, sample_file, sealed_dir):
    evidence_id = seal_evidence(conn, sample_file, metadata={"source": "test"}, sealed_dir=sealed_dir)
    expected_hash = sha256(sample_file.read_bytes()).hexdigest()
    assert evidence_id == expected_hash


def test_seal_evidence_never_modifies_the_original_file(conn, sample_file, sealed_dir):
    original_bytes = sample_file.read_bytes()
    seal_evidence(conn, sample_file, sealed_dir=sealed_dir)
    assert sample_file.read_bytes() == original_bytes


def test_seal_evidence_registers_in_evidence_table(conn, sample_file, sealed_dir):
    evidence_id = seal_evidence(conn, sample_file, metadata={"source": "webhook"}, sealed_dir=sealed_dir)
    row = conn.execute(
        "SELECT evidence_id, content_hash, source FROM evidence WHERE evidence_id = ?", (evidence_id,)
    ).fetchone()
    assert row is not None
    assert row[0] == evidence_id
    assert row[1] == evidence_id
    assert row[2] == "webhook"


def test_seal_evidence_writes_first_custody_entry_atomically(conn, sample_file, sealed_dir):
    evidence_id = seal_evidence(conn, sample_file, sealed_dir=sealed_dir)
    entry = conn.execute(
        "SELECT action, evidence_id FROM custody_log WHERE evidence_id = ? AND action = 'sealed'",
        (evidence_id,),
    ).fetchone()
    assert entry is not None

    ok, bad = recompute_and_verify_chain(conn)
    assert ok is True


def test_sealing_same_file_twice_is_handled_as_logged_re_intake(conn, sample_file, sealed_dir):
    first_id = seal_evidence(conn, sample_file, sealed_dir=sealed_dir)
    second_id = seal_evidence(conn, sample_file, sealed_dir=sealed_dir)

    assert first_id == second_id

    sealed_count = conn.execute(
        "SELECT COUNT(*) FROM custody_log WHERE evidence_id = ? AND action = 'sealed'", (first_id,)
    ).fetchone()[0]
    reintake_count = conn.execute(
        "SELECT COUNT(*) FROM custody_log WHERE evidence_id = ? AND action = 're_intake'", (first_id,)
    ).fetchone()[0]
    assert sealed_count == 1
    assert reintake_count == 1

    evidence_rows = conn.execute(
        "SELECT COUNT(*) FROM evidence WHERE evidence_id = ?", (first_id,)
    ).fetchone()[0]
    assert evidence_rows == 1  # no duplicate evidence row created


def test_sealing_a_missing_file_fails_gracefully_not_a_crash(conn, tmp_path, sealed_dir):
    missing = tmp_path / "does_not_exist.txt"
    with pytest.raises(IntakeError):
        seal_evidence(conn, missing, sealed_dir=sealed_dir)

    failure_entry = conn.execute(
        "SELECT action FROM custody_log WHERE action = 'seal_failed'"
    ).fetchone()
    assert failure_entry is not None

    evidence_rows = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    assert evidence_rows == 0  # no partial/orphaned evidence row


def test_sealing_an_empty_file_does_not_crash(conn, tmp_path, sealed_dir):
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    evidence_id = seal_evidence(conn, empty, sealed_dir=sealed_dir)
    assert evidence_id == sha256(b"").hexdigest()