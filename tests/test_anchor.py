"""
Tests for external anchoring (Issue #7): seal/anchor.py and the independent
verifier/anchor_check.py.

Real Ed25519 + real ML-DSA-65, no mocks. If liboqs is unavailable the whole
module is SKIPPED (shown as skipped, never passed).

Tests marked LIMITATION pin down what anchoring does NOT protect against, so
the limit is explicit and cannot be quietly over-claimed.
"""

import ast
import base64
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

# Skip ONLY if liboqs itself cannot be imported. Importing our own modules is
# deliberately outside the try: a real bug in seal/ must fail loudly here, not
# hide behind a "skipped" (a skipped test is not a passed test).
try:
    import oqs  # noqa: F401
except Exception as exc:  # ImportError, or liboqs' RuntimeError on a failed native build
    pytest.skip(f"liboqs unavailable, anchoring not tested here: {type(exc).__name__}", allow_module_level=True)

from seal import anchor, signing
from seal import custody_log
from seal.custody_log import append_entry
from verifier import anchor_check

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "schema.sql"
GUARD_TRIGGERS = ("custody_log_no_update", "custody_log_no_delete", "custody_log_no_replace")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    keys_dir = tmp_path_factory.mktemp("keys")
    signing.create_case_keys("case1", keys_dir=keys_dir)
    return SimpleNamespace(dir=keys_dir, public=keys_dir / "case1" / "public")


@pytest.fixture
def env(tmp_path, keys):
    """A database file in tmp/db, an (existing) anchor directory in tmp/usb."""
    db_dir, usb = tmp_path / "db", tmp_path / "usb"
    db_dir.mkdir()
    usb.mkdir()
    db_path = db_dir / "stamped.db"
    conn = sqlite3.connect(db_path, timeout=30)
    conn.executescript(SCHEMA_PATH.read_text())
    fill(conn, 5)
    yield SimpleNamespace(conn=conn, db=db_path, usb=usb, keys=keys)
    conn.close()


def fill(conn, n, start=0):
    for i in range(start, start + n):
        append_entry(conn, "ash", "examiner", f"action_{i}", evidence_id="ev1", details={"i": i})
    conn.commit()


def make_anchor(env):
    return anchor.create_anchor(env.conn, case_id="case1", anchor_dir=env.usb, keys_dir=env.keys.dir)


def check(env, **kw):
    return anchor_check.check_anchors(env.db, env.usb, env.keys.public, **kw)


def codes(result):
    return [f["code"] for f in result["failures"]]


def drop_guards(conn):
    for t in GUARD_TRIGGERS:
        conn.execute(f"DROP TRIGGER IF EXISTS {t}")


def tamper(conn, sql, args=()):
    """What an attacker with raw DB-file access can do: remove the guards, then edit."""
    drop_guards(conn)
    conn.execute(sql, args)
    conn.commit()


def rewrite_suffix_consistently(conn, from_entry):
    """The perfect forgery: recompute prev_hash/entry_hash for every entry from
    `from_entry` onward so the chain is internally consistent again."""
    rows = conn.execute(
        "SELECT entry_id, timestamp_utc, actor, role, action, evidence_id, artifact_id, details_json "
        "FROM custody_log WHERE entry_id >= ? ORDER BY entry_id", (from_entry,)
    ).fetchall()
    prev = conn.execute("SELECT entry_hash FROM custody_log WHERE entry_id = ?", (from_entry - 1,)).fetchone()[0]
    for entry_id, ts, actor, role, action, ev, art, details in rows:
        fields = {"timestamp_utc": ts, "actor": actor, "role": role, "action": action,
                  "evidence_id": ev, "artifact_id": art, "details_json": details}
        new_hash = custody_log._compute_entry_hash(fields, prev)
        conn.execute("UPDATE custody_log SET prev_hash = ?, entry_hash = ? WHERE entry_id = ?",
                     (prev, new_hash, entry_id))
        prev = new_hash
    conn.commit()


def anchor_path(env, n):
    return env.usb / f"anchor_{n:06d}.json"


def load(path):
    return json.loads(Path(path).read_text())


def save(path, record):
    path = Path(path)
    os.chmod(path, 0o644)
    path.write_text(json.dumps(record, indent=2, sort_keys=True))


def write_signed_anchor(env, seq, **overrides):
    """An insider WITH the signing keys writes a validly signed anchor, with
    chosen payload values. Lets tests build specific inconsistent states."""
    prev = anchor_path(env, seq - 1)
    prev_hash = load(prev)["anchor_hash"] if prev.exists() else "0" * 64
    payload = {
        "format": "stamped-anchor/1", "case_id": "case1", "seq": seq,
        "anchored_at": "2026-10-11T09:00:00+00:00", "head_entry_id": 5,
        "head_entry_hash": env.conn.execute("SELECT entry_hash FROM custody_log WHERE entry_id = 5").fetchone()[0],
        "entry_count": 5, "prev_anchor_hash": prev_hash,
    }
    payload.update(overrides)
    msg = anchor.payload_bytes(payload)
    ed_priv, pq_priv = signing.load_private_keys("case1", env.keys.dir)
    sig_c, sig_pq = signing.sign_hybrid(msg, ed_priv, pq_priv)
    record = {
        "format": "stamped-anchor/1", "payload": payload, "anchor_hash": hashlib.sha256(msg).hexdigest(),
        "signatures": {"ed25519": base64.b64encode(sig_c).decode(), "ml_dsa_65": base64.b64encode(sig_pq).decode()},
        "meta": {"location_assurance": "separate_device"},
    }
    anchor_path(env, seq).write_text(json.dumps(record, indent=2, sort_keys=True))


def flip_b64_byte(b64: str) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[0] ^= 0xFF
    return base64.b64encode(bytes(raw)).decode()


# ---------------------------------------------------------------------------
# Format: pinned so the app and the independent checker cannot drift apart
# ---------------------------------------------------------------------------
# Computed by a standalone script that imports neither seal nor verifier.
GOLDEN_PAYLOAD = {
    "format": "stamped-anchor/1", "case_id": "case1", "seq": 1,
    "anchored_at": "2026-10-11T08:30:00+00:00", "head_entry_id": 5,
    "head_entry_hash": "ab" * 32, "entry_count": 5, "prev_anchor_hash": "0" * 64,
}
GOLDEN_CANONICAL = (
        '{"anchored_at":"2026-10-11T08:30:00+00:00","case_id":"case1","entry_count":5,'
        '"format":"stamped-anchor/1","head_entry_hash":"' + "ab" * 32 + '","head_entry_id":5,'
                                                                        '"prev_anchor_hash":"' + "0" * 64 + '","seq":1}'
)
GOLDEN_SHA256 = "c96231e574ab2c2258afb1297660f6f7a2dad4a9c1153905d21918cdc994b749"


def test_golden_payload_canonical_form_and_hash_are_pinned():
    assert anchor.canonical_json(GOLDEN_PAYLOAD) == GOLDEN_CANONICAL
    assert hashlib.sha256(anchor.payload_bytes(GOLDEN_PAYLOAD)).hexdigest() == GOLDEN_SHA256


def test_app_and_independent_checker_agree_on_the_signed_bytes():
    assert anchor.payload_bytes(GOLDEN_PAYLOAD) == anchor_check._canonical(GOLDEN_PAYLOAD).encode("utf-8")


@pytest.mark.parametrize("bad_entry", [1, 2, 3, 4, 5])
def test_app_and_independent_checker_agree_on_chain_verification(env, bad_entry):
    rows = custody_log.fetch_chain_rows(env.conn)
    assert custody_log.verify_chain_rows(rows) == anchor_check.verify_chain(rows) == (True, None)
    tamper(env.conn, "UPDATE custody_log SET actor = 'x' WHERE entry_id = ?", (bad_entry,))
    rows = custody_log.fetch_chain_rows(env.conn)
    assert custody_log.verify_chain_rows(rows) == anchor_check.verify_chain(rows) == (False, bad_entry)


# ---------------------------------------------------------------------------
# create_anchor
# ---------------------------------------------------------------------------
def test_create_anchor_signs_the_current_head_and_writes_one_file(env):
    record = make_anchor(env)
    files = sorted(p.name for p in env.usb.iterdir())
    assert files == ["anchor_000001.json"]

    head_id, head_hash = env.conn.execute(
        "SELECT entry_id, entry_hash FROM custody_log WHERE action != 'anchored' ORDER BY entry_id DESC LIMIT 1"
    ).fetchone()
    p = record["payload"]
    assert (p["head_entry_id"], p["head_entry_hash"], p["entry_count"]) == (head_id, head_hash, 5)
    assert p["seq"] == 1 and p["prev_anchor_hash"] == "0" * 64 and p["case_id"] == "case1"
    assert p["anchored_at"].endswith("+00:00")


def test_both_signatures_are_real_and_verify_over_the_exact_payload_bytes(env):
    record = make_anchor(env)
    ed_pub, pq_pub = signing.load_public_keys(env.keys.public)
    sig_c = base64.b64decode(record["signatures"]["ed25519"])
    sig_pq = base64.b64decode(record["signatures"]["ml_dsa_65"])
    assert len(sig_c) == 64 and len(sig_pq) > 3000
    assert signing.verify_hybrid(anchor.payload_bytes(record["payload"]), sig_c, sig_pq, ed_pub, pq_pub) is True
    assert record["anchor_hash"] == hashlib.sha256(anchor.payload_bytes(record["payload"])).hexdigest()


def test_anchors_chain_to_each_other(env):
    first = make_anchor(env)
    fill(env.conn, 2, start=10)
    second = make_anchor(env)
    assert second["payload"]["seq"] == 2
    assert second["payload"]["prev_anchor_hash"] == first["anchor_hash"]
    assert second["payload"]["head_entry_id"] > first["payload"]["head_entry_id"]


def test_anchor_is_recorded_in_the_anchors_table_and_the_custody_log(env):
    record = make_anchor(env)
    row = env.conn.execute("SELECT anchor_id, entry_hash, anchor_type, external_reference FROM anchors").fetchone()
    assert row[0] == record["anchor_id"] and row[1] == record["payload"]["head_entry_hash"]
    assert row[2] == "signed-file" and row[3].endswith("anchor_000001.json")

    action, details = env.conn.execute(
        "SELECT action, details_json FROM custody_log ORDER BY entry_id DESC LIMIT 1"
    ).fetchone()
    assert action == "anchored"
    assert json.loads(details)["anchored_entry_id"] == record["payload"]["head_entry_id"]
    assert custody_log.recompute_and_verify_chain(env.conn) == (True, None)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_anchor_file_is_read_only_and_never_overwritten(env):
    make_anchor(env)
    path = anchor_path(env, 1)
    assert stat.S_IMODE(path.stat().st_mode) == 0o444
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        anchor._write_new_file(path, b"overwrite attempt")
    assert path.read_bytes() == before


def test_anchor_is_published_atomically_never_visible_half_written(tmp_path):
    path = tmp_path / "anchor_000001.json"
    data = b'{"complete": true}' * 500
    seen = []
    real_link = os.link

    def spy(src, dst):
        assert not Path(dst).exists()               # final name does not exist yet...
        assert Path(src).read_bytes() == data       # ...and the temp file is already complete
        seen.append(True)
        return real_link(src, dst)

    with mock.patch.object(anchor.os, "link", spy):
        anchor._write_new_file(path, data)
    assert seen == [True] and path.read_bytes() == data
    assert [p.name for p in tmp_path.iterdir()] == ["anchor_000001.json"]      # temp file cleaned up


def test_publishing_falls_back_when_the_filesystem_has_no_hard_links(tmp_path):
    path = tmp_path / "anchor_000001.json"
    with mock.patch.object(anchor.os, "link", side_effect=OSError(1, "Operation not permitted")):
        anchor._write_new_file(path, b"data")
    assert path.read_bytes() == b"data"
    assert [p.name for p in tmp_path.iterdir()] == ["anchor_000001.json"]


def test_publishing_never_overwrites_and_leaves_no_temp_file(tmp_path):
    path = tmp_path / "anchor_000001.json"
    path.write_bytes(b"original")
    for link_behaviour in (None, OSError(1, "no hard links")):
        patch = mock.patch.object(anchor.os, "link", side_effect=link_behaviour) if link_behaviour else mock.patch.object(anchor.os, "link", wraps=os.link)
        with patch:
            with pytest.raises(FileExistsError):
                anchor._write_new_file(path, b"overwrite attempt")
        assert path.read_bytes() == b"original"
        assert [p.name for p in tmp_path.iterdir()] == ["anchor_000001.json"]


def test_a_file_still_being_written_gets_a_grace_period_not_a_false_corruption_alarm(env):
    make_anchor(env)
    path = anchor_path(env, 1)
    good = path.read_text()
    os.chmod(path, 0o644)
    path.write_text(good[:20])                      # looks half-written

    def finish_writing():
        import time; time.sleep(0.15)
        path.write_text(good)

    t = threading.Thread(target=finish_writing); t.start()
    seq, _, head_id = anchor._read_previous_anchor(env.usb)
    t.join()
    assert (seq, head_id) == (1, 5)


def test_lost_sequence_race_retries_with_the_next_number(env):
    make_anchor(env)
    real = anchor._read_previous_anchor
    calls = {"n": 0}

    def stale_once(anchor_dir):
        calls["n"] += 1
        return (0, "0" * 64, 0) if calls["n"] == 1 else real(anchor_dir)  # first look: pretend no anchors yet

    with mock.patch.object(anchor, "_read_previous_anchor", stale_once):
        record = make_anchor(env)
    assert record["payload"]["seq"] == 2
    assert sorted(p.name for p in env.usb.iterdir()) == ["anchor_000001.json", "anchor_000002.json"]
    assert check(env)["ok"] is True


def test_a_stale_snapshot_is_discarded_instead_of_anchored(env):
    """If another process anchored while we were reading, our view of the chain
    is older than the newest anchor. Anchoring it would make the anchors appear
    to go backwards, so it must be thrown away and re-read."""
    make_anchor(env)                                   # newest anchor now covers entry #5 (and #6 exists)
    real = anchor.fetch_chain_rows
    calls = {"n": 0}

    def stale_first_time(conn):
        calls["n"] += 1
        rows = real(conn)
        return rows[:3] if calls["n"] == 1 else rows   # a valid but OLD prefix of the chain

    with mock.patch.object(anchor, "fetch_chain_rows", stale_first_time):
        record = make_anchor(env)
    assert calls["n"] == 2                             # it noticed, and re-read
    assert record["payload"]["head_entry_id"] >= 5
    assert check(env)["ok"] is True                    # no regression in the anchor sequence


def test_refuses_an_empty_log(tmp_path, keys):
    usb = tmp_path / "usb"; usb.mkdir()
    conn = sqlite3.connect(tmp_path / "e.db"); conn.executescript(SCHEMA_PATH.read_text())
    with pytest.raises(anchor.AnchorError, match="empty"):
        anchor.create_anchor(conn, case_id="case1", anchor_dir=usb, keys_dir=keys.dir)


def test_refuses_to_anchor_an_already_broken_chain(env):
    tamper(env.conn, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = 3")
    with pytest.raises(anchor.AnchorError, match="broken at entry 3"):
        make_anchor(env)
    assert list(env.usb.iterdir()) == []          # nothing written
    assert env.conn.execute("SELECT COUNT(*) FROM anchors").fetchone()[0] == 0


def test_refuses_to_anchor_a_perfectly_rewritten_log_that_contradicts_an_earlier_anchor(env):
    """The chain recomputes cleanly after a perfect forgery, so 'chain not broken'
    is not enough: creating a new anchor must also compare against existing ones."""
    make_anchor(env)
    tamper(env.conn, "UPDATE custody_log SET action = 'tampered' WHERE entry_id = 3")
    rewrite_suffix_consistently(env.conn, from_entry=3)
    assert custody_log.recompute_and_verify_chain(env.conn) == (True, None)     # chain alone is fooled
    entries_before = env.conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0]
    with pytest.raises(anchor.AnchorError, match="History was rewritten"):
        make_anchor(env)
    assert [p.name for p in env.usb.iterdir()] == ["anchor_000001.json"]         # no second anchor
    assert env.conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0] == entries_before  # no 'anchored' entry


def test_refuses_to_anchor_a_log_with_entries_deleted_since_the_last_anchor(env):
    make_anchor(env)
    tamper(env.conn, "DELETE FROM custody_log WHERE entry_id >= 4")
    with pytest.raises(anchor.AnchorError, match="no longer in the log"):
        make_anchor(env)
    assert [p.name for p in env.usb.iterdir()] == ["anchor_000001.json"]


def test_does_not_auto_create_a_missing_anchor_directory(env, tmp_path):
    missing = tmp_path / "usb_not_mounted"
    with pytest.raises(anchor.AnchorError, match="does not exist"):
        anchor.create_anchor(env.conn, case_id="case1", anchor_dir=missing, keys_dir=env.keys.dir)
    assert not missing.exists()


def test_missing_keys_write_nothing(env):
    with pytest.raises(signing.KeyManagementError):
        anchor.create_anchor(env.conn, case_id="no_such_case", anchor_dir=env.usb, keys_dir=env.keys.dir)
    assert list(env.usb.iterdir()) == []


def test_corrupt_previous_anchor_is_not_built_upon(env):
    make_anchor(env)
    save(anchor_path(env, 1), {"garbage": True})
    with pytest.raises(anchor.AnchorError, match="unreadable or malformed"):
        make_anchor(env)


def test_database_failure_after_the_external_write_is_reported_and_rolled_back(env):
    env.conn.execute("DROP TABLE anchors")
    env.conn.commit()
    before = env.conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0]
    with pytest.raises(anchor.AnchorError, match="WAS written externally"):
        make_anchor(env)
    assert env.conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0] == before  # no half-recorded state
    assert anchor_path(env, 1).exists()                       # the external anchor still stands...
    assert check(env)["ok"] is True                           # ...and is still valid


def test_in_memory_database_can_be_anchored(tmp_path, keys):
    usb = tmp_path / "usb"; usb.mkdir()
    conn = sqlite3.connect(":memory:"); conn.executescript(SCHEMA_PATH.read_text()); fill(conn, 3)
    record = anchor.create_anchor(conn, case_id="case1", anchor_dir=usb, keys_dir=keys.dir)
    assert record["payload"]["entry_count"] == 3


# --- DoD / guardrail: the anchor must be OUTSIDE the application's write path --
def test_refuses_anchor_directory_inside_the_database_directory(env):
    inside = env.db.parent / "anchors"; inside.mkdir()
    with pytest.raises(anchor.AnchorError, match="overlaps the database directory"):
        anchor.create_anchor(env.conn, case_id="case1", anchor_dir=inside, keys_dir=env.keys.dir)


def test_refuses_anchor_directory_equal_to_the_database_directory(env):
    with pytest.raises(anchor.AnchorError, match="overlaps"):
        anchor.create_anchor(env.conn, case_id="case1", anchor_dir=env.db.parent, keys_dir=env.keys.dir)


def test_refuses_anchor_directory_that_contains_the_database(env):
    with pytest.raises(anchor.AnchorError, match="overlaps"):
        anchor.create_anchor(env.conn, case_id="case1", anchor_dir=env.db.parent.parent, keys_dir=env.keys.dir)


def test_refuses_anchor_directory_inside_the_application_tree(env):
    inside_repo = REPO_ROOT / "data"
    inside_repo.mkdir(exist_ok=True)
    try:
        with pytest.raises(anchor.AnchorError, match="overlaps the application directory"):
            anchor.create_anchor(env.conn, case_id="case1", anchor_dir=inside_repo, keys_dir=env.keys.dir)
    finally:
        if not any(inside_repo.iterdir()):
            inside_repo.rmdir()


def test_refuses_a_symlink_into_the_database_directory(env, tmp_path):
    link = tmp_path / "innocent_looking"
    try:
        link.symlink_to(env.db.parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available here")
    with pytest.raises(anchor.AnchorError, match="overlaps"):
        anchor.create_anchor(env.conn, case_id="case1", anchor_dir=link, keys_dir=env.keys.dir)


def test_location_assurance_distinguishes_same_and_separate_devices(env):
    real_stat = os.stat
    usb_resolved = str(env.usb.resolve())   # resolved BEFORE patching: Path.resolve() itself calls os.stat

    def fake_stat(path, *a, **kw):
        result = real_stat(path, *a, **kw)
        dev = 999 if os.fspath(path) == usb_resolved else 111
        return SimpleNamespace(st_dev=dev, st_mode=result.st_mode)

    assert anchor.check_anchor_location(env.usb, env.db.resolve()) == "same_device"
    with mock.patch.object(anchor.os, "stat", fake_stat):
        assert anchor.check_anchor_location(env.usb, env.db.resolve()) == "separate_device"
    assert make_anchor(env)["meta"]["location_assurance"] == "same_device"  # honest label in this sandbox


# ---------------------------------------------------------------------------
# Periodic anchoring
# ---------------------------------------------------------------------------
def test_has_unanchored_entries_ignores_the_anchors_own_bookkeeping(env):
    assert anchor.has_unanchored_entries(env.conn) is True
    make_anchor(env)                       # appends an 'anchored' entry of its own
    assert anchor.has_unanchored_entries(env.conn) is False
    fill(env.conn, 1, start=50)
    assert anchor.has_unanchored_entries(env.conn) is True


def test_watch_anchors_only_when_something_new_happened(env):
    env.conn.close()
    messages = []
    created = anchor.watch(env.db, case_id="case1", anchor_dir=env.usb, keys_dir=env.keys.dir,
                           interval_seconds=0.01, max_rounds=3, log=messages.append)
    assert created == 1
    assert sorted(p.name for p in env.usb.iterdir()) == ["anchor_000001.json"]
    assert sum("skipping" in m for m in messages) == 2


def test_watch_picks_up_new_entries_on_a_later_round(env):
    env.conn.close()
    stop = threading.Event()
    seen = []

    def log(msg):
        seen.append(msg)
        if len(seen) == 1:                       # after the first anchor, add an entry
            c = sqlite3.connect(env.db, timeout=30); fill(c, 1, start=70); c.close()
        if len(seen) == 3:
            stop.set()

    created = anchor.watch(env.db, case_id="case1", anchor_dir=env.usb, keys_dir=env.keys.dir,
                           interval_seconds=0.01, stop_event=stop, log=log)
    assert created == 2


# --- concurrency: a manual anchor and the periodic job at the same time -------
def test_concurrent_anchoring_produces_a_clean_monotonic_anchor_sequence(env):
    env.conn.close()
    errors = []

    def worker():
        try:
            c = sqlite3.connect(env.db, timeout=60)
            for _ in range(3):
                anchor.create_anchor(c, case_id="case1", anchor_dir=env.usb, keys_dir=env.keys.dir)
            c.close()
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert errors == []
    n = len(list(env.usb.iterdir()))
    assert n == 12
    result = anchor_check.check_anchors(env.db, env.usb, env.keys.public)
    assert result["ok"] is True, result["failures"]       # contiguous, linked, never going backwards
    assert result["anchors_checked"] == 12


# ---------------------------------------------------------------------------
# DoD: anchor, then tamper with a pre-anchor entry -> caught by the anchor check
# ---------------------------------------------------------------------------
def test_untouched_log_passes(env):
    make_anchor(env)
    result = check(env)
    assert result["ok"] is True and result["failures"] == []
    assert result["anchors_checked"] == 1 and result["latest_anchor"]["head_entry_id"] == 5


def test_DOD_editing_a_pre_anchor_entry_is_caught(env):
    make_anchor(env)
    tamper(env.conn, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = 3")
    result = check(env)
    assert result["ok"] is False
    assert "chain_broken" in codes(result)
    assert result["chain"]["first_bad_entry"] == 3


def test_anchor_closes_LIMITATION_perfect_suffix_rewrite(env):
    """Chain-only verification cannot catch an attacker who edits entry 3 and
    recomputes every later hash (see tests/test_custody_log.py). The anchor can."""
    make_anchor(env)
    tamper(env.conn, "UPDATE custody_log SET action = 'tampered' WHERE entry_id = 3")
    rewrite_suffix_consistently(env.conn, from_entry=3)
    assert custody_log.recompute_and_verify_chain(env.conn) == (True, None)   # chain alone is fooled...
    result = check(env)
    assert result["ok"] is False                                              # ...the anchor is not
    assert result["chain"]["ok"] is True
    assert "anchored_hash_mismatch" in codes(result)


def test_anchor_closes_LIMITATION_truncating_the_newest_entries(env):
    make_anchor(env)
    tamper(env.conn, "DELETE FROM custody_log WHERE entry_id >= 4")
    assert custody_log.recompute_and_verify_chain(env.conn) == (True, None)   # a shorter chain looks fine
    result = check(env)
    assert result["ok"] is False
    assert "anchored_entry_missing" in codes(result)


def test_deleting_a_middle_entry_is_caught(env):
    make_anchor(env)
    tamper(env.conn, "DELETE FROM custody_log WHERE entry_id = 3")
    result = check(env)
    assert result["ok"] is False
    assert "chain_broken" in codes(result)


def test_LIMITATION_entries_added_after_the_newest_anchor_are_not_protected(env):
    make_anchor(env)
    fill(env.conn, 3, start=20)
    tamper(env.conn, "UPDATE custody_log SET action = 'tampered' WHERE entry_id = 8")   # after the anchor
    rewrite_suffix_consistently(env.conn, from_entry=8)
    result = check(env)
    assert result["ok"] is True                                                         # undetectable...
    assert result["unanchored_entries"] > 0                                             # ...and says so
    assert any("not externally protected" in w for w in result["warnings"])


# ---------------------------------------------------------------------------
# Attacks on the anchor files themselves
# ---------------------------------------------------------------------------
def test_editing_the_anchored_hash_in_the_file_is_caught(env):
    make_anchor(env)
    rec = load(anchor_path(env, 1))
    rec["payload"]["head_entry_hash"] = "0" * 64
    save(anchor_path(env, 1), rec)
    result = check(env)
    assert result["ok"] is False
    assert {"anchor_hash_mismatch", "anchor_signature_invalid"} <= set(codes(result))


@pytest.mark.parametrize("which, expect", [("ed25519", "Ed25519"), ("ml_dsa_65", "ML-DSA")])
def test_a_single_bad_signature_fails_the_anchor_and_names_it(env, which, expect):
    make_anchor(env)
    rec = load(anchor_path(env, 1))
    rec["signatures"][which] = flip_b64_byte(rec["signatures"][which])
    save(anchor_path(env, 1), rec)
    result = check(env)
    assert result["ok"] is False
    msg = next(f["message"] for f in result["failures"] if f["code"] == "anchor_signature_invalid")
    assert expect in msg


def test_an_anchor_signed_with_someone_elses_keys_is_rejected(env, tmp_path):
    make_anchor(env)
    other = tmp_path / "other_keys"; other.mkdir()
    signing.create_case_keys("case1", keys_dir=other)
    result = anchor_check.check_anchors(env.db, env.usb, other / "case1" / "public")
    assert result["ok"] is False and "anchor_signature_invalid" in codes(result)


def test_removing_a_middle_anchor_is_caught(env):
    make_anchor(env); fill(env.conn, 1, start=30)
    make_anchor(env); fill(env.conn, 1, start=31)
    make_anchor(env)
    os.chmod(anchor_path(env, 2), 0o644); anchor_path(env, 2).unlink()
    result = check(env)
    assert result["ok"] is False
    assert {"anchor_sequence_gap", "anchor_link_broken"} <= set(codes(result))


def test_removing_the_oldest_anchor_is_caught(env):
    make_anchor(env); fill(env.conn, 1, start=30); make_anchor(env)
    os.chmod(anchor_path(env, 1), 0o644); anchor_path(env, 1).unlink()
    assert "anchor_sequence_gap" in codes(check(env))


def test_LIMITATION_deleting_the_newest_anchor_is_not_detectable_by_this_check(env):
    """Why the anchor storage must be append-only / held by someone else."""
    make_anchor(env); fill(env.conn, 1, start=30); make_anchor(env)
    os.chmod(anchor_path(env, 2), 0o644); anchor_path(env, 2).unlink()
    result = check(env)
    assert result["ok"] is True
    assert result["latest_anchor"]["seq"] == 1


def test_no_anchors_is_a_failure_not_a_pass(env):
    result = check(env)
    assert result["ok"] is False and codes(result) == ["no_anchors"]


def test_no_anchors_can_be_explicitly_allowed_but_says_nothing_external_was_checked(env):
    result = check(env, require_anchor=False)
    assert result["ok"] is True and result["anchors_checked"] == 0
    assert any("nothing external was checked" in w for w in result["warnings"])


def test_a_corrupt_anchor_file_fails_loudly(env):
    make_anchor(env)
    anchor_path(env, 1).chmod(0o644)
    anchor_path(env, 1).write_text('{"payload": {"truncated')
    result = check(env)
    assert result["ok"] is False and "anchor_unreadable" in codes(result)


def test_stray_files_are_ignored_with_a_note(env):
    make_anchor(env)
    (env.usb / ".DS_Store").write_text("x")
    result = check(env)
    assert result["ok"] is True
    assert any(".DS_Store" in w for w in result["warnings"])


def test_a_signed_anchor_with_the_wrong_entry_count_is_caught(env):
    write_signed_anchor(env, 1, entry_count=4)
    result = check(env)
    assert result["ok"] is False and "anchored_entry_count_mismatch" in codes(result)


def test_an_anchor_that_goes_backwards_is_caught(env):
    write_signed_anchor(env, 1, head_entry_id=5, entry_count=5)
    head3 = env.conn.execute("SELECT entry_hash FROM custody_log WHERE entry_id = 3").fetchone()[0]
    write_signed_anchor(env, 2, head_entry_id=3, head_entry_hash=head3, entry_count=3)
    assert "anchor_regression" in codes(check(env))


def test_a_file_number_that_disagrees_with_the_signed_sequence_is_caught(env):
    write_signed_anchor(env, 1)
    anchor_path(env, 1).rename(anchor_path(env, 2))
    result = check(env)
    assert result["ok"] is False
    assert {"anchor_seq_mismatch", "anchor_sequence_gap"} & set(codes(result))


# ---------------------------------------------------------------------------
# Fails closed: anything that cannot be checked is not a pass
# ---------------------------------------------------------------------------
def test_missing_liboqs_is_an_error_not_a_pass(env, capsys):
    make_anchor(env)
    with mock.patch.object(anchor_check, "_load_oqs", side_effect=anchor_check.CheckerError("no liboqs")):
        rc = anchor_check.main(["--db", str(env.db), "--anchors", str(env.usb), "--public-keys", str(env.keys.public)])
    assert rc == 2
    assert "PASS" not in capsys.readouterr().out


def test_real_import_failure_of_liboqs_raises_checker_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "oqs", None)       # makes `import oqs` raise ImportError
    with pytest.raises(anchor_check.CheckerError, match="Refusing to report a result"):
        anchor_check._load_oqs()


@pytest.mark.parametrize("args", [
    lambda e: ["--db", "/no/such.db", "--anchors", str(e.usb), "--public-keys", str(e.keys.public)],
    lambda e: ["--db", str(e.db), "--anchors", "/no/such/dir", "--public-keys", str(e.keys.public)],
    lambda e: ["--db", str(e.db), "--anchors", str(e.usb), "--public-keys", "/no/such/keys"],
])
def test_unusable_inputs_exit_with_error_code_2(env, args, capsys):
    assert anchor_check.main(args(env)) == 2
    assert "PASS" not in capsys.readouterr().out


def test_the_checker_never_writes_to_the_database(env):
    make_anchor(env)
    before = env.db.read_bytes()
    check(env)
    assert env.db.read_bytes() == before
    with pytest.raises(sqlite3.OperationalError):   # the connection it uses is read-only
        c = sqlite3.connect(env.db.resolve().as_uri() + "?mode=ro", uri=True)
        c.execute("INSERT INTO anchors (anchor_id, entry_hash, anchor_type, anchored_at) VALUES ('x','y','z','w')")


# ---------------------------------------------------------------------------
# Guardrail 2: the comparison is wired into the REAL path and fails it.
# Run both command-line tools as separate processes, as a user would.
# ---------------------------------------------------------------------------
def _run(args, cwd):
    return subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": ""})


def test_end_to_end_via_the_real_command_line_tools(env, tmp_path):
    env.conn.close()
    create = ["-m", "seal.anchor", "create", "--db", str(env.db), "--case", "case1",
              "--anchor-dir", str(env.usb), "--keys-dir", str(env.keys.dir)]
    verify = [str(REPO_ROOT / "verifier" / "anchor_check.py"), "--db", str(env.db),
              "--anchors", str(env.usb), "--public-keys", str(env.keys.public)]

    r = _run(create, REPO_ROOT)
    assert r.returncode == 0, r.stderr
    assert "Anchor created" in r.stdout

    # Run the checker from an unrelated directory with no PYTHONPATH: it must not need the app.
    ok = _run(verify, tmp_path)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "ANCHOR CHECK: PASS" in ok.stdout

    c = sqlite3.connect(env.db)
    tamper(c, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = 2")
    c.close()
    bad = _run(verify, tmp_path)
    assert bad.returncode == 1, bad.stdout
    assert "ANCHOR CHECK: FAIL" in bad.stdout and "entry 2" in bad.stdout

    refused = _run(create, REPO_ROOT)                     # and it will not anchor the tampered log
    assert refused.returncode == 1 and "broken at entry 2" in refused.stderr


@pytest.mark.parametrize("flags", [[], ["-OO"]])
def test_cli_does_not_depend_on_docstrings_being_present(flags):
    """`python -OO` strips docstrings (as can some editors/tools). The CLI must
    still start; it once built its --help text from __doc__ and crashed."""
    r = subprocess.run([sys.executable, *flags, "-m", "seal.anchor", "create", "--help"],
                       cwd=REPO_ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ""})
    assert r.returncode == 0, r.stderr
    assert "--anchor-dir" in r.stdout


def test_cli_refuses_a_directory_beside_the_database(env):
    inside = env.db.parent / "anchors"; inside.mkdir()
    env.conn.close()
    r = _run(["-m", "seal.anchor", "create", "--db", str(env.db), "--case", "case1",
              "--anchor-dir", str(inside), "--keys-dir", str(env.keys.dir)], REPO_ROOT)
    assert r.returncode == 1 and "overlaps" in r.stderr


# ---------------------------------------------------------------------------
# Independence of the checker (also enforced by scripts/ci_guardrails.py)
# ---------------------------------------------------------------------------
def test_anchor_checker_imports_nothing_from_the_application():
    tree = ast.parse((REPO_ROOT / "verifier" / "anchor_check.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"seal", "app", "ingest", "detect", "access", "report", "capture", "schemas"}
    assert imported & forbidden == set()
    assert imported <= {"argparse", "base64", "binascii", "hashlib", "json", "re", "sqlite3", "sys",
                        "pathlib", "cryptography", "oqs"}