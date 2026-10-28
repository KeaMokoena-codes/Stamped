"""Tests for re-sealing / evidence renewal (Issue #10).

What is pinned here:
  * a re-seal APPENDS one entry and never changes an existing one;
  * the independent verifier accepts a correct re-seal and rejects every way of faking one;
  * the verifier fails closed: a re-seal it cannot check is never a pass.
"""
import base64
import contextlib
import hashlib
import io
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from tests.test_verify import fill, needs_oqs, new_db, rewrite_suffix_consistently, run, tamper
from verifier import verify

REPO_ROOT = Path(__file__).resolve().parent.parent
CASE = "case1"

pytestmark = needs_oqs

try:
    from seal import anchor, reseal, signing
    from seal.custody_log import fetch_chain_rows, recompute_and_verify_chain
except (Exception, SystemExit):  # noqa: BLE001  liboqs missing or broken (it may abort): every test below is skipped, not passed
    anchor = reseal = signing = None


# ---------------------------------------------------------------------------
# Fixtures: own keys, so nothing here leaks into other test modules
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    keys_dir = tmp_path_factory.mktemp("reseal-keys")
    signing.create_case_keys(CASE, keys_dir=keys_dir)
    key_id = reseal.create_reseal_keys(CASE, keys_dir)
    return SimpleNamespace(dir=keys_dir, key_id=key_id, public=keys_dir / CASE / "public")


def build_live(tmp_path, keys, entries=6):
    """The live case: entries, one anchor signed the ORIGINAL way (Ed25519 + ML-DSA-65)."""
    work, usb = tmp_path / "work", tmp_path / "usb"
    work.mkdir()
    usb.mkdir()
    db = work / "stamped.db"
    conn = new_db(db)
    fill(conn, entries)
    anchor.create_anchor(conn, case_id=CASE, anchor_dir=usb, keys_dir=keys.dir)
    return SimpleNamespace(conn=conn, db=db, usb=usb, keys=keys)


def do_reseal(live, **kw):
    kw.setdefault("case_id", CASE)
    kw.setdefault("from_entry_id", 1)
    return reseal.reseal_range(live.conn, keys_dir=live.keys.dir, key_id=live.keys.key_id, **kw)


def export_case(live, tmp_path, name="export"):
    import shutil
    root = tmp_path / name
    root.mkdir()
    shutil.copyfile(live.db, root / "stamped.db")
    shutil.copytree(live.usb, root / "anchors", copy_function=shutil.copyfile)
    shutil.copytree(live.keys.public, root / "public")
    return SimpleNamespace(root=root, db=root / "stamped.db", anchors=root / "anchors", public=root / "public")


def rows_of(db_or_conn):
    if isinstance(db_or_conn, sqlite3.Connection):
        return fetch_chain_rows(db_or_conn)
    conn = sqlite3.connect(db_or_conn)
    try:
        return fetch_chain_rows(conn)
    finally:
        conn.close()


def reseal_entry(db: Path, n=-1):
    conn = sqlite3.connect(db)
    try:
        found = conn.execute("SELECT entry_id, details_json FROM custody_log WHERE action = 'resealed' ORDER BY entry_id").fetchall()
    finally:
        conn.close()
    return found[n]


def rewrite_reseal_details(db: Path, mutate, n=-1):
    """Change a re-seal entry's details, then recompute the chain so it is internally consistent again
    (what a careful forger does). `mutate` edits the parsed details dict in place."""
    entry_id, details = reseal_entry(db, n)
    d = json.loads(details)
    mutate(d)
    tamper(db, "UPDATE custody_log SET details_json = ? WHERE entry_id = ?", (verify.canonical(d), entry_id))
    rewrite_suffix_consistently(db, entry_id)
    return entry_id


def codes(report, kind):
    return [f["code"] for f in report["reseals"][kind]]


# ---------------------------------------------------------------------------
# Creating a re-seal
# ---------------------------------------------------------------------------
def test_a_reseal_appends_exactly_one_entry_and_changes_nothing_that_was_there(tmp_path, keys):
    live = build_live(tmp_path, keys)
    before = rows_of(live.conn)

    result = do_reseal(live)

    after = rows_of(live.conn)
    assert after[:len(before)] == before                      # every original row identical, hashes included
    assert len(after) == len(before) + 1
    assert after[-1][0] == result["entry_id"] and after[-1][4] == "resealed"
    assert after[-1][8] == before[-1][9]                      # it chains onto the old head like any other entry
    assert recompute_and_verify_chain(live.conn) == (True, None)
    assert not live.conn.in_transaction


def test_the_reseal_references_old_hashes_and_defaults_to_the_whole_log(tmp_path, keys):
    live = build_live(tmp_path, keys)
    old = rows_of(live.conn)
    p = do_reseal(live)["payload"]
    assert (p["from_entry_id"], p["to_entry_id"], p["entry_count"]) == (1, old[-1][0], len(old))
    assert p["first_entry_prev_hash"] == old[0][8] == "0" * 64
    assert p["last_entry_hash"] == old[-1][9]
    assert p["range_digest"] == verify.range_digest([r[9] for r in old])
    assert p["suite"] == {"classical": "Ed448", "post_quantum": "ML-DSA-87"}
    assert p["key_id"] == keys.key_id and p["seq"] == 1


def test_a_partial_range_can_be_resealed(tmp_path, keys):
    live = build_live(tmp_path, keys)
    p = do_reseal(live, from_entry_id=2, to_entry_id=4)["payload"]
    assert (p["from_entry_id"], p["to_entry_id"], p["entry_count"]) == (2, 4, 3)


def test_range_digest_is_pinned_and_matches_the_verifiers_own_implementation():
    expected = hashlib.sha256(b'["aa","bb"]').hexdigest()
    assert reseal.range_digest(["aa", "bb"]) == verify.range_digest(["aa", "bb"]) == expected
    assert reseal.range_digest(["bb", "aa"]) != expected      # order matters


def test_reseals_are_numbered_and_a_later_one_can_wrap_an_earlier_one(tmp_path, keys):
    live = build_live(tmp_path, keys)
    first = do_reseal(live)
    second = do_reseal(live)                                  # wraps the first re-seal entry too
    assert (first["payload"]["seq"], second["payload"]["seq"]) == (1, 2)
    assert second["payload"]["to_entry_id"] == first["entry_id"]


@pytest.mark.parametrize("kwargs, message", [
    ({"from_entry_id": 5, "to_entry_id": 2}, "must not come after"),
    ({"from_entry_id": 0}, "must both exist"),
    ({"from_entry_id": 1, "to_entry_id": 999}, "must both exist"),
])
def test_bad_ranges_are_refused_and_leave_the_log_alone(tmp_path, keys, kwargs, message):
    live = build_live(tmp_path, keys)
    before = rows_of(live.conn)
    with pytest.raises(reseal.ResealError, match=message):
        do_reseal(live, **kwargs)
    assert rows_of(live.conn) == before and not live.conn.in_transaction


def test_resealing_an_already_broken_chain_is_refused(tmp_path, keys):
    live = build_live(tmp_path, keys)
    live.conn.close()
    tamper(live.db, "UPDATE custody_log SET actor = 'evil' WHERE entry_id = 2")
    live.conn = sqlite3.connect(live.db)
    count = len(rows_of(live.conn))
    with pytest.raises(reseal.ResealError, match="already broken at entry 2"):
        do_reseal(live)
    assert len(rows_of(live.conn)) == count and not live.conn.in_transaction


def test_an_empty_log_is_refused(tmp_path, keys):
    conn = new_db(tmp_path / "empty.db")
    with pytest.raises(reseal.ResealError, match="empty"):
        reseal.reseal_range(conn, case_id=CASE, from_entry_id=1, keys_dir=keys.dir, key_id=keys.key_id)


def test_missing_or_ambiguous_renewal_keys_are_refused(tmp_path, keys):
    live = build_live(tmp_path, keys)
    with pytest.raises(reseal.ResealError, match="No renewal keys exist"):
        reseal.reseal_range(live.conn, case_id=CASE, from_entry_id=1, keys_dir=tmp_path / "nowhere")
    with pytest.raises(reseal.ResealError, match="No renewal keys 'nope'"):
        reseal.reseal_range(live.conn, case_id=CASE, from_entry_id=1, keys_dir=keys.dir, key_id="nope")

    two = tmp_path / "two-keys"
    signing.create_case_keys(CASE, keys_dir=two)
    reseal.create_reseal_keys(CASE, two)
    reseal.create_reseal_keys(CASE, two)
    with pytest.raises(reseal.ResealError, match="pass --key-id"):
        reseal.reseal_range(live.conn, case_id=CASE, from_entry_id=1, keys_dir=two)


def test_creating_keys_writes_private_files_owner_only_and_a_public_manifest(tmp_path):
    key_id = reseal.create_reseal_keys("demo_case", tmp_path)
    priv = tmp_path / "demo_case" / "reseal" / key_id
    assert sorted(p.name for p in priv.iterdir()) == ["ed448_private.bin", "mldsa87_private.bin"]
    if sys.platform != "win32":
        assert (priv / "ed448_private.bin").stat().st_mode & 0o077 == 0
    manifest = json.loads((tmp_path / "demo_case" / "public" / "reseal" / f"{key_id}.json").read_text())
    assert manifest["key_id"] == key_id and manifest["classical"]["algorithm"] == "Ed448"
    assert "private" not in json.dumps(manifest).lower()
    with pytest.raises(reseal.ResealError):
        reseal.create_reseal_keys("../escape", tmp_path)      # case id becomes a directory name


# ---------------------------------------------------------------------------
# The independent verifier
# ---------------------------------------------------------------------------
def test_verifier_passes_a_correctly_resealed_case_and_lists_the_reseal(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    rc, report, text, err = run(export_case(live, tmp_path))
    assert rc == 0, text + err
    assert report["overall"] == "PASS"
    assert report["reseals"]["status"] == "PASS"
    seg = report["reseals"]["segments"][0]
    assert (seg["ed448"], seg["ml_dsa_87"], seg["range_matches"]) == (True, True, True)
    _, _, text, _ = run(export_case(live, tmp_path, "again"), as_json=False)
    assert "RESULT: PASS" in text and "[4] Re-sealed segments" in text and "RE-SEALS" in text


def test_the_original_anchor_and_entries_still_verify_alongside_the_reseal(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    _, report, _, _ = run(export_case(live, tmp_path))
    assert [report["checks"][k]["status"] for k in ("chain", "signatures", "anchors")] == ["PASS"] * 3
    assert report["checks"]["signatures"]["valid"] == 1       # the Ed25519 + ML-DSA-65 anchor, untouched


def test_a_log_without_reseals_gets_the_same_report_as_before(tmp_path, keys):
    live = build_live(tmp_path, keys)
    rc, report, _, _ = run(export_case(live, tmp_path))
    assert rc == 0 and "reseals" not in report
    _, _, text, _ = run(export_case(live, tmp_path, "again"), as_json=False)
    assert "[4]" not in text and "RE-SEALS" not in text


def test_two_reseals_one_wrapping_the_other_pass(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    do_reseal(live)
    rc, report, text, _ = run(export_case(live, tmp_path))
    assert rc == 0, text
    assert [s["seq"] for s in report["reseals"]["segments"]] == [1, 2]


def test_entries_added_after_a_reseal_do_not_break_it(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live, to_entry_id=4)
    fill(live.conn, 3, start=100)
    rc, report, text, _ = run(export_case(live, tmp_path))
    assert rc == 0, text
    assert report["reseals"]["segments"][0]["entry_count"] == 4


def test_the_perfect_forgery_inside_a_resealed_range_is_caught(tmp_path, keys):
    """Change an old entry and recompute every later hash: the chain is consistent again,
    but the re-seal pinned the original hashes."""
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    tamper(ex.db, "UPDATE custody_log SET actor = 'someone-else' WHERE entry_id = 3")
    rewrite_suffix_consistently(ex.db, 3)
    rc, report, text, _ = run(ex)
    assert rc == 1, text
    assert report["checks"]["chain"]["status"] == "PASS"       # the forgery really is chain-consistent
    assert "reseal_range_mismatch" in codes(report, "failures")
    failure = next(f for f in report["reseals"]["failures"] if f["code"] == "reseal_range_mismatch")
    assert failure["suspect_range"] == [1, report["reseals"]["segments"][0]["to_entry_id"]]
    assert report["reseals"]["segments"][0]["range_matches"] is False


def test_a_removed_entry_inside_the_range_is_caught_even_if_the_chain_is_patched(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    tamper(ex.db, "DELETE FROM custody_log WHERE entry_id = 3")
    rewrite_suffix_consistently(ex.db, 3)  # relink #4 onwards to #2, so the gap is invisible to the chain
    rc, report, _, _ = run(ex)
    assert rc == 1 and "reseal_range_mismatch" in codes(report, "failures")


def test_editing_a_reseal_entry_without_fixing_the_chain_breaks_the_chain_at_that_entry(tmp_path, keys):
    live = build_live(tmp_path, keys)
    result = do_reseal(live)
    ex = export_case(live, tmp_path)
    tamper(ex.db, "UPDATE custody_log SET actor = 'evil' WHERE entry_id = ?", (result["entry_id"],))
    rc, report, _, _ = run(ex)
    assert rc == 1 and report["broken_entry_id"] == result["entry_id"]


def test_a_corrupted_classical_signature_fails_even_with_a_consistent_chain(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)

    def flip(d):
        sig = bytearray(base64.b64decode(d["signatures"]["ed448"]))
        sig[0] ^= 0xFF
        d["signatures"]["ed448"] = base64.b64encode(bytes(sig)).decode()

    rewrite_reseal_details(ex.db, flip)
    rc, report, text, _ = run(ex)
    assert rc == 1, text
    assert codes(report, "failures") == ["reseal_signature_invalid"]
    seg = report["reseals"]["segments"][0]
    assert (seg["ed448"], seg["ml_dsa_87"]) == (False, True)   # one half valid is still a failure: both are required


def test_a_corrupted_post_quantum_signature_fails_even_with_a_consistent_chain(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)

    def flip(d):
        sig = bytearray(base64.b64decode(d["signatures"]["ml_dsa_87"]))
        sig[10] ^= 0xFF
        d["signatures"]["ml_dsa_87"] = base64.b64encode(bytes(sig)).decode()

    rewrite_reseal_details(ex.db, flip)
    rc, report, _, _ = run(ex)
    seg = report["reseals"]["segments"][0]
    assert rc == 1 and (seg["ed448"], seg["ml_dsa_87"]) == (True, False)


def test_changing_the_signed_payload_is_caught_by_the_payload_hash_and_the_signatures(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    rewrite_reseal_details(ex.db, lambda d: d["payload"].update(entry_count=d["payload"]["entry_count"] - 1))
    rc, report, _, _ = run(ex)
    assert rc == 1
    assert {"reseal_hash_mismatch", "reseal_signature_invalid", "reseal_range_mismatch"} <= set(codes(report, "failures"))


def test_a_removed_reseal_is_noticed_when_the_numbering_has_a_gap(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    first_id, _ = reseal_entry(ex.db, 0)
    # An attacker re-labels the first re-seal's action so it is no longer one, then patches the chain.
    tamper(ex.db, "UPDATE custody_log SET action = 'something_else' WHERE entry_id = ?", (first_id,))
    rewrite_suffix_consistently(ex.db, first_id)
    rc, report, _, _ = run(ex)
    assert rc == 1 and "reseal_sequence" in codes(report, "failures")


def test_a_reseal_that_claims_a_range_that_is_not_earlier_is_rejected(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    rewrite_reseal_details(ex.db, lambda d: d["payload"].update(to_entry_id=d["payload"]["to_entry_id"] + 5))
    rc, report, _, _ = run(ex)
    assert rc == 1 and "reseal_range_invalid" in codes(report, "failures")


def test_malformed_reseal_details_are_a_failure_not_a_crash(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    entry_id, _ = reseal_entry(ex.db)
    tamper(ex.db, "UPDATE custody_log SET details_json = ? WHERE entry_id = ?", ("not json at all", entry_id))
    rewrite_suffix_consistently(ex.db, entry_id)
    rc, report, _, err = run(ex)
    assert rc == 1 and "reseal_malformed" in codes(report, "failures") and "Traceback" not in err


def test_missing_renewal_public_keys_are_an_error_never_a_pass(tmp_path, keys):
    import shutil
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    shutil.rmtree(ex.public / "reseal")
    rc, report, text, _ = run(ex)
    assert rc == 2 and report["overall"] == "ERROR", text
    assert report["reseals"]["status"] == "ERROR" and codes(report, "errors") == ["reseal_key_missing"]


def test_an_altered_renewal_key_file_is_a_failure(tmp_path, keys):
    """The key id is a fingerprint of both public keys, so swapping a key under the same id is detectable."""
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    attacker = reseal.create_reseal_keys("attacker", tmp_path / "attacker-keys")
    stolen = json.loads((tmp_path / "attacker-keys" / "attacker" / "public" / "reseal" / f"{attacker}.json").read_text())
    path = ex.public / "reseal" / f"{keys.key_id}.json"
    real = json.loads(path.read_text())
    real["classical"] = stolen["classical"]                    # attacker's Ed448 key under the real key id
    path.write_text(json.dumps(real))
    rc, report, _, _ = run(ex)
    assert rc == 1 and "reseal_key_altered" in codes(report, "failures")


def test_a_reseal_for_a_different_case_than_its_keys_is_a_failure(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    rewrite_reseal_details(ex.db, lambda d: d["payload"].update(case_id="some-other-case"))
    rc, report, _, _ = run(ex)
    assert rc == 1 and "reseal_case_mismatch" in codes(report, "failures")


def test_when_liboqs_is_unavailable_a_reseal_is_an_error_not_a_pass(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    with mock.patch.object(verify, "load_oqs", side_effect=verify.VerifierError("no liboqs")):
        rc, report, _, _ = run(ex)
    assert rc == 2 and report["overall"] == "ERROR"
    assert "liboqs_unavailable" in codes(report, "errors")


def test_a_crash_inside_the_reseal_check_becomes_an_error(tmp_path, keys):
    live = build_live(tmp_path, keys)
    do_reseal(live)
    ex = export_case(live, tmp_path)
    with mock.patch.object(verify, "check_reseals", side_effect=RuntimeError("boom")):
        rc, report, _, _ = run(ex)
    assert rc == 2 and report["overall"] == "ERROR" and codes(report, "errors") == ["internal_error"]


@pytest.mark.parametrize("reseal_status, expected", [
    ("SKIPPED", "PASS"), ("PASS", "PASS"), ("FAIL", "FAIL"), ("ERROR", "ERROR"), ("weird", "ERROR"),
])
def test_decide_counts_the_reseal_check_only_when_it_ran(reseal_status, expected):
    assert verify.decide("PASS", "PASS", "PASS", False, reseal_status) == expected
    assert verify.decide("PASS", "PASS", "PASS", False) == "PASS"      # old call shape unchanged


def test_the_verifier_stays_independent_of_the_application():
    source = (REPO_ROOT / "verifier" / "verify.py").read_text()
    assert not any(line.lstrip().startswith(("from seal", "import seal")) for line in source.splitlines())


# ---------------------------------------------------------------------------
# The command line and the demo
# ---------------------------------------------------------------------------
def test_command_line_creates_keys_and_reseals(tmp_path, keys):
    keys_dir = tmp_path / "cli-keys"
    signing.create_case_keys(CASE, keys_dir=keys_dir)
    live = build_live(tmp_path, keys)
    live.conn.close()
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        assert reseal.main(["create-keys", "--case", CASE, "--keys-dir", str(keys_dir)]) == 0
        assert reseal.main(["reseal", "--db", str(live.db), "--case", CASE, "--from", "2", "--to", "5",
                            "--keys-dir", str(keys_dir)]) == 0
    assert "Re-seal appended" in out.getvalue() and "covers entries #2 to #5 (4 entries)" in out.getvalue()
    assert rows_of(live.db)[-1][4] == "resealed"


def test_command_line_reports_errors_without_a_traceback(tmp_path, keys):
    live = build_live(tmp_path, keys)
    live.conn.close()
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = reseal.main(["reseal", "--db", str(live.db), "--case", CASE, "--from", "1", "--keys-dir", str(tmp_path / "none")])
    assert rc == 1 and err.getvalue().startswith("ERROR:") and "Traceback" not in err.getvalue()


def test_demo_script_shows_the_record_unchanged_and_catches_a_forgery(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "reseal_demo.py"), "--tamper", "--demo-dir", str(tmp_path / "demo")],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "original entries byte-for-byte unchanged: YES" in out and "old record hash identical: YES" in out
    assert "[4] Re-sealed segments" in out and "PASS" in out
    assert "STEP 5" in out and "RESULT: FAIL" in out


def test_demo_script_refuses_a_non_empty_folder(tmp_path):
    (tmp_path / "x").write_text("occupied")
    proc = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "reseal_demo.py"), "--demo-dir", str(tmp_path)],
                          capture_output=True, text=True, cwd=REPO_ROOT, timeout=60)
    assert proc.returncode == 1 and "refusing to overwrite" in proc.stdout