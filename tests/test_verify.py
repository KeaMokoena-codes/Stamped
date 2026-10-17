"""

"""
import ast
import contextlib
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from seal.custody_log import append_entry  # the APP writes the log; the verifier must agree with it
from verifier import verify

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFY_PY = REPO_ROOT / "verifier" / "verify.py"
SCHEMA_PATH = REPO_ROOT / "schemas" / "schema.sql"
GUARD_TRIGGERS = ("custody_log_no_update", "custody_log_no_delete", "custody_log_no_replace")

try:
    import oqs  # noqa: F401
    HAVE_OQS = True
except Exception:  # ImportError, or liboqs' RuntimeError on a failed native build
    HAVE_OQS = False

needs_oqs = pytest.mark.skipif(not HAVE_OQS, reason="liboqs unavailable: signature tests are skipped, not passed")


# ---------------------------------------------------------------------------
# Building exported case packages
#   <root>/stamped.db   <root>/anchors/   <root>/public/
# ---------------------------------------------------------------------------
_KEY_CACHE = {}


def real_keys(name="case1"):
    """Real hybrid keys for a case, generated once per test run."""
    from seal import signing  # imported lazily: seal.signing needs liboqs
    if name not in _KEY_CACHE:
        keys_dir = Path(tempfile.mkdtemp(prefix="stamped-test-keys-"))
        signing.create_case_keys(name, keys_dir=keys_dir)
        _KEY_CACHE[name] = SimpleNamespace(dir=keys_dir, public=keys_dir / name / "public")
    return _KEY_CACHE[name]


def write_dummy_public_keys(public_dir: Path):
    """Tier A never reaches a signature check, so placeholder key files are enough."""
    public_dir.mkdir(parents=True, exist_ok=True)
    (public_dir / "ed25519_public.bin").write_bytes(b"\x01" * 32)
    (public_dir / "mldsa65_public.bin").write_bytes(b"\x02" * 64)


def fill(conn, n, start=0):
    for i in range(start, start + n):
        # non-ASCII on purpose: exercises the double-encoded details_json rule
        append_entry(conn, "ash", "examiner", f"action_{i}", evidence_id="ev1", details={"i": i, "note": "café"})
    conn.commit()


def new_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30)
    conn.executescript(SCHEMA_PATH.read_text())
    return conn


def make_export(tmp_path, entries=7, plan=None, tail=0, real=False, name="export"):
    """Build an exported case package.

    entries : number of plain entries when there are no anchors (plan is None)
    plan    : e.g. [4, 3] = add 4 entries, anchor, add 3 entries, anchor. Each
              anchoring also logs one 'anchored' entry, exactly as the app does.
    tail    : entries added after the last anchor (not covered by any anchor)
    real    : use real keys (required whenever anchors are made)
    """
    work, usb, root = tmp_path / f"{name}-work", tmp_path / f"{name}-usb", tmp_path / name
    work.mkdir()
    usb.mkdir()
    root.mkdir()
    conn = new_db(work / "stamped.db")
    if plan:
        from seal import anchor  # lazily: needs liboqs
        keys = real_keys()
        for n in plan:
            fill(conn, n, start=conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0])
            anchor.create_anchor(conn, case_id="case1", anchor_dir=usb, keys_dir=keys.dir)
        if tail:
            fill(conn, tail, start=conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0])
    else:
        fill(conn, entries + tail)
    conn.close()

    shutil.copy2(work / "stamped.db", root / "stamped.db")
    # copyfile, NOT copy2: do not carry over the read-only attribute anchors are created with.
    # On Windows a read-only file cannot be deleted or overwritten, and tests below do both.
    shutil.copytree(usb, root / "anchors", copy_function=shutil.copyfile)
    if real:
        shutil.copytree(real_keys().public, root / "public")
    else:
        write_dummy_public_keys(root / "public")
    return SimpleNamespace(root=root, db=root / "stamped.db", anchors=root / "anchors", public=root / "public")


def tamper(db: Path, sql: str, args=()):
    """What an attacker with raw access to the database file can do: remove the
    structural guards, then edit."""
    conn = sqlite3.connect(db)
    for t in GUARD_TRIGGERS:
        conn.execute(f"DROP TRIGGER IF EXISTS {t}")
    conn.execute(sql, args)
    conn.commit()
    conn.close()


def rewrite_suffix_consistently(db: Path, from_entry: int):
    """The perfect forgery: recompute prev_hash/entry_hash for every entry from
    `from_entry` on, so the chain is internally consistent again."""
    conn = sqlite3.connect(db)
    for t in GUARD_TRIGGERS:
        conn.execute(f"DROP TRIGGER IF EXISTS {t}")
    rows = conn.execute(
        "SELECT entry_id, timestamp_utc, actor, role, action, evidence_id, artifact_id, details_json "
        "FROM custody_log WHERE entry_id >= ? ORDER BY entry_id", (from_entry,)).fetchall()
    prev = (conn.execute("SELECT entry_hash FROM custody_log WHERE entry_id = ?", (from_entry - 1,)).fetchone() or ("0" * 64,))[0]
    for entry_id, ts, actor, role, action, ev, art, details in rows:
        fields = {"timestamp_utc": ts, "actor": actor, "role": role, "action": action,
                  "evidence_id": ev, "artifact_id": art, "details_json": details}
        new_hash = verify.compute_entry_hash(fields, prev)
        conn.execute("UPDATE custody_log SET prev_hash = ?, entry_hash = ? WHERE entry_id = ?", (prev, new_hash, entry_id))
        prev = new_hash
    conn.commit()
    conn.close()


def last_entry_id(db: Path) -> int:
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT MAX(entry_id) FROM custody_log").fetchone()[0]
    finally:
        conn.close()


def positions(db: Path) -> dict:
    last = last_entry_id(db)
    return {"first": 1, "middle": (last + 1) // 2, "last": last}


def run(export, *extra, as_json=True):
    """Run verify.main in-process. Returns (exit_code, report_or_None, stdout, stderr)."""
    argv = ["--case-export", str(export.root), *extra]
    if as_json:
        argv.append("--json")
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = verify.main(argv)
    text = out.getvalue()
    report = json.loads(text) if as_json and text.strip() else None
    return rc, report, text, err.getvalue()


def run_cli(args, cwd):
    """Run the verifier exactly as a third party would: a separate process, an
    unrelated working directory, and the repository NOT on the import path."""
    return subprocess.run([sys.executable, str(VERIFY_PY), *args], cwd=cwd, capture_output=True,
                          text=True, env={**os.environ, "PYTHONPATH": ""})


def failure_codes(report):
    return {f["code"] for c in report["checks"].values() for f in c.get("failures", [])}


# ===========================================================================
# TIER A (no liboqs needed)
# ===========================================================================
# ---- the written format, reproduced independently of the app ---------------
def test_entry_hash_matches_the_test_vector_in_the_format_document():
    fields = {"timestamp_utc": "2026-10-05T08:30:00+00:00", "actor": "ash", "role": "examiner",
              "action": "sealed", "evidence_id": "ab" * 32, "artifact_id": None,
              "details_json": verify.canonical({"note": "café", "n": 1})}
    assert fields["details_json"] == '{"n":1,"note":"caf\\u00e9"}'
    assert verify.compute_entry_hash(fields, "0" * 64) == "2b2f3fb66296aede41737bf9d88bffac73de8abdacd9885c7716e909db27ef38"


def test_anchor_payload_hash_matches_the_test_vector_in_the_anchoring_document():
    payload = {"format": "stamped-anchor/1", "case_id": "case1", "seq": 1,
               "anchored_at": "2026-10-11T08:30:00+00:00", "head_entry_id": 5,
               "head_entry_hash": "ab" * 32, "entry_count": 5, "prev_anchor_hash": "0" * 64}
    assert hashlib.sha256(verify.canonical(payload).encode("utf-8")).hexdigest() == \
           "c96231e574ab2c2258afb1297660f6f7a2dad4a9c1153905d21918cdc994b749"


def test_the_verifier_agrees_with_the_application_on_a_real_log(tmp_path):
    ex = make_export(tmp_path, entries=7)
    rc, report, *_ = run(ex, "--allow-no-anchors")
    assert report["checks"]["chain"]["status"] == "PASS" and report["checks"]["chain"]["entries"] == 7


# ---- DoD: tampering is pinpointed at the first, middle and last entry ------
@pytest.mark.parametrize("where", ["first", "middle", "last"])
@pytest.mark.parametrize("kind", ["content", "details", "timestamp", "stored_entry_hash", "stored_prev_hash"])
def test_DOD_edit_is_reported_at_exactly_the_edited_entry(tmp_path, where, kind):
    ex = make_export(tmp_path, entries=7)
    target = positions(ex.db)[where]
    edits = {
        "content": ("UPDATE custody_log SET actor = 'mallory' WHERE entry_id = ?", (target,)),
        "details": ("UPDATE custody_log SET details_json = '{\"i\":999}' WHERE entry_id = ?", (target,)),
        "timestamp": ("UPDATE custody_log SET timestamp_utc = '2001-01-01T00:00:00+00:00' WHERE entry_id = ?", (target,)),
        "stored_entry_hash": ("UPDATE custody_log SET entry_hash = ? WHERE entry_id = ?", ("f" * 64, target)),
        "stored_prev_hash": ("UPDATE custody_log SET prev_hash = ? WHERE entry_id = ?", ("e" * 64, target)),
    }
    tamper(ex.db, *edits[kind])
    rc, report, text, _ = run(ex, "--allow-no-anchors")
    assert rc == 1
    assert report["overall"] == "FAIL"
    assert report["broken_entry_id"] == target      # not target - 1, not target + 1
    assert report["checks"]["chain"]["first_bad_entry"] == target


@pytest.mark.parametrize("where", ["first", "middle", "last"])
def test_DOD_text_report_names_the_broken_entry(tmp_path, where):
    ex = make_export(tmp_path, entries=7)
    target = positions(ex.db)[where]
    tamper(ex.db, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = ?", (target,))
    rc, _, text, _ = run(ex, "--allow-no-anchors", as_json=False)
    assert rc == 1
    assert "RESULT: FAIL" in text
    assert f"The chain first breaks at entry #{target}." in text


def test_when_several_entries_are_altered_the_FIRST_one_is_reported(tmp_path):
    ex = make_export(tmp_path, entries=7)
    tamper(ex.db, "UPDATE custody_log SET actor = 'x' WHERE entry_id = 6")
    tamper(ex.db, "UPDATE custody_log SET actor = 'x' WHERE entry_id = 2")
    tamper(ex.db, "UPDATE custody_log SET actor = 'x' WHERE entry_id = 4")
    assert run(ex, "--allow-no-anchors")[1]["broken_entry_id"] == 2


@pytest.mark.parametrize("where,expected_offset", [("first", 1), ("middle", 1)])
def test_a_deleted_entry_is_reported_at_the_entry_after_the_gap(tmp_path, where, expected_offset):
    ex = make_export(tmp_path, entries=7)
    victim = positions(ex.db)[where]
    tamper(ex.db, "DELETE FROM custody_log WHERE entry_id = ?", (victim,))
    rc, report, *_ = run(ex, "--allow-no-anchors")
    assert rc == 1
    assert report["broken_entry_id"] == victim + expected_offset
    assert report["checks"]["chain"]["reason"] == "prev_hash_mismatch"


def test_ids_with_a_gap_do_not_shift_the_answer(tmp_path):
    """Blame the row's real entry_id, never its position in the list."""
    ex = make_export(tmp_path, entries=8)
    tamper(ex.db, "DELETE FROM custody_log WHERE entry_id = 3")      # ids are now 1,2,4,5,6,7,8
    assert run(ex, "--allow-no-anchors")[1]["broken_entry_id"] == 4
    ex2 = make_export(tmp_path, entries=8, name="export2")
    tamper(ex2.db, "UPDATE custody_log SET entry_id = entry_id + 100 WHERE entry_id >= 5")   # ids 1-4, 105-108
    tamper(ex2.db, "UPDATE custody_log SET actor = 'x' WHERE entry_id = 106")
    assert run(ex2, "--allow-no-anchors")[1]["broken_entry_id"] == 106


def test_LIMITATION_chain_alone_cannot_see_the_newest_entries_being_deleted(tmp_path):
    """Needs anchors to detect. With no anchors the result is explicitly labelled CHAIN ONLY."""
    ex = make_export(tmp_path, entries=7)
    tamper(ex.db, "DELETE FROM custody_log WHERE entry_id IN (6, 7)")
    rc, report, text, _ = run(ex, "--allow-no-anchors", as_json=False)
    assert rc == 0 and "CHAIN ONLY" in text


def test_a_perfectly_rewritten_chain_passes_the_chain_check_on_its_own(tmp_path):
    """This is exactly why anchors exist (Tier B shows them catching it)."""
    ex = make_export(tmp_path, entries=7)
    tamper(ex.db, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = 3")
    rewrite_suffix_consistently(ex.db, 3)
    assert run(ex, "--allow-no-anchors")[1]["checks"]["chain"]["status"] == "PASS"


# ---- DoD: unusable values in the database are FAIL at that entry, not a crash
def test_values_that_cannot_be_hashed_fail_at_that_entry(tmp_path):
    ex = make_export(tmp_path, entries=5)
    tamper(ex.db, "UPDATE custody_log SET actor = x'ff00' WHERE entry_id = 3")    # a BLOB where text belongs
    rc, report, *_ = run(ex, "--allow-no-anchors")
    assert rc == 1 and report["broken_entry_id"] == 3
    assert report["checks"]["chain"]["reason"] == "malformed_entry"


def test_null_fields_fail_instead_of_crashing(tmp_path):
    ex = make_export(tmp_path, entries=5)
    tamper(ex.db, "UPDATE custody_log SET details_json = NULL WHERE entry_id = 2")
    rc, report, *_ = run(ex, "--allow-no-anchors")
    assert rc == 1 and report["broken_entry_id"] == 2


def test_an_empty_log_is_a_failure_not_a_pass(tmp_path):
    ex = make_export(tmp_path, entries=0)
    rc, report, text, _ = run(ex, "--allow-no-anchors", as_json=False)
    assert rc == 1 and "RESULT: FAIL" in text and "log is empty" in text


# ---- DoD: every exception path is an explicit ERROR, never a silent pass ---
def error_run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = verify.main(argv)
    return rc, out.getvalue(), err.getvalue()


def test_missing_case_export_folder_is_error_2(tmp_path):
    rc, out, err = error_run(["--case-export", str(tmp_path / "nope")])
    assert rc == 2 and "PASS" not in out and "not found" in err


def test_missing_database_is_error_2(tmp_path):
    ex = make_export(tmp_path)
    ex.db.unlink()
    rc, out, err = error_run(["--case-export", str(ex.root)])
    assert rc == 2 and "PASS" not in out


def test_two_databases_and_no_stamped_db_is_error_2(tmp_path):
    ex = make_export(tmp_path)
    shutil.move(ex.db, ex.root / "a.db")
    shutil.copy2(ex.root / "a.db", ex.root / "b.db")
    rc, out, err = error_run(["--case-export", str(ex.root)])
    assert rc == 2 and "--db" in err and "PASS" not in out


def test_a_file_that_is_not_a_database_is_error_2(tmp_path):
    ex = make_export(tmp_path)
    ex.db.write_bytes(b"this is not a sqlite database" * 50)
    rc, out, err = error_run(["--case-export", str(ex.root), "--allow-no-anchors"])
    assert rc == 2 and "PASS" not in out


def test_a_database_without_the_custody_table_is_error_2(tmp_path):
    ex = make_export(tmp_path)
    ex.db.unlink()
    conn = sqlite3.connect(ex.db)
    conn.execute("CREATE TABLE unrelated (x)")
    conn.commit()
    conn.close()
    rc, out, err = error_run(["--case-export", str(ex.root), "--allow-no-anchors"])
    assert rc == 2 and "PASS" not in out


def test_invalid_utf8_text_in_the_database_is_not_a_pass(tmp_path):
    ex = make_export(tmp_path)
    tamper(ex.db, "UPDATE custody_log SET actor = CAST(x'80ff' AS TEXT) WHERE entry_id = 2")
    rc, out, err = error_run(["--case-export", str(ex.root), "--allow-no-anchors"])
    assert rc in (1, 2) and "RESULT: PASS" not in out


@pytest.mark.parametrize("breakage", ["no_folder", "no_ed25519", "no_mldsa", "empty_ed25519"])
def test_missing_or_empty_public_keys_are_error_2(tmp_path, breakage):
    ex = make_export(tmp_path)
    if breakage == "no_folder":
        shutil.rmtree(ex.public)
    elif breakage == "no_ed25519":
        (ex.public / "ed25519_public.bin").unlink()
    elif breakage == "no_mldsa":
        (ex.public / "mldsa65_public.bin").unlink()
    else:
        (ex.public / "ed25519_public.bin").write_bytes(b"")
    rc, out, err = error_run(["--case-export", str(ex.root), "--allow-no-anchors"])
    assert rc == 2 and "PASS" not in out


def test_missing_anchor_folder_is_error_2_even_with_allow_no_anchors(tmp_path):
    ex = make_export(tmp_path)
    shutil.rmtree(ex.anchors)
    rc, out, err = error_run(["--case-export", str(ex.root), "--allow-no-anchors"])
    assert rc == 2 and "PASS" not in out


def test_unknown_arguments_exit_2_without_a_result():
    rc = None
    try:
        verify.main(["--no-such-flag"])
    except SystemExit as exc:
        rc = exc.code
    assert rc == 2


def test_an_unexpected_crash_while_reading_is_error_2_never_a_pass(tmp_path):
    ex = make_export(tmp_path)
    with mock.patch.object(verify, "read_custody_log", side_effect=RuntimeError("boom")):
        rc, out, err = error_run(["--case-export", str(ex.root), "--allow-no-anchors"])
    assert rc == 2 and "PASS" not in out and "boom" in err


def test_a_crash_inside_the_chain_check_is_error_not_pass(tmp_path):
    ex = make_export(tmp_path)
    with mock.patch.object(verify, "check_chain", side_effect=RuntimeError("boom")):
        rc, report, *_ = run(ex, "--allow-no-anchors")
    assert rc == 2 and report["overall"] == "ERROR"


def test_a_crash_inside_the_anchor_check_is_error_not_pass(tmp_path):
    ex = make_export(tmp_path)
    with mock.patch.object(verify, "check_anchors", side_effect=RuntimeError("boom")):
        rc, report, *_ = run(ex, "--allow-no-anchors")
    assert rc == 2 and report["overall"] == "ERROR"


def test_a_crash_while_printing_is_error_2(tmp_path):
    ex = make_export(tmp_path)
    with mock.patch.object(verify, "render_report", side_effect=RuntimeError("boom")):
        rc, out, err = error_run(["--case-export", str(ex.root), "--allow-no-anchors"])
    assert rc == 2 and "PASS" not in out


@pytest.mark.parametrize("statuses,limited,expected", [
    (("PASS", "PASS", "PASS"), False, "PASS"),
    (("FAIL", "PASS", "PASS"), False, "FAIL"),
    (("PASS", "FAIL", "PASS"), False, "FAIL"),
    (("PASS", "PASS", "FAIL"), False, "FAIL"),
    (("FAIL", "ERROR", "PASS"), False, "FAIL"),            # a definite failure outranks "could not check"
    (("PASS", "ERROR", "PASS"), False, "ERROR"),
    (("ERROR", "PASS", "PASS"), False, "ERROR"),
    (("PASS", "SKIPPED", "SKIPPED"), False, "ERROR"),      # skipping is only allowed when explicitly requested
    (("PASS", "SKIPPED", "SKIPPED"), True, "PASS"),
    (("FAIL", "SKIPPED", "SKIPPED"), True, "FAIL"),
    (("ERROR", "SKIPPED", "SKIPPED"), True, "ERROR"),
    (("PASS", "PASS", "something-unexpected"), False, "ERROR"),
    (("PASS", "PASS", None), False, "ERROR"),
])
def test_decide_is_PASS_only_when_every_check_explicitly_passes(statuses, limited, expected):
    assert verify.decide(*statuses, limited) == expected


# ---- anchors that are not valid: FAIL, never a crash (no liboqs needed) -----
@pytest.mark.parametrize("content", [
    "this is not json",
    "",
    "[]",
    "null",
    '"a string"',
    "{}",
    '{"format": "stamped-anchor/1", "payload": [], "signatures": {}, "anchor_hash": "x"}',
    '{"format": "stamped-anchor/1", "payload": {"x": NaN}, "signatures": {}, "anchor_hash": "x"}',
    "[" * 100000,                                          # nesting deep enough to exhaust the parser
], ids=[
    "not_json", "empty", "empty_list", "null", "json_string", "empty_object",
    "payload_is_a_list", "nan_in_payload",
    "deeply_nested_brackets",   # explicit id: pytest would otherwise use the 100000-char value as the test name,
])                              # and Windows rejects environment variables over 32767 characters (PYTEST_CURRENT_TEST)
def test_a_malformed_anchor_file_is_a_failure_not_a_crash(tmp_path, content):
    ex = make_export(tmp_path)
    (ex.anchors / "anchor_000001.json").write_text(content)
    rc, report, *_ = run(ex)
    assert rc == 1 and "anchor_unreadable" in failure_codes(report)


def test_a_directory_named_like_an_anchor_is_a_failure(tmp_path):
    ex = make_export(tmp_path)
    (ex.anchors / "anchor_000001.json").mkdir()
    rc, report, *_ = run(ex)
    assert rc == 1 and "anchor_unreadable" in failure_codes(report)


def test_no_anchors_is_a_failure_by_default(tmp_path):
    ex = make_export(tmp_path)
    rc, report, *_ = run(ex)
    assert rc == 1 and "no_anchors" in failure_codes(report)


def test_lookalike_unicode_digits_are_not_treated_as_an_anchor(tmp_path):
    ex = make_export(tmp_path)
    (ex.anchors / "anchor_\u0660\u0660\u0660\u0660\u0660\u0661.json").write_text("{}")
    rc, report, *_ = run(ex)
    assert rc == 1 and "no_anchors" in failure_codes(report)


def test_odd_file_names_never_crash_the_report(tmp_path):
    ex = make_export(tmp_path)
    (ex.anchors / "r\u00e9sum\u00e9-\u4e2d\u6587.txt").write_text("x")
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = verify.main(["--case-export", str(ex.root), "--allow-no-anchors"])
    text = out.getvalue()
    assert rc == 0 and text.isascii() and "Ignored unexpected item" in text


# ---- liboqs problems must be ERROR, never a pass and never a flood of fake tamper alarms
class _FakeSignature:
    """A stand-in used only to simulate a BROKEN liboqs; it is never used to produce a result."""
    answer = True

    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def generate_keypair(self): return b"pub"
    def sign(self, m): return b"sig"
    def verify(self, m, s, p): return self.answer


def test_a_liboqs_that_accepts_everything_is_refused():
    with mock.patch.dict(sys.modules, {"oqs": SimpleNamespace(Signature=_FakeSignature)}):
        with pytest.raises(verify.VerifierError, match="wrong answers"):
            verify.load_oqs()


def test_a_liboqs_that_rejects_everything_is_refused():
    class Rejecting(_FakeSignature):
        answer = False
    with mock.patch.dict(sys.modules, {"oqs": SimpleNamespace(Signature=Rejecting)}):
        with pytest.raises(verify.VerifierError, match="wrong answers"):
            verify.load_oqs()


def test_a_liboqs_without_ml_dsa_65_is_refused():
    class Unsupported(_FakeSignature):
        def __init__(self, *a, **k): raise RuntimeError("algorithm not enabled")
    with mock.patch.dict(sys.modules, {"oqs": SimpleNamespace(Signature=Unsupported)}):
        with pytest.raises(verify.VerifierError, match="did not work"):
            verify.load_oqs()


def test_a_missing_liboqs_is_refused():
    with mock.patch.dict(sys.modules, {"oqs": None}):          # makes `import oqs` raise ImportError
        with pytest.raises(verify.VerifierError, match="not available"):
            verify.load_oqs()


def test_a_liboqs_that_aborts_its_own_import_is_refused():
    """liboqs-python can try to build itself on first import and exit if that fails."""
    class AbortingFinder:
        def find_spec(self, name, path=None, target=None):
            if name == "oqs":
                raise SystemExit("native build failed")
            return None

    finder = AbortingFinder()
    with mock.patch.dict(sys.modules):
        sys.modules.pop("oqs", None)
        sys.meta_path.insert(0, finder)
        try:
            with pytest.raises(verify.VerifierError, match="not available"):
                verify.load_oqs()
        finally:
            sys.meta_path.remove(finder)


# ---- DoD: independence ------------------------------------------------------
def _imported_modules(path):
    tree = ast.parse(Path(path).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    return imported


def test_DOD_verifier_imports_only_crypto_libraries_and_the_standard_library():
    imported = _imported_modules(VERIFY_PY)
    allowed = {"argparse", "base64", "hashlib", "json", "re", "sqlite3", "sys", "pathlib",   # stdlib
               "cryptography", "oqs"}                                                          # crypto
    assert imported <= allowed, f"unexpected imports: {imported - allowed}"
    forbidden = {"seal", "app", "ingest", "detect", "access", "report", "capture", "schemas", "verifier",
                 "streamlit", "pandas", "flask"}
    assert imported & forbidden == set()


def test_DOD_verifier_runs_as_a_standalone_script_from_an_unrelated_directory(tmp_path):
    """Separate process, no PYTHONPATH, working directory far from the repository."""
    ex = make_export(tmp_path)
    elsewhere = tmp_path / "somewhere-else"
    elsewhere.mkdir()
    r = run_cli(["--case-export", str(ex.root), "--allow-no-anchors"], elsewhere)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "RESULT: PASS" in r.stdout and "CHAIN ONLY" in r.stdout


def test_cli_tamper_demo_without_anchors(tmp_path):
    ex = make_export(tmp_path)
    elsewhere = tmp_path / "somewhere-else"
    elsewhere.mkdir()
    tamper(ex.db, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = 4")
    r = run_cli(["--case-export", str(ex.root), "--allow-no-anchors"], elsewhere)
    assert r.returncode == 1
    assert "RESULT: FAIL" in r.stdout and "entry #4" in r.stdout


@pytest.mark.parametrize("flags", [[], ["-OO"]])
def test_cli_does_not_depend_on_docstrings_being_present(flags):
    r = subprocess.run([sys.executable, *flags, str(VERIFY_PY), "--help"], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": ""})
    assert r.returncode == 0, r.stderr
    assert "--case-export" in r.stdout


def test_the_verifier_never_writes_anything(tmp_path):
    ex = make_export(tmp_path)
    before_db = ex.db.read_bytes()
    before_files = sorted(p.relative_to(ex.root).as_posix() for p in ex.root.rglob("*"))
    run(ex, "--allow-no-anchors")        # a passing run ...
    assert run(ex)[0] == 1               # ... and a failing run (no anchors)
    assert ex.db.read_bytes() == before_db
    assert sorted(p.relative_to(ex.root).as_posix() for p in ex.root.rglob("*")) == before_files


def test_the_database_connection_it_uses_is_read_only(tmp_path):
    ex = make_export(tmp_path)
    with pytest.raises(sqlite3.OperationalError):
        conn = sqlite3.connect(ex.db.resolve().as_uri() + "?mode=ro", uri=True)
        conn.execute("DELETE FROM custody_log")


def test_json_and_text_output_agree(tmp_path):
    ex = make_export(tmp_path)
    tamper(ex.db, "UPDATE custody_log SET actor = 'x' WHERE entry_id = 3")
    _, report, *_ = run(ex, "--allow-no-anchors")
    _, _, text, _ = run(ex, "--allow-no-anchors", as_json=False)
    assert report["overall"] == "FAIL" and "RESULT: FAIL" in text and "entry #3" in text


# ===========================================================================
# TIER B (real Ed25519 + real ML-DSA-65)
# ===========================================================================
PLAN = [4, 3]       # anchor 1 covers entries 1-4 (then #5 'anchored'), anchor 2 covers 1-8 (then #9 'anchored')


def anchored_export(tmp_path, **kw):
    return make_export(tmp_path, plan=kw.pop("plan", PLAN), real=True, **kw)


def load_anchor(ex, n):
    return json.loads((ex.anchors / f"anchor_{n:06d}.json").read_text())


def save_anchor(ex, n, record):
    p = ex.anchors / f"anchor_{n:06d}.json"
    os.chmod(p, 0o644)
    p.write_text(json.dumps(record, indent=2, sort_keys=True))


def write_signed_anchor(ex, file_no, **overrides):
    """An insider WITH the signing keys writes a validly signed anchor carrying chosen
    values. Used to prove the verifier checks consistency, not just signatures."""
    import base64
    from seal import signing
    prev = ex.anchors / f"anchor_{file_no - 1:06d}.json"
    prev_hash = json.loads(prev.read_text())["anchor_hash"] if prev.exists() else "0" * 64
    conn = sqlite3.connect(ex.db)
    head_hash = conn.execute("SELECT entry_hash FROM custody_log WHERE entry_id = 8").fetchone()[0]
    conn.close()
    payload = {"format": "stamped-anchor/1", "case_id": "case1", "seq": file_no,
               "anchored_at": "2099-01-01T00:00:00+00:00", "head_entry_id": 8, "head_entry_hash": head_hash,
               "entry_count": 8, "prev_anchor_hash": prev_hash}
    payload.update(overrides)
    msg = verify.canonical(payload).encode("utf-8")
    ed_priv, pq_priv = signing.load_private_keys("case1", real_keys().dir)
    sig_c, sig_pq = signing.sign_hybrid(msg, ed_priv, pq_priv)
    record = {"format": "stamped-anchor/1", "payload": payload, "anchor_hash": hashlib.sha256(msg).hexdigest(),
              "signatures": {"ed25519": base64.b64encode(sig_c).decode(), "ml_dsa_65": base64.b64encode(sig_pq).decode()},
              "meta": {"location_assurance": "separate_device"}}
    (ex.anchors / f"anchor_{file_no:06d}.json").write_text(json.dumps(record, indent=2, sort_keys=True))


@needs_oqs
def test_DOD_known_good_export_passes(tmp_path):
    ex = anchored_export(tmp_path)
    rc, report, text, err = run(ex)
    assert rc == 0, text + err
    assert report["overall"] == "PASS"
    assert [c["status"] for c in report["checks"].values()] == ["PASS", "PASS", "PASS"]
    assert report["checks"]["signatures"]["valid"] == 2 == report["checks"]["signatures"]["checked"]
    assert report["case_id"] == "case1"
    _, _, text, _ = run(ex, as_json=False)
    assert "RESULT: PASS" in text and "[2] Hybrid signatures on anchors" in text


@needs_oqs
def test_known_good_export_prints_both_key_fingerprints(tmp_path):
    ex = anchored_export(tmp_path)
    _, report, *_ = run(ex)
    assert report["keys"]["ed25519_sha256"] == hashlib.sha256((ex.public / "ed25519_public.bin").read_bytes()).hexdigest()
    assert report["keys"]["mldsa65_sha256"] == hashlib.sha256((ex.public / "mldsa65_public.bin").read_bytes()).hexdigest()


@needs_oqs
def test_entries_after_the_newest_anchor_are_reported_as_unprotected(tmp_path):
    ex = anchored_export(tmp_path, tail=2)
    rc, report, *_ = run(ex)
    assert rc == 0 and report["unanchored_real_entries"] == 2
    _, _, text, _ = run(ex, as_json=False)
    assert "not externally protected yet" in text


@needs_oqs
def test_LIMITATION_tampering_after_the_newest_anchor_is_not_detected(tmp_path):
    """Entries added after the newest anchor are covered only by the chain (and, here, perfectly rewritten)."""
    ex = anchored_export(tmp_path, tail=2)
    last = last_entry_id(ex.db)
    tamper(ex.db, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = ?", (last,))
    rewrite_suffix_consistently(ex.db, last)
    rc, report, *_ = run(ex)
    assert rc == 0 and report["unanchored_real_entries"] == 2


@needs_oqs
@pytest.mark.parametrize("where", ["first", "middle", "last"])
def test_DOD_tampered_export_fails_at_the_correct_entry_even_with_anchors(tmp_path, where):
    ex = anchored_export(tmp_path)
    target = positions(ex.db)[where]
    tamper(ex.db, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = ?", (target,))
    rc, report, text, _ = run(ex)
    assert rc == 1
    assert report["overall"] == "FAIL" and report["broken_entry_id"] == target
    assert report["checks"]["chain"]["status"] == "FAIL"
    assert report["checks"]["signatures"]["status"] == "PASS"   # the anchors themselves are untouched


@needs_oqs
@pytest.mark.parametrize("rewrite_from", [1, 3, 6, 8])
def test_perfect_rewrite_passes_the_chain_but_the_anchors_catch_it_and_narrow_it_down(tmp_path, rewrite_from):
    ex = anchored_export(tmp_path)
    tamper(ex.db, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = ?", (rewrite_from,))
    rewrite_suffix_consistently(ex.db, rewrite_from)
    rc, report, *_ = run(ex)
    assert rc == 1 and report["overall"] == "FAIL"
    assert report["checks"]["chain"]["status"] == "PASS"            # the forgery is internally consistent
    assert "anchored_hash_mismatch" in failure_codes(report)
    lo, hi = report["suspect_range"]
    assert lo <= rewrite_from <= hi                                    # the real culprit is inside the reported range
    _, _, text, _ = run(ex, as_json=False)
    assert f"between entry #{lo} and entry #{hi}" in text


@needs_oqs
def test_range_is_narrowed_by_the_newest_anchor_that_still_matches(tmp_path):
    ex = anchored_export(tmp_path)
    tamper(ex.db, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = 7")
    rewrite_suffix_consistently(ex.db, 7)
    _, report, *_ = run(ex)
    assert report["suspect_range"] == [5, 8]          # anchor 1 (entry 4) still matches, so the edit is after it


@needs_oqs
@pytest.mark.parametrize("count", [1, 2, 5])
def test_deleting_the_newest_entries_is_caught_by_the_anchors(tmp_path, count):
    ex = anchored_export(tmp_path)
    last = last_entry_id(ex.db)
    tamper(ex.db, "DELETE FROM custody_log WHERE entry_id > ?", (last - count,))
    rc, report, *_ = run(ex)
    assert report["checks"]["chain"]["status"] == "PASS"            # a shorter chain is still consistent
    # deleting only the final bookkeeping entry (#9) leaves anchor 2 (entry 8) intact: that is the documented limit
    if count == 1:
        assert rc == 0
    else:
        assert rc == 1 and "anchored_entry_missing" in failure_codes(report)


@needs_oqs
def test_deleting_a_middle_entry_is_caught(tmp_path):
    ex = anchored_export(tmp_path)
    tamper(ex.db, "DELETE FROM custody_log WHERE entry_id = 3")
    rc, report, *_ = run(ex)
    assert rc == 1 and report["broken_entry_id"] == 4


@needs_oqs
def test_a_validly_signed_anchor_with_the_wrong_entry_count_is_caught(tmp_path):
    ex = anchored_export(tmp_path)
    write_signed_anchor(ex, 3, entry_count=7)           # entry #8 exists, but 8 entries precede it, not 7
    rc, report, *_ = run(ex)
    assert rc == 1 and "anchored_entry_count_mismatch" in failure_codes(report)
    assert report["checks"]["signatures"]["status"] == "PASS"      # the signatures are fine; the CONTENT is wrong


@needs_oqs
def test_a_validly_signed_anchor_that_goes_backwards_is_caught(tmp_path):
    ex = anchored_export(tmp_path)
    write_signed_anchor(ex, 3, head_entry_id=4, entry_count=4,
                        head_entry_hash=json.loads((ex.anchors / "anchor_000001.json").read_text())["payload"]["head_entry_hash"])
    rc, report, *_ = run(ex)
    assert rc == 1 and "anchor_regression" in failure_codes(report)


@needs_oqs
def test_a_validly_signed_anchor_that_does_not_link_to_its_predecessor_is_caught(tmp_path):
    ex = anchored_export(tmp_path)
    write_signed_anchor(ex, 3, prev_anchor_hash="12" * 32)
    rc, report, *_ = run(ex)
    assert rc == 1 and "anchor_link_broken" in failure_codes(report)


@needs_oqs
def test_a_validly_signed_anchor_naming_a_different_case_is_caught(tmp_path):
    ex = anchored_export(tmp_path)
    write_signed_anchor(ex, 3, case_id="some-other-case")
    rc, report, *_ = run(ex)
    assert rc == 1 and "anchor_case_mismatch" in failure_codes(report)


@needs_oqs
def test_a_signed_sequence_number_that_disagrees_with_the_file_number_is_caught_on_its_own(tmp_path):
    ex = anchored_export(tmp_path)
    write_signed_anchor(ex, 3, seq=5)                   # file anchor_000003.json, but it signs "I am anchor 5"
    rc, report, *_ = run(ex)
    assert rc == 1 and failure_codes(report) == {"anchor_seq_mismatch"}


@needs_oqs
def test_a_file_number_that_disagrees_with_the_signed_sequence_is_caught(tmp_path):
    ex = anchored_export(tmp_path)
    os.chmod(ex.anchors / "anchor_000002.json", 0o644)
    (ex.anchors / "anchor_000002.json").rename(ex.anchors / "anchor_000003.json")
    rc, report, *_ = run(ex)
    assert rc == 1 and {"anchor_seq_mismatch", "anchor_sequence_gap"} & failure_codes(report)


@needs_oqs
def test_one_bad_signature_fails_and_names_which(tmp_path):
    import base64
    for which, label in (("ed25519", "Ed25519"), ("ml_dsa_65", "ML-DSA-65")):
        ex = anchored_export(tmp_path, name=f"export-{which}")
        record = load_anchor(ex, 2)
        raw = bytearray(base64.b64decode(record["signatures"][which]))
        raw[0] ^= 0xFF
        record["signatures"][which] = base64.b64encode(bytes(raw)).decode()
        save_anchor(ex, 2, record)
        rc, report, text, _ = run(ex)
        assert rc == 1, "BOTH signatures are required; one valid signature must not be enough"
        msgs = [f["message"] for f in report["checks"]["signatures"]["failures"] if f["code"] == "anchor_signature_invalid"]
        assert len(msgs) == 1
        named = msgs[0].split("failed for ")[1].split(". Both")[0]
        assert named == label                       # names the broken half, and only that half


@needs_oqs
def test_editing_the_anchored_hash_in_an_anchor_file_is_caught(tmp_path):
    ex = anchored_export(tmp_path)
    record = load_anchor(ex, 2)
    record["payload"]["head_entry_hash"] = "ab" * 32
    save_anchor(ex, 2, record)
    rc, report, *_ = run(ex)
    assert rc == 1
    assert {"anchor_hash_mismatch", "anchor_signature_invalid"} <= failure_codes(report)


@needs_oqs
def test_an_anchor_re_signed_with_someone_elses_keys_is_rejected(tmp_path):
    ex = anchored_export(tmp_path)
    other = real_keys("other-case")
    shutil.rmtree(ex.public)
    shutil.copytree(other.public, ex.public)               # a swapped-in key set
    rc, report, *_ = run(ex)
    assert rc == 1 and "anchor_signature_invalid" in failure_codes(report)
    assert "keys_case_mismatch" in failure_codes(report)   # and the manifest says these keys are for another case


@needs_oqs
def test_removing_a_middle_or_oldest_anchor_is_caught(tmp_path):
    ex = anchored_export(tmp_path, plan=[3, 2, 2], name="export-mid")
    os.chmod(ex.anchors / "anchor_000002.json", 0o644)
    (ex.anchors / "anchor_000002.json").unlink()
    rc, report, *_ = run(ex)
    assert rc == 1 and "anchor_sequence_gap" in failure_codes(report)

    ex2 = anchored_export(tmp_path, plan=[3, 2], name="export-old")
    os.chmod(ex2.anchors / "anchor_000001.json", 0o644)
    (ex2.anchors / "anchor_000001.json").unlink()
    rc, report, *_ = run(ex2)
    assert rc == 1 and "anchor_sequence_gap" in failure_codes(report)


@needs_oqs
def test_LIMITATION_deleting_the_newest_anchor_file_is_not_detectable(tmp_path):
    ex = anchored_export(tmp_path, plan=[4, 3])
    os.chmod(ex.anchors / "anchor_000002.json", 0o644)
    (ex.anchors / "anchor_000002.json").unlink()
    rc, report, *_ = run(ex)
    assert rc == 0 and report["latest_anchor"]["seq"] == 1      # the log still matches the older anchor


@needs_oqs
def test_anchors_can_come_from_a_separately_held_copy(tmp_path):
    ex = anchored_export(tmp_path)
    usb = tmp_path / "usb-copy"
    shutil.copytree(ex.anchors, usb)
    shutil.rmtree(ex.anchors)                                   # not in the package at all
    rc, report, text, _ = run(ex, "--anchors", str(usb), as_json=False)
    assert rc == 0 and "read from inside the case package" not in text


@needs_oqs
def test_anchors_inside_the_package_carry_a_provenance_note(tmp_path):
    ex = anchored_export(tmp_path)
    _, _, text, _ = run(ex, as_json=False)
    assert "read from inside the case package" in text


@needs_oqs
def test_liboqs_missing_is_error_2_for_an_otherwise_good_export(tmp_path):
    ex = anchored_export(tmp_path)
    with mock.patch.object(verify, "load_oqs", side_effect=verify.VerifierError("no liboqs")):
        rc, report, text, _ = run(ex)
    assert rc == 2 and report["overall"] == "ERROR" and "RESULT: PASS" not in text


@needs_oqs
def test_a_definite_chain_failure_is_still_reported_as_FAIL_when_liboqs_is_missing(tmp_path):
    ex = anchored_export(tmp_path)
    tamper(ex.db, "UPDATE custody_log SET actor = 'x' WHERE entry_id = 2")
    with mock.patch.object(verify, "load_oqs", side_effect=verify.VerifierError("no liboqs")):
        rc, report, *_ = run(ex)
    assert rc == 1 and report["broken_entry_id"] == 2


@needs_oqs
def test_the_checker_agrees_with_anchor_check_on_good_and_tampered_exports(tmp_path):
    """Two independent implementations should reach the same verdict. A disagreement means one has a bug."""
    from verifier import anchor_check
    scenarios = {
        "good": lambda ex: None,
        "edit_first": lambda ex: tamper(ex.db, "UPDATE custody_log SET actor = 'x' WHERE entry_id = 1"),
        "edit_last": lambda ex: tamper(ex.db, "UPDATE custody_log SET actor = 'x' WHERE entry_id = 9"),
        "rewrite": lambda ex: (tamper(ex.db, "UPDATE custody_log SET actor = 'x' WHERE entry_id = 3"),
                               rewrite_suffix_consistently(ex.db, 3)),
        "truncate": lambda ex: tamper(ex.db, "DELETE FROM custody_log WHERE entry_id > 6"),
        "delete_middle": lambda ex: tamper(ex.db, "DELETE FROM custody_log WHERE entry_id = 2"),
    }
    for name, mutate in scenarios.items():
        ex = anchored_export(tmp_path, name=f"agree-{name}")
        mutate(ex)
        mine = run(ex)[1]["overall"] == "PASS"
        theirs = anchor_check.check_anchors(ex.db, ex.anchors, ex.public)["ok"]
        assert mine == theirs, f"verify.py and anchor_check.py disagree on '{name}'"


@needs_oqs
def test_cli_end_to_end_good_then_tampered_demo(tmp_path):
    """The live demo: pass, tamper one entry, fail naming that entry."""
    ex = anchored_export(tmp_path)
    elsewhere = tmp_path / "judge-laptop"
    elsewhere.mkdir()

    good = run_cli(["--case-export", str(ex.root)], elsewhere)
    assert good.returncode == 0, good.stdout + good.stderr
    assert "RESULT: PASS" in good.stdout

    tamper(ex.db, "UPDATE custody_log SET actor = 'mallory' WHERE entry_id = 5")
    bad = run_cli(["--case-export", str(ex.root)], elsewhere)
    assert bad.returncode == 1
    assert "RESULT: FAIL" in bad.stdout and "The chain first breaks at entry #5." in bad.stdout