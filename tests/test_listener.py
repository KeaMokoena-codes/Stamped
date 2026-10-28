"""Tests for capture/listener.py (Issue: webhook listener).

The listener is exercised through Flask's test client against a real SQLite
database built from schemas/schema.sql and the real seal_evidence(). Nothing is
mocked except where a test needs a sealing failure that cannot be produced
naturally.
"""
import ast
import base64
import contextlib
import dataclasses
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from capture import listener
from capture.auth import signed_headers
from capture.listener import Settings, create_app
from seal.custody_log import recompute_and_verify_chain
from seal.intake import IntakeError

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "schema.sql"
SAMPLE_DIR = REPO_ROOT / "data" / "sample"
FIXTURE = SAMPLE_DIR / "bundle_example.json"


class Env:
    """A listener wired to a throwaway database, sealed folder and staging root."""

    def __init__(self, tmp_path: Path, **overrides):
        self.tmp = tmp_path
        self.db_path = tmp_path / "stamped.db"
        self.sealed = tmp_path / "sealed"
        self.staging = tmp_path / "staging"
        self.staging.mkdir()
        # The path entry in the fixture is relative to the staging root.
        (self.staging / "cloudtrail_sample.json").write_bytes((SAMPLE_DIR / "cloudtrail_sample.json").read_bytes())
        with self.conn() as conn:
            conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        base = Settings(db_path=self.db_path, sealed_dir=self.sealed, staging_root=self.staging)
        self.settings = dataclasses.replace(base, **overrides)
        self.client = create_app(self.settings).test_client()

    def post(self, payload, content_type="application/json"):
        data = payload if isinstance(payload, (bytes, str)) else json.dumps(payload)
        return self.client.post("/alert", data=data, content_type=content_type)

    @contextlib.contextmanager
    def conn(self):
        # Always closed: Windows cannot delete a database file that is still open.
        connection = sqlite3.connect(self.db_path)
        try:
            yield connection
        finally:
            connection.close()

    def count(self, table):
        with self.conn() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def assert_nothing_sealed(self):
        assert self.count("evidence") == 0
        assert self.count("custody_log") == 0
        assert not self.sealed.exists() or not any(self.sealed.iterdir())


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def make_bundle():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def inline_file(name="x.log", data=b"Oct 12 10:14:00 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2\n", **extra):
    entry = {"name": name, "kind": "auth_log", "content_b64": base64.b64encode(data).decode("ascii")}
    entry.update(extra)
    return entry


def bundle_with(*files):
    bundle = make_bundle()
    bundle["files"] = list(files)
    return bundle


# ---------------------------------------------------------------------------
# The happy path: the Definition of Done test
# ---------------------------------------------------------------------------
def test_valid_payload_seals_every_file_and_creates_custody_entries(env):
    response = env.post(make_bundle())

    assert response.status_code == 201
    body = response.get_json()
    assert body["status"] == "sealed" and body["bundle_id"] == "bundle-2026-10-12-0001"
    assert [f["status"] for f in body["files"]] == ["sealed", "sealed"]

    cloudtrail = (SAMPLE_DIR / "cloudtrail_sample.json").read_bytes()
    assert body["files"][0]["evidence_id"] == hashlib.sha256(cloudtrail).hexdigest()

    with env.conn() as conn:
        evidence = conn.execute(
            "SELECT evidence_id, sealed_path, source, collector, captured_at, original_name, metadata_json "
            "FROM evidence ORDER BY sealed_at, evidence_id").fetchall()
        custody = conn.execute("SELECT actor, role, action, evidence_id FROM custody_log ORDER BY entry_id").fetchall()
        assert recompute_and_verify_chain(conn) == (True, None)

    assert len(evidence) == 2
    assert [c[2] for c in custody] == ["sealed", "sealed"]
    assert {c[0] for c in custody} == {listener.ACTOR}
    assert {c[1] for c in custody} == {listener.ROLE}
    assert {c[3] for c in custody} == {e[0] for e in evidence}

    by_name = {e[5]: e for e in evidence}
    assert set(by_name) == {"cloudtrail_sample.json", "auth.log"}
    for evidence_id, sealed_path, source, collector, captured_at, _name, metadata_json in evidence:
        assert Path(sealed_path).read_bytes() and hashlib.sha256(Path(sealed_path).read_bytes()).hexdigest() == evidence_id
        assert (source, collector) == ("demo-alert-source", "capture-listener@lab-01")
        assert captured_at == "2026-10-12T10:26:12+00:00"
        metadata = json.loads(metadata_json)
        assert metadata["bundle_id"] == "bundle-2026-10-12-0001"
        assert metadata["alert_type"] == "failed_console_login"
        assert metadata["alert_id"] == "alert-0001"
    assert json.loads(by_name["auth.log"][6])["base_year"] == 2026
    assert json.loads(by_name["auth.log"][6])["kind"] == "auth_log"


def test_posting_the_same_bundle_again_is_a_logged_re_intake(env):
    assert env.post(make_bundle()).status_code == 201
    second = env.post(make_bundle())

    assert second.status_code == 201
    assert [f["status"] for f in second.get_json()["files"]] == ["re_intake", "re_intake"]
    assert env.count("evidence") == 2          # no duplicate evidence rows
    assert env.count("custody_log") == 4       # but every attempt is on the record
    with env.conn() as conn:
        assert recompute_and_verify_chain(conn) == (True, None)


def test_z_suffix_timestamps_are_stored_in_plus_zero_form(env):
    bundle = bundle_with(inline_file())
    bundle["captured_at"] = "2026-10-12T10:26:12Z"
    assert env.post(bundle).status_code == 201
    with env.conn() as conn:
        assert conn.execute("SELECT captured_at FROM evidence").fetchone()[0] == "2026-10-12T10:26:12+00:00"


def test_empty_file_is_sealed_not_crashed(env):
    assert env.post(bundle_with(inline_file(data=b""))).status_code == 201


def test_path_entry_inside_a_subfolder_of_the_staging_root_works(env):
    (env.staging / "sub").mkdir()
    (env.staging / "sub" / "inner.log").write_bytes(b"Oct 12 10:14:00 h sshd[1]: x\n")
    entry = {"name": "inner.log", "kind": "auth_log", "path": "sub/inner.log"}
    assert env.post(bundle_with(entry)).status_code == 201


# ---------------------------------------------------------------------------
# Malformed transport and JSON
# ---------------------------------------------------------------------------
def test_wrong_content_type_is_415(env):
    response = env.post(json.dumps(make_bundle()), content_type="text/plain")
    assert response.status_code == 415
    assert response.get_json()["error"] == "unsupported_media_type"
    env.assert_nothing_sealed()


@pytest.mark.parametrize("raw", [
    b"", b"not json", b"{", b'{"a": NaN}', b'{"a": Infinity}',
    b'{"a": 1, "a": 2}', b"\xff\xfe\x00", b"[]", b'"a string"', b"null", b"123",
])
def test_unparseable_or_non_object_bodies_are_400_not_a_crash(env, raw):
    response = env.post(raw)
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_bundle"
    env.assert_nothing_sealed()


def test_unknown_route_and_wrong_method_return_json(env):
    assert env.client.get("/alert").status_code == 405
    assert env.client.get("/alert").get_json()["error"] == "method_not_allowed"
    assert env.client.get("/nope").status_code == 404
    assert env.client.get("/nope").get_json()["error"] == "not_found"


# ---------------------------------------------------------------------------
# Schema violations: every one is a 400 and seals nothing
# ---------------------------------------------------------------------------
def _set(path, value):
    def mutate(bundle):
        target = bundle
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return mutate


def _drop(path):
    def mutate(bundle):
        target = bundle
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]
    return mutate


INVALID = {
    **{f"missing_{k}": _drop([k]) for k in listener.TOP_REQUIRED},
    "unknown_top_field": _set(["surprise"], 1),
    "wrong_format_version": _set(["format_version"], "stamped-bundle/2"),
    "format_version_not_string": _set(["format_version"], 1),
    "naive_timestamp": _set(["captured_at"], "2026-10-12T10:26:12"),
    "non_utc_offset": _set(["captured_at"], "2026-10-12T10:26:12+02:00"),
    "timestamp_not_iso": _set(["alert_timestamp"], "yesterday"),
    "timestamp_is_number": _set(["alert_timestamp"], 1760264772),
    "bundle_id_is_int": _set(["bundle_id"], 7),
    "bundle_id_empty": _set(["bundle_id"], "   "),
    "collector_is_list": _set(["collector"], ["a"]),
    "collector_control_chars": _set(["collector"], "a\nb"),
    "alert_id_is_dict": _set(["alert_id"], {"a": 1}),
    "files_empty": _set(["files"], []),
    "files_is_dict": _set(["files"], {"a": 1}),
    "files_is_string": _set(["files"], "a.log"),
    "file_entry_is_string": _set(["files", 0], "a.log"),
    "file_entry_is_null": _set(["files", 0], None),
    "too_many_files": _set(["files"], [inline_file(f"f{i}.log", f"{i}".encode()) for i in range(11)]),
    "kind_unknown": _set(["files", 0, "kind"], "evtx"),
    "kind_not_string": _set(["files", 0, "kind"], ["auth_log"]),
    "kind_missing": _drop(["files", 0, "kind"]),
    "name_missing": _drop(["files", 0, "name"]),
    "both_path_and_inline": _set(["files", 0, "content_b64"], "QQ=="),
    "neither_path_nor_inline": _drop(["files", 0, "path"]),
    "unknown_file_field": _set(["files", 0, "mode"], "0777"),
    "path_not_string": _set(["files", 0, "path"], 5),
    "content_not_string": _set(["files", 1, "content_b64"], 5),
    "content_not_base64": _set(["files", 1, "content_b64"], "!!! not base64 !!!"),
    "content_bad_padding": _set(["files", 1, "content_b64"], "QUJD="),
    "base_year_is_bool": _set(["files", 1, "base_year"], True),
    "base_year_is_string": _set(["files", 1, "base_year"], "2026"),
    "base_year_is_float": _set(["files", 1, "base_year"], 2026.0),
    "base_year_out_of_range": _set(["files", 1, "base_year"], 12),
    "base_year_on_cloudtrail": _set(["files", 0, "base_year"], 2026),
    "sha256_wrong_shape": _set(["files", 1, "sha256"], "ABC"),
    "sha256_uppercase": _set(["files", 1, "sha256"], "A" * 64),
    "sha256_not_string": _set(["files", 1, "sha256"], 1),
    "sha256_does_not_match": _set(["files", 1, "sha256"], "0" * 64),
}


@pytest.mark.parametrize("mutate", INVALID.values(), ids=INVALID.keys())
def test_invalid_bundle_is_rejected_with_400_and_seals_nothing(env, mutate):
    bundle = make_bundle()
    mutate(bundle)
    response = env.post(bundle)

    assert response.status_code == 400, response.get_data(as_text=True)
    body = response.get_json()
    assert body["error"] == "invalid_bundle" and body["details"]
    env.assert_nothing_sealed()


def test_a_bad_second_file_means_the_first_is_not_sealed_either(env):
    bundle = bundle_with(inline_file("good.log"), inline_file("bad.log", sha256="0" * 64))
    assert env.post(bundle).status_code == 400
    env.assert_nothing_sealed()


def test_every_problem_is_reported_not_just_the_first(env):
    bundle = make_bundle()
    del bundle["bundle_id"]
    bundle["captured_at"] = "nope"
    details = env.post(bundle).get_json()["details"]
    assert any("bundle_id" in d for d in details) and any("captured_at" in d for d in details)


# ---------------------------------------------------------------------------
# Path traversal and hostile names (the guardrail cases)
# ---------------------------------------------------------------------------
BAD_NAMES = [
    "../../etc/passwd", "..\\..\\windows\\system32\\x", "a/b.log", "a\\b.log", "/etc/passwd",
    "C:\\x.log", "file.log:stream", "..", ".", "", "trailing.", "trailing ", "CON", "nul.txt", "COM1.log",
    "evil\x00.log", "line\nbreak.log", "q?.log", "star*.log", "x" * 129, 5, None, ["a.log"],
]


@pytest.mark.parametrize("name", BAD_NAMES, ids=[repr(n)[:30] for n in BAD_NAMES])
def test_hostile_file_names_are_rejected_not_cleaned(env, name):
    response = env.post(bundle_with(inline_file(name=name)))

    assert response.status_code == 400
    env.assert_nothing_sealed()
    # Nothing was created anywhere under the test's folder besides the fixtures.
    created = {p.name for p in env.tmp.rglob("*")}
    assert not ({"passwd", "system32", "escape.log"} & created)


def test_a_traversal_name_does_not_write_outside_the_working_folder(env):
    env.post(bundle_with(inline_file(name="../../escape.log")))
    assert not list(env.tmp.parent.rglob("escape.log"))


BAD_PATHS = [
    "../../etc/passwd", "../cloudtrail_sample.json", "sub/../../x", "/etc/passwd", "\\etc\\passwd",
    "C:\\Windows\\win.ini", "C:win.ini", "\\\\server\\share\\x", ".", "", "missing.json", "x\x00y",
]


@pytest.mark.parametrize("path", BAD_PATHS, ids=[repr(p)[:30] for p in BAD_PATHS])
def test_path_entries_cannot_escape_the_staging_root(env, path):
    (env.tmp / "outside.txt").write_text("secret")
    entry = {"name": "x.log", "kind": "auth_log", "path": path}
    response = env.post(bundle_with(entry))

    assert response.status_code == 400
    env.assert_nothing_sealed()


def test_dotdot_is_refused_even_when_it_stays_inside_the_root(env):
    (env.staging / "sub").mkdir()
    entry = {"name": "x.log", "kind": "auth_log", "path": "sub/../cloudtrail_sample.json"}
    response = env.post(bundle_with(entry))
    assert response.status_code == 400
    assert any("'..'" in d for d in response.get_json()["details"])
    env.assert_nothing_sealed()


def test_a_symlink_pointing_outside_the_staging_root_is_refused(env):
    (env.tmp / "outside.txt").write_text("secret")
    try:
        (env.staging / "link.log").symlink_to(env.tmp / "outside.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available on this platform")
    entry = {"name": "link.log", "kind": "auth_log", "path": "link.log"}
    assert env.post(bundle_with(entry)).status_code == 400
    env.assert_nothing_sealed()


def test_a_directory_is_not_a_file(env):
    (env.staging / "adir").mkdir()
    entry = {"name": "x.log", "kind": "auth_log", "path": "adir"}
    assert env.post(bundle_with(entry)).status_code == 400


def test_path_entries_are_refused_when_no_staging_root_is_configured(tmp_path):
    env = Env(tmp_path, staging_root=None)
    response = env.post(make_bundle())          # fixture has a path entry
    assert response.status_code == 400
    assert any("disabled" in d for d in response.get_json()["details"])
    env.assert_nothing_sealed()
    assert env.post(bundle_with(inline_file())).status_code == 201   # inline still works


# ---------------------------------------------------------------------------
# Size limits
# ---------------------------------------------------------------------------
def test_oversize_request_body_is_413(tmp_path):
    env = Env(tmp_path, max_body_bytes=2000)
    response = env.post(bundle_with(inline_file(data=b"A" * 5000)))
    assert response.status_code == 413
    assert response.get_json()["error"] == "payload_too_large"
    env.assert_nothing_sealed()


CAPTURE_SECRET = b"synthetic-capture-secret-with-more-than-32-bytes"


def test_non_loopback_listener_requires_authentication(tmp_path):
    with pytest.raises(ValueError, match="Non-loopback"):
        create_app(Settings(db_path=tmp_path / "stamped.db"), host="0.0.0.0")


def test_signed_listener_rejects_missing_and_invalid_signatures_without_logging_body(tmp_path, caplog):
    env = Env(tmp_path, auth_secret=CAPTURE_SECRET)
    body = json.dumps(bundle_with(inline_file(data=b"body-must-not-be-logged"))).encode()

    missing = env.client.post("/alert", data=body, content_type="application/json")
    assert missing.status_code == 401
    headers = signed_headers(b"wrong-secret-with-at-least-32-bytes", body)
    invalid = env.client.post(
        "/alert", data=body, content_type="application/json", headers=headers
    )
    assert invalid.status_code == 401
    assert invalid.get_json()["error"] == "unauthorized"
    assert env.client.application.extensions["stamped_listener_rejections"]["authentication"] == 2
    assert "body-must-not-be-logged" not in caplog.text
    env.assert_nothing_sealed()


def test_signed_listener_rejects_a_replayed_request(tmp_path):
    env = Env(tmp_path, auth_secret=CAPTURE_SECRET)
    body = json.dumps(bundle_with(inline_file())).encode()
    headers = signed_headers(CAPTURE_SECRET, body)

    first = env.client.post(
        "/alert", data=body, content_type="application/json", headers=headers
    )
    assert first.status_code == 201
    entries_after_first = env.count("custody_log")

    replay = env.client.post(
        "/alert", data=body, content_type="application/json", headers=headers
    )
    assert replay.status_code == 401
    assert replay.get_json()["error"] == "replayed_request"
    assert env.count("custody_log") == entries_after_first
    assert env.client.application.extensions["stamped_listener_rejections"]["authentication"] == 1


def test_listener_rate_limits_requests_per_source(tmp_path):
    env = Env(tmp_path, max_requests_per_minute=1)
    first = env.client.post("/alert", data="{}", content_type="text/plain")
    second = env.client.post("/alert", data="{}", content_type="text/plain")
    assert first.status_code == 415
    assert second.status_code == 429
    assert second.get_json()["error"] == "rate_limited"
    assert env.client.application.extensions["stamped_listener_rejections"]["rate_limited"] == 1


def test_oversize_inline_file_is_rejected(tmp_path):
    env = Env(tmp_path, max_file_bytes=10)
    assert env.post(bundle_with(inline_file(data=b"A" * 11))).status_code == 400
    assert env.post(bundle_with(inline_file(data=b"A" * 10))).status_code == 201


def test_oversize_path_file_is_rejected(tmp_path):
    env = Env(tmp_path, max_file_bytes=10)
    (env.staging / "big.log").write_bytes(b"A" * 11)
    assert env.post(bundle_with({"name": "big.log", "kind": "auth_log", "path": "big.log"})).status_code == 400
    env.assert_nothing_sealed()


def test_combined_size_limit(tmp_path):
    env = Env(tmp_path, max_total_bytes=15)
    two = bundle_with(inline_file("a.log", b"A" * 10), inline_file("b.log", b"B" * 10))
    assert env.post(two).status_code == 400
    env.assert_nothing_sealed()


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------
def test_one_failing_file_gives_207_and_keeps_the_others(env, monkeypatch):
    real = listener.seal_evidence

    def flaky(conn, file_path, *args, **kwargs):
        if Path(file_path).name == "auth.log":
            raise IntakeError(f"disk exploded at {file_path}")
        return real(conn, file_path, *args, **kwargs)

    monkeypatch.setattr(listener, "seal_evidence", flaky)
    response = env.post(make_bundle())

    assert response.status_code == 207
    body = response.get_json()
    assert body["status"] == "partial"
    assert [f["status"] for f in body["files"]] == ["sealed", "failed"]
    assert body["files"][1]["evidence_id"] is None
    assert env.count("evidence") == 1
    text = response.get_data(as_text=True)
    assert str(env.tmp) not in text and "stamped-capture" not in text and "exploded" not in text


def test_every_file_failing_is_500_with_per_file_results(env, monkeypatch):
    def broken(*args, **kwargs):
        raise IntakeError("nope")
    monkeypatch.setattr(listener, "seal_evidence", broken)
    response = env.post(make_bundle())
    assert response.status_code == 500
    assert response.get_json()["status"] == "failed"
    assert [f["status"] for f in response.get_json()["files"]] == ["failed", "failed"]


def test_unexpected_exception_gives_a_generic_500_without_details(env, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("secret detail at /home/someone/keys")
    monkeypatch.setattr(listener, "seal_bundle", boom)
    response = env.post(make_bundle())

    assert response.status_code == 500
    assert response.get_json() == {"error": "internal_error"}
    assert "secret" not in response.get_data(as_text=True)


def test_missing_database_is_503(tmp_path):
    env = Env(tmp_path)
    env.db_path.unlink()
    response = env.post(make_bundle())
    assert response.status_code == 503
    assert response.get_json()["error"] == "evidence_database_unavailable"
    assert str(tmp_path) not in response.get_data(as_text=True)


def test_cli_refuses_to_start_without_a_database(tmp_path, capsys):
    assert listener.main(["--db", str(tmp_path / "nope.db")]) == 2
    assert "Database not found" in capsys.readouterr().err


def test_cli_refuses_a_bad_staging_root(tmp_path, capsys):
    assert listener.main(["--staging-root", str(tmp_path / "nope")]) == 2


# ---------------------------------------------------------------------------
# Scope guardrail: the listener is a stand-in, not an integration
# ---------------------------------------------------------------------------
def test_listener_imports_no_external_service_clients():
    tree = ast.parse((REPO_ROOT / "capture" / "listener.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    allowed = {
        "__future__", "argparse", "base64", "binascii", "hashlib", "ipaddress", "json",
        "logging", "os", "re", "sys", "tempfile", "threading", "time", "collections",
        "dataclasses", "datetime", "pathlib", "flask", "werkzeug", "access", "capture",
        "seal", "gunicorn",
    }
    assert imported <= allowed, f"unexpected imports: {sorted(imported - allowed)}"