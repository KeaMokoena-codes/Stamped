"""Hostile synthetic case-package inputs; all writes stay in pytest temp folders."""

import pytest

from tests.test_verify import make_export, run
from verifier import verify


def test_anchor_symlink_is_rejected_without_parsing_the_target(tmp_path, monkeypatch):
    export = make_export(tmp_path)
    outside = tmp_path / "outside-anchor.json"
    outside.write_text("{}", encoding="utf-8")
    link = export.anchors / "anchor_000001.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this platform")

    def must_not_read(_path):
        pytest.fail("the verifier followed a symbolic link out of the package")

    monkeypatch.setattr(verify, "_parse_anchor", must_not_read)
    rc, report, *_ = run(export)
    assert rc == 1
    assert report["overall"] == "FAIL"
    assert "anchor_path_invalid" in {
        failure["code"]
        for check in report["checks"].values()
        for failure in check.get("failures", [])
    }


def test_database_symlink_is_rejected(tmp_path):
    export = make_export(tmp_path)
    outside = tmp_path / "outside.db"
    outside.write_bytes(export.db.read_bytes())
    export.db.unlink()
    try:
        export.db.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this platform")

    from tests.test_verify import error_run

    rc, out, err = error_run(["--case-export", str(export.root), "--allow-no-anchors"])
    assert rc == 2
    assert "symbolic link" in err
    assert "PASS" not in out


def test_oversized_anchor_is_rejected_before_json_parsing(tmp_path, monkeypatch):
    export = make_export(tmp_path)
    anchor = export.anchors / "anchor_000001.json"
    anchor.write_bytes(b" " * (verify.MAX_ANCHOR_BYTES + 1))

    def must_not_read(_path):
        pytest.fail("the verifier parsed an oversized anchor")

    monkeypatch.setattr(verify, "_parse_anchor", must_not_read)
    rc, report, *_ = run(export)
    assert rc == 1
    assert report["overall"] == "FAIL"
    assert "anchor_too_large" in {
        failure["code"]
        for check in report["checks"].values()
        for failure in check.get("failures", [])
    }
