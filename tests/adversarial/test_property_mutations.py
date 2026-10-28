"""Property-based integrity checks over synthetic exported case copies."""

from hypothesis import given, settings, strategies as st

from tests.test_verify import make_export, run, tamper
from verifier import verify


@settings(max_examples=15, deadline=None)
@given(st.text(min_size=1, max_size=32))
def test_changing_a_custody_field_never_produces_pass(tmp_path_factory, replacement):
    work = tmp_path_factory.mktemp("field-mutation")
    export = make_export(work)
    tamper(
        export.db,
        "UPDATE custody_log SET actor = ? WHERE entry_id = 3",
        (f"attacker-{replacement}",),
    )

    rc, report, *_ = run(export, "--allow-no-anchors")
    assert rc == 1
    assert report["overall"] == "FAIL"
    assert report["broken_entry_id"] == 3


def test_canonical_json_is_stable_across_key_insertion_order():
    left = {"case_id": "CASE-1", "details": {"z": 2, "a": 1}}
    right = {"details": {"a": 1, "z": 2}, "case_id": "CASE-1"}
    assert verify.canonical(left) == verify.canonical(right)
    assert verify.canonical(left) != verify.canonical({**right, "case_id": "CASE-2"})
