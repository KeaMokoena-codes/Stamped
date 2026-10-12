"""Tests the scoring MATH only (tiny hand cases). Real numbers come from a public dataset."""
from detect.validation import precision_recall


def f(dim, key):
    return {"grouped_by": dim, "key": key}


def test_precision_recall_basic():
    findings = [f("source_ip", "a"), f("source_ip", "b"), f("source_ip", "c")]
    truth = {("source_ip", "a"), ("source_ip", "b"), ("source_ip", "d")}
    r = precision_recall(findings, truth, "source_ip")
    assert (r["tp"], r["fp"], r["fn"]) == (2, 1, 1)
    assert round(r["precision"], 3) == 0.667 and round(r["recall"], 3) == 0.667


def test_other_dimension_is_ignored():
    r = precision_recall([f("account", "x")], {("source_ip", "a")}, "source_ip")
    assert (r["tp"], r["fp"], r["fn"]) == (0, 0, 1) and r["precision"] is None


def test_empty_truth_gives_no_recall():
    assert precision_recall([f("source_ip", "a")], set(), "source_ip")["recall"] is None