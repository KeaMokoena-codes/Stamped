"""
Precision/recall helpers for validating rules against a PUBLIC labelled dataset.

Ground truth is a set of (dimension, key) pairs known to be malicious, e.g.
{("source_ip", "203.0.113.7")}. Score one dimension at a time.

Precision is only meaningful if the dataset contains benign traffic as well.
If it is attack-only, report recall alone and say so in the validation notes.
Never score against the team's own synthetic attacks: that is circular.
"""
from __future__ import annotations

from detect.rules.brute_force import BruteForceConfig, detect


def precision_recall(findings, truth, dimension):
    flagged = {(f["grouped_by"], f["key"]) for f in findings if f["grouped_by"] == dimension}
    truth = {t for t in truth if t[0] == dimension}
    tp = len(flagged & truth)
    fp = len(flagged - truth)
    fn = len(truth - flagged)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "recall": tp / (tp + fn) if (tp + fn) else None,
    }


def sweep(events, truth, dimension, thresholds, windows, follow_seconds=300):
    """Score a grid of (threshold, window) pairs. Returns rows ready for a table."""
    events = list(events)
    rows = []
    for th in thresholds:
        for w in windows:
            cfg = BruteForceConfig(th, w, follow_seconds)
            rows.append({"threshold": th, "window_seconds": w,
                         **precision_recall(detect(events, cfg), truth, dimension)})
    return rows


def score_labeled(findings, malicious, benign, dimension="source_ip"):
    """Score against WEAK labels: malicious / benign key sets (e.g. IPs).

    Flagged keys in neither set are UNLABELLED. They are counted separately and
    excluded from precision, because we cannot say whether they are right.
    Always report n_benign: a tiny benign set means precision is barely measured.
    """
    flagged = {f["key"] for f in findings if f["grouped_by"] == dimension}
    tp = len(flagged & malicious)
    fp = len(flagged & benign)
    fn = len(malicious - flagged)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "unlabelled_flagged": len(flagged - malicious - benign),
        "n_malicious": len(malicious), "n_benign": len(benign),
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "recall": tp / (tp + fn) if (tp + fn) else None,
    }


def sweep_labeled(events, malicious, benign, thresholds, windows,
                  dimension="source_ip", follow_seconds=300):
    events = list(events)
    rows = []
    for th in thresholds:
        for w in windows:
            cfg = BruteForceConfig(th, w, follow_seconds)
            rows.append({"threshold": th, "window_seconds": w,
                         **score_labeled(detect(events, cfg), malicious, benign, dimension)})
    return rows