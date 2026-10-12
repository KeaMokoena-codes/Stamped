"""Logic + provenance tests for the brute-force rule.

These use hand-built events and prove the code behaves as designed.
They do NOT count toward precision/recall; that must come from a public dataset.
"""
from datetime import datetime, timedelta, timezone

import pytest

from detect.rules.brute_force import BruteForceConfig, detect
from schemas.normalized_event import NormalizedEvent

BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
CFG = BruteForceConfig(threshold=5, window_seconds=60, success_follow_seconds=60)


def ev(i, secs, outcome="failure", account="alice", ip="10.0.0.1", evid="E1"):
    return {
        "event_id": f"ev{i}", "evidence_id": evid, "raw_ref": f"line:{i}",
        "timestamp_utc": (BASE + timedelta(seconds=secs)).isoformat(),
        "event_type": "auth", "outcome": outcome,
        "account": account, "source_ip": ip, "service": "ssh",
    }


def burst(n=5, start=0, **kw):
    return [ev(i, start + i, **kw) for i in range(n)]


def by_dim(findings, dim):
    return [f for f in findings if f["grouped_by"] == dim]


def test_below_threshold_no_finding():
    assert detect(burst(4), CFG) == []


def test_at_threshold_flags_once_per_dimension():
    f = detect(burst(5), CFG)
    assert len(by_dim(f, "account")) == 1 and len(by_dim(f, "source_ip")) == 1


def test_failures_outside_window_not_flagged():
    assert detect([ev(i, i * 30) for i in range(5)], CFG) == []   # 120s span


def test_window_edge_is_inclusive():
    assert detect([ev(i, i * 15) for i in range(5)], CFG)          # exactly 60s span


def test_one_second_past_window_not_flagged():
    events = [ev(i, i * 15) for i in range(4)] + [ev(4, 61)]
    assert detect(events, CFG) == []


def test_one_long_attack_is_one_finding_not_many():
    events = [ev(i, i * 5) for i in range(40)]
    assert len(by_dim(detect(events, CFG), "account")) == 1


def test_two_separate_attacks_are_two_findings():
    events = burst(5) + [ev(100 + i, 10_000 + i) for i in range(5)]
    assert len(by_dim(detect(events, CFG), "account")) == 2


def test_different_accounts_are_not_mixed():
    events = [ev(i, i, account=f"user{i}", ip=f"10.0.0.{i}") for i in range(5)]
    assert detect(events, CFG) == []


def test_spraying_one_ip_many_accounts_flags_ip_only():
    events = [ev(i, i, account=f"user{i}") for i in range(5)]
    f = detect(events, CFG)
    assert len(by_dim(f, "source_ip")) == 1 and by_dim(f, "account") == []


def test_success_after_burst_raises_severity():
    f = by_dim(detect(burst(5) + [ev(99, 20, outcome="success")], CFG), "account")[0]
    assert f["severity"] == "high" and f["followed_by_success"]


def test_success_too_late_does_not_raise_severity():
    f = by_dim(detect(burst(5) + [ev(99, 500, outcome="success")], CFG), "account")[0]
    assert f["severity"] == "medium"


def test_success_for_other_account_does_not_count():
    events = burst(5) + [ev(99, 20, outcome="success", account="bob", ip="10.9.9.9")]
    assert by_dim(detect(events, CFG), "account")[0]["severity"] == "medium"


def test_matched_success_is_part_of_the_examined_events():
    f = by_dim(detect(burst(5) + [ev(99, 20, outcome="success")], CFG), "account")[0]
    assert "ev99" in {s["event_id"] for s in f["source_events"]}


def test_deterministic_regardless_of_input_order():
    events = burst(6)
    a, b = detect(events, CFG), detect(list(reversed(events)), CFG)
    assert a == b and a[0]["finding_hash"] == b[0]["finding_hash"]


def test_input_hash_ignores_unrelated_events():
    events = burst(5)
    base = by_dim(detect(events, CFG), "account")[0]["input_hash"]
    noise = ev(500, 9999, account="bob", ip="10.9.9.9", evid="E2")
    assert by_dim(detect(events + [noise], CFG), "account")[0]["input_hash"] == base


def test_input_hash_changes_when_examined_event_changes():
    events = burst(5)
    base = by_dim(detect(events, CFG), "account")[0]["input_hash"]
    events[2] = dict(events[2], raw_ref="line:tampered")
    assert by_dim(detect(events, CFG), "account")[0]["input_hash"] != base


def test_input_hash_is_not_constant_across_different_bursts():
    a = by_dim(detect(burst(5), CFG), "account")[0]["input_hash"]
    b = by_dim(detect([ev(i + 50, i, account="carol", ip="10.1.1.1") for i in range(5)], CFG), "account")[0]["input_hash"]
    assert a != b


def test_finding_links_to_exact_source_lines():
    f = by_dim(detect(burst(5), CFG), "account")[0]
    assert {s["raw_ref"] for s in f["source_events"]} == {f"line:{i}" for i in range(5)}


def test_config_change_changes_finding_hash():
    a = detect(burst(5), CFG)[0]["finding_hash"]
    b = detect(burst(5), BruteForceConfig(5, 90, 60))[0]["finding_hash"]
    assert a != b


def test_accepts_normalized_event_dataclasses_and_z_suffix():
    events = [NormalizedEvent(f"e{i}", "E1", f"line:{i}",
                              f"2026-01-01T12:00:0{i}Z", "auth", "failure",
                              account="alice", source_ip="10.0.0.1")
              for i in range(5)]
    assert detect(events, CFG)


def test_naive_timestamp_is_rejected():
    bad = burst(5)
    bad[0]["timestamp_utc"] = "2026-01-01T12:00:00"
    with pytest.raises(ValueError):
        detect(bad, CFG)


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        BruteForceConfig(threshold=1)
    with pytest.raises(ValueError):
        BruteForceConfig(window_seconds=0)


def test_normalized_event_rejects_bad_outcome():
    with pytest.raises(ValueError):
        NormalizedEvent("e", "E1", "line:1", "2026-01-01T12:00:00+00:00", "auth", "maybe")