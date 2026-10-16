"""large_access rule: baseline, triggers, no-future-leak, real links, persistence.

Events here are hand-built, so these tests prove the LOGIC and the guardrails.
They say nothing about detection accuracy, which needs real labelled data.
"""
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from detect.canon import canonical_hash
from detect.findings import (detect_and_record, detect_large_access_and_record,
                             load_trigger_findings, record_finding)
from detect.rules import large_access
from detect.rules.brute_force import BruteForceConfig, detect
from detect.rules.impossible_travel import TravelConfig, detect_impossible_travel
from detect.rules.large_access import LargeAccessConfig, assess_triggers, detect_large_access
from schemas.init_db import SCHEMA_PATH
from seal.custody_log import recompute_and_verify_chain

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)
H = 3600
LOGIN_T = 30 * H                       # login 30 hours into the data
CFG = LargeAccessConfig(window_seconds=H, lookback_seconds=24 * H, min_history_seconds=12 * H,
                        min_baseline_events=5, z=3.0, min_bytes=1000)
BF = BruteForceConfig(threshold=5, window_seconds=60, success_follow_seconds=60)
_n = [0]


def _ev(secs, event_type, outcome, account="alice", ip="9.9.9.9", evid="E1", nbytes=None):
    _n[0] += 1
    d = {"event_id": f"ev{_n[0]:05d}", "evidence_id": evid, "raw_ref": f"line:{_n[0]}",
         "timestamp_utc": (BASE + timedelta(seconds=secs)).isoformat(), "event_type": event_type,
         "outcome": outcome, "account": account, "source_ip": ip, "service": "x"}
    if nbytes is not None:
        d["bytes_out"] = nbytes
    return d


def vol(secs, nbytes, **kw):
    return _ev(secs, "data_access", "success", nbytes=nbytes, **kw)


def baseline(account="alice", evid="E1"):
    """24 hourly events of 100/200/300/200 bytes: mean 200, population std 70.71."""
    return [vol(6 * H + i * H + 1800, [100, 200, 300, 200][i % 4], account=account, evid=evid)
            for i in range(24)]


def attack_logins():
    """5 failures then a success for alice from 9.9.9.9 at LOGIN_T."""
    return ([_ev(LOGIN_T - 50 + i * 10, "auth", "failure") for i in range(5)]
            + [_ev(LOGIN_T, "auth", "success")])


def scenario(spike=50_000):
    return baseline() + attack_logins() + [vol(LOGIN_T + 600, spike)]


def triggers_for(events):
    return detect(events, BF)


def la(events, cfg=CFG, triggers=None):
    return detect_large_access(events, triggers if triggers is not None else triggers_for(events), cfg)


# ----------------------------------------------------------------- the rule works
def test_flags_a_spike_after_a_bruteforce_login():
    f = la(scenario())
    assert len(f) == 1
    assert f[0]["key"] == "alice" and f[0]["window"]["bytes"] == 50_000


def test_baseline_statistics_are_exactly_what_the_docs_define():
    b = la(scenario())[0]["baseline"]
    assert (b["n_buckets"], b["n_events"]) == (24, 24)
    assert b["mean_bytes_per_bucket"] == 200.0
    assert b["std_bytes_per_bucket"] == pytest.approx(70.711, abs=1e-3)
    assert b["threshold_bytes"] == pytest.approx(412.132, abs=1e-3)


def test_volume_without_a_flagged_login_is_not_a_finding():
    assert la(baseline() + [vol(LOGIN_T + 600, 10**9)], triggers=[]) == []
    assert la(baseline() + [vol(LOGIN_T + 600, 10**9)]) == []      # no login events, so no triggers


def test_a_burst_with_no_success_has_no_login_to_follow():
    events = baseline() + [_ev(LOGIN_T - 50 + i * 10, "auth", "failure") for i in range(5)] \
             + [vol(LOGIN_T + 600, 10**6)]
    assert triggers_for(events) and la(events) == []


def test_below_threshold_is_not_flagged_and_above_is():
    cfg = replace(CFG, min_bytes=0)
    assert la(scenario(spike=400), cfg) == []          # under 412.13
    assert len(la(scenario(spike=500), cfg)) == 1      # over it


def test_absolute_floor_stops_tiny_but_relatively_huge_spikes():
    assert la(scenario(spike=900)) == []               # 4x baseline but under min_bytes=1000


def test_no_baseline_means_no_finding_not_a_guess():
    thin = [vol(29 * H, 1)] + attack_logins() + [vol(LOGIN_T + 600, 10**9)]
    assert la(thin) == []
    st = assess_triggers(thin, triggers_for(thin), CFG)
    assert {a["status"] for a in st} == {"insufficient_baseline"}


def test_young_history_is_not_enough():
    young = [vol(28 * H + i * 60, 200) for i in range(30)]          # only 2h of history
    events = young + attack_logins() + [vol(LOGIN_T + 600, 10**6)]
    assert la(events) == []


def test_only_successful_data_access_with_valid_bytes_counts():
    junk = [_ev(LOGIN_T + 100, "data_access", "failure", nbytes=10**9),
            _ev(LOGIN_T + 110, "activity", "success", nbytes=10**9),
            _ev(LOGIN_T + 120, "data_access", "success", nbytes=-5),
            _ev(LOGIN_T + 130, "data_access", "success", nbytes="999999999"),
            _ev(LOGIN_T + 140, "data_access", "success", nbytes=True),
            _ev(LOGIN_T + 150, "data_access", "success")]
    assert la(baseline() + attack_logins() + junk) == []


def test_other_accounts_volume_is_not_attributed():
    events = baseline() + attack_logins() + [vol(LOGIN_T + 600, 10**9, account="bob")]
    assert la(events) == []


def test_deterministic_regardless_of_input_order():
    ev = scenario()
    assert la(ev) == la(list(reversed(ev)))


def test_invalid_config_rejected():
    for bad in (dict(window_seconds=0), dict(lookback_seconds=100, window_seconds=60),
                dict(z=-1), dict(min_bytes=-1), dict(min_baseline_events=0)):
        with pytest.raises(ValueError):
            LargeAccessConfig(**bad)


# ------------------------------------------- GUARDRAIL 1: no future data in the baseline
def test_data_after_the_window_changes_nothing():
    ev = scenario()
    future = [vol(LOGIN_T + 2 * H + i * 60, 10**9) for i in range(50)]
    assert la(ev) == la(ev + future)
    assert la(ev)[0]["baseline"] == la(ev + future)[0]["baseline"]


def test_streaming_prefix_gives_identical_findings():
    """Live behaviour: a system that has only seen data up to the end of the window
    must produce exactly what the full historical run produces."""
    ev = scenario()
    tail = [vol(LOGIN_T + 5 * H + i * 60, 10**8) for i in range(40)] + baseline(account="bob")
    prefix_end = BASE + timedelta(seconds=LOGIN_T + H)
    prefix = [e for e in ev + tail if datetime.fromisoformat(e["timestamp_utc"]) < prefix_end]
    assert len(prefix) < len(ev + tail)
    assert la(prefix, triggers=triggers_for(ev)) == la(ev + tail, triggers=triggers_for(ev))


def test_baseline_never_includes_the_login_window_or_anything_after():
    ev = scenario(spike=10**9)
    assert la(ev)[0]["baseline"]["n_events"] == 24
    assert la(ev)[0]["baseline"]["mean_bytes_per_bucket"] == 200.0


def test_event_exactly_at_login_time_is_window_not_baseline():
    at_login = [vol(LOGIN_T, 5000)]
    f = la(scenario(spike=500) + at_login, replace(CFG, min_bytes=0))[0]
    assert f["window"]["bytes"] == 5500 and f["baseline"]["n_events"] == 24


def test_baseline_ignores_the_future_even_for_a_different_login_time():
    """Same data, trigger moved earlier: the later spike must not leak backwards."""
    ev = baseline() + attack_logins() + [vol(LOGIN_T + 600, 50_000)]
    early = [_ev(18 * H - 50 + i * 10, "auth", "failure") for i in range(5)] + [_ev(18 * H, "auth", "success")]
    f = la(ev + early, triggers=triggers_for(early))
    assert f == []                                     # nothing after 18h is allowed to matter


# ------------------------------------------ GUARDRAIL 2: the link is real stored data
def test_finding_references_the_real_trigger_finding_hashes():
    ev = scenario()
    trig = triggers_for(ev)
    f = la(ev)[0]
    assert {t["finding_hash"] for t in f["triggered_by"]} == {t["finding_hash"] for t in trig}
    assert all(len(t["finding_hash"]) == 64 for t in f["triggered_by"])


def test_two_triggers_on_one_login_make_one_finding():
    ev = scenario()
    assert len(triggers_for(ev)) == 2                  # account and source_ip groupings
    assert len(la(ev)) == 1


def test_the_trigger_hashes_are_part_of_the_findings_own_hash():
    ev = scenario()
    trig = triggers_for(ev)
    a = la(ev, triggers=trig)[0]
    b = la(ev, triggers=trig[:1])[0]
    assert a["input_hash"] != b["input_hash"] and a["finding_hash"] != b["finding_hash"]


def test_a_forged_or_edited_trigger_is_rejected():
    ev = scenario()
    forged = dict(triggers_for(ev)[0], key="mallory")
    assert la(ev, triggers=[forged]) == []
    assert assess_triggers(ev, [forged], CFG)[0]["reason"] == "finding_hash_mismatch"


def test_trigger_whose_login_event_is_missing_is_unresolved_not_guessed():
    ev = scenario()
    trig = triggers_for(ev)
    without_login = [e for e in ev if not (e["event_type"] == "auth" and e["outcome"] == "success")]
    assert la(without_login, triggers=trig) == []
    assert {a["reason"] for a in assess_triggers(without_login, trig, CFG)} == {"login_event_not_in_events"}


def test_impossible_travel_trigger_uses_the_second_login():
    places = {"1.1.1.1": (51.5, -0.12), "2.2.2.2": (40.7, -74.0)}
    logins = [_ev(LOGIN_T - 600, "auth", "success", ip="1.1.1.1"), _ev(LOGIN_T, "auth", "success", ip="2.2.2.2")]
    ev = baseline() + logins + [vol(LOGIN_T + 900, 50_000, ip="2.2.2.2")]
    trav = detect_impossible_travel(ev, TravelConfig(), places.get, {"source": "fake", "sha256": "0" * 64})
    f = la(ev, triggers=trav)
    assert len(f) == 1 and f[0]["login"]["source_ip"] == "2.2.2.2"
    assert f[0]["triggered_by"][0]["rule_name"] == "impossible_travel"
    assert f[0]["window"]["source_ips"] == ["2.2.2.2"]


# -------------------------------------------------- input hash covers exactly what was read
def test_input_hash_ignores_unrelated_events():
    ev = scenario()
    base = la(ev)[0]["input_hash"]
    noise = baseline(account="bob") + [vol(LOGIN_T + 700, 777, account="bob")]
    assert la(ev + noise, triggers=triggers_for(ev))[0]["input_hash"] == base


def test_input_hash_changes_when_a_baseline_event_changes():
    ev = scenario()
    base = la(ev)[0]["input_hash"]
    i = next(k for k, e in enumerate(ev) if e["event_type"] == "data_access")
    ev2 = list(ev)
    ev2[i] = dict(ev2[i], raw_ref="line:tampered")
    assert la(ev2, triggers=triggers_for(ev))[0]["input_hash"] != base


def test_source_events_link_to_the_login_and_the_window_events():
    f = la(scenario())[0]
    assert f["source_events"][0]["raw_ref"].startswith("line:")
    assert len(f["source_events"]) == 2                # the login and the one window event
    assert f["baseline"]["events_hash"] and f["baseline"]["evidence_ids"] == ["E1"]


def test_rule_version():
    assert large_access.RULE_VERSION == "1.0.0"


# ------------------------------------------------------------------------ persistence
@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    yield c
    c.close()


def _count(conn, sql):
    return conn.execute(sql).fetchone()[0]


def test_recording_without_the_trigger_is_refused_and_writes_nothing(conn):
    ev = scenario()
    with pytest.raises(ValueError, match="not recorded"):
        record_finding(conn, la(ev)[0])
    assert _count(conn, "SELECT COUNT(*) FROM findings") == 0
    assert _count(conn, "SELECT COUNT(*) FROM artifacts") == 0
    assert _count(conn, "SELECT COUNT(*) FROM custody_log") == 0


def test_end_to_end_link_is_a_real_database_relationship(conn):
    ev = scenario()
    detect_and_record(conn, ev, BF)
    triggers = load_trigger_findings(conn)
    assert len(triggers) == 2
    assert detect_large_access_and_record(conn, ev, triggers, CFG) == 1
    fid = la(ev, triggers=triggers)[0]["finding_hash"]

    src_evidence, src_artifact = conn.execute(
        "SELECT source_evidence_id, source_artifact_id FROM artifacts WHERE artifact_id = ?", (fid,)).fetchone()
    assert src_evidence is None and src_artifact in {t["finding_hash"] for t in triggers}
    joined = conn.execute(
        "SELECT t.rule_id FROM artifacts a JOIN findings t ON t.finding_id = a.source_artifact_id "
        "WHERE a.artifact_id = ?", (fid,)).fetchall()
    assert joined and joined[0][0].startswith("brute_force_login@")
    assert recompute_and_verify_chain(conn) == (True, None)


def test_custody_entries_and_metadata_list_every_trigger(conn):
    ev = scenario()
    detect_and_record(conn, ev, BF)
    triggers = load_trigger_findings(conn)
    detect_large_access_and_record(conn, ev, triggers, CFG)
    fid = la(ev, triggers=triggers)[0]["finding_hash"]
    import json
    meta = json.loads(conn.execute("SELECT metadata_json FROM artifacts WHERE artifact_id = ?", (fid,)).fetchone()[0])
    assert set(meta["triggered_by"]) == {t["finding_hash"] for t in triggers}
    rows = conn.execute("SELECT details_json FROM custody_log WHERE artifact_id = ?", (fid,)).fetchall()
    assert rows and all(set(json.loads(r[0])["triggered_by"]) == set(meta["triggered_by"]) for r in rows)


def test_stored_finding_hashes_to_its_output_hash_and_rerecording_is_idempotent(conn):
    import hashlib
    ev = scenario()
    detect_and_record(conn, ev, BF)
    triggers = load_trigger_findings(conn)
    detect_large_access_and_record(conn, ev, triggers, CFG)
    assert detect_large_access_and_record(conn, ev, triggers, CFG) == 0
    text, out = conn.execute(
        "SELECT f.details_json, a.output_hash FROM findings f JOIN artifacts a ON a.artifact_id = f.artifact_id "
        "WHERE f.rule_id LIKE 'large_access@%'").fetchone()
    assert hashlib.sha256(text.encode()).hexdigest() == out


def test_load_trigger_findings_round_trips_the_originals(conn):
    ev = scenario()
    originals = triggers_for(ev)
    detect_and_record(conn, ev, BF)
    loaded = load_trigger_findings(conn)
    assert sorted(loaded, key=lambda f: f["finding_hash"]) == sorted(originals, key=lambda f: f["finding_hash"])
    assert all(canonical_hash({k: v for k, v in f.items() if k != "finding_hash"}) == f["finding_hash"] for f in loaded)



def test_timeline_places_the_finding_at_the_end_of_its_window_and_keeps_the_link(conn):
    from ingest.timeline import build_timeline, load_findings_from_db
    ev = scenario()
    f = la(ev)[0]
    assert (f["first_seen"], f["last_seen"]) == (f["window"]["start"], f["window"]["end"])
    items = build_timeline([], [f])
    assert items[0]["timestamp_utc"] == f["window"]["end"]
    assert {t["finding_hash"] for t in items[0]["details"]["triggered_by"]} == \
        {t["finding_hash"] for t in triggers_for(ev)}
    detect_and_record(conn, ev, BF)
    detect_large_access_and_record(conn, ev, load_trigger_findings(conn), CFG)
    stored = [x for x in build_timeline([], load_findings_from_db(conn)) if x["service"].startswith("large_access@")]
    assert stored[0]["timestamp_utc"] == f["window"]["end"]