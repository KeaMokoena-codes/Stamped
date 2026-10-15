"""Tests for the impossible_travel rule, its provenance, and its false positives.

The geolocator is a fake dict here, so these tests check the RULE LOGIC, not
the accuracy of any real geolocation database. Real-database behaviour is
checked separately (tests/test_geo.py and scripts/geo_fp_demo.py).
"""
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from detect.canon import canonical_hash
from detect.findings import detect_travel_and_record, record_finding
from detect.rules.impossible_travel import (
    TravelConfig, detect_impossible_travel, detect_with_stats, haversine_km)
from seal.custody_log import recompute_and_verify_chain

SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "schema.sql"
BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
GEO_INFO = {"source": "fake.mmdb", "sha256": "f" * 64, "build_epoch": 1}

JNB, LON, PTA = (-26.2041, 28.0473), (51.5074, -0.1278), (-25.7479, 28.2293)
CPT, FRA = (-33.9249, 18.4241), (50.1109, 8.6821)
PLACES = {
    "203.0.113.1": JNB, "203.0.113.2": LON, "203.0.113.3": PTA,
    "203.0.113.4": CPT, "203.0.113.5": FRA, "203.0.113.6": JNB,
}


def geolocate(ip):
    return PLACES.get(ip)           # unknown -> None (unlocatable)


_n = [0]


def ev(account, ip, seconds, outcome="success", evidence="E1"):
    _n[0] += 1
    return {
        "event_id": f"ev{_n[0]}", "evidence_id": evidence, "raw_ref": f"line:{_n[0]}",
        "timestamp_utc": (BASE + timedelta(seconds=seconds)).isoformat(),
        "event_type": "auth", "outcome": outcome,
        "account": account, "source_ip": ip, "service": "ssh",
    }


def run(events, cfg=TravelConfig()):
    return detect_impossible_travel(events, cfg, geolocate, GEO_INFO)


# ---------------------------------------------------------------- core logic
def test_haversine_known_distance():
    assert haversine_km(JNB, LON) == pytest.approx(9070, abs=60)
    assert haversine_km(JNB, JNB) == 0


def test_far_apart_and_fast_is_flagged_once():
    f = run([ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 600)])
    assert len(f) == 1
    assert f[0]["grouped_by"] == "account" and f[0]["key"] == "alice"
    assert f[0]["speed_kmh"] > 900 and f[0]["distance_km"] > 9000
    assert f[0]["severity"] == "medium" and f[0]["instantaneous"] is False


def test_slow_enough_is_not_flagged():
    # ~9070 km in 15 h is ~605 km/h: physically possible by plane
    assert run([ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 15 * 3600)]) == []


def test_speed_threshold_is_configurable():
    events = [ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 15 * 3600)]
    assert len(run(events, TravelConfig(speed_threshold_kmh=500))) == 1


def test_short_hop_under_min_distance_is_ignored_even_if_fast():
    # Johannesburg -> Pretoria ~55 km in 1 minute is ~3000 km/h, but under the floor
    f, stats = detect_with_stats(
        [ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.3", 60)],
        TravelConfig(), geolocate, GEO_INFO)
    assert f == [] and stats["pairs_below_min_distance"] == 1


def test_min_distance_is_configurable():
    events = [ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.3", 60)]
    assert len(run(events, TravelConfig(min_distance_km=10))) == 1


def test_same_ip_never_counts():
    f, stats = detect_with_stats(
        [ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.1", 1)],
        TravelConfig(), geolocate, GEO_INFO)
    assert f == [] and stats["pairs_same_ip"] == 1


def test_failures_are_ignored():
    assert run([ev("alice", "203.0.113.1", 0),
                ev("alice", "203.0.113.2", 60, outcome="failure")]) == []


def test_accounts_are_not_mixed():
    assert run([ev("alice", "203.0.113.1", 0), ev("bob", "203.0.113.2", 60)]) == []


def test_unlocatable_ip_is_dropped_and_counted_not_guessed():
    f, stats = detect_with_stats(
        [ev("alice", "203.0.113.1", 0), ev("alice", "198.51.100.99", 30),
         ev("alice", "203.0.113.2", 60)],
        TravelConfig(), geolocate, GEO_INFO)
    assert stats["unlocatable_logins"] == 1
    assert len(f) == 1                       # the two located logins are compared directly
    assert {l["source_ip"] for l in f[0]["logins"]} == {"203.0.113.1", "203.0.113.2"}


def test_only_unlocatable_ips_gives_no_finding():
    assert run([ev("alice", "198.51.100.1", 0), ev("alice", "198.51.100.2", 60)]) == []


def test_simultaneous_logins_are_flagged_with_null_speed_and_valid_json():
    f = run([ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 0)])
    assert len(f) == 1 and f[0]["speed_kmh"] is None and f[0]["instantaneous"] is True
    json.dumps(f[0], allow_nan=False)        # no Infinity/NaN anywhere


def test_three_logins_compare_consecutive_pairs_only():
    f = run([ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 600),
             ev("alice", "203.0.113.1", 1200)])
    assert len(f) == 2                       # JNB->LON and LON->JNB


def test_deterministic_regardless_of_input_order():
    events = [ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 600)]
    assert run(events) == run(list(reversed(events)))


def test_naive_timestamp_is_rejected():
    bad = ev("alice", "203.0.113.1", 0)
    bad["timestamp_utc"] = "2026-01-01T12:00:00"
    with pytest.raises(ValueError):
        run([bad, ev("alice", "203.0.113.2", 60)])


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        TravelConfig(speed_threshold_kmh=0)
    with pytest.raises(ValueError):
        TravelConfig(min_distance_km=-1)


# ---------------------------------------------------------------- provenance
def test_input_hash_covers_only_the_two_examined_events():
    a, b = ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 600)
    noise = [ev("bob", "203.0.113.4", 10), ev("alice", "203.0.113.1", 99999)]
    f1, f2 = run([a, b])[0], run([a, b] + noise)[0]
    assert f1["input_hash"] == f2["input_hash"] == canonical_hash([a, b])


def test_input_hash_changes_when_an_examined_event_changes():
    a, b = ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 600)
    b2 = dict(b, raw_ref="line:99999")
    assert run([a, b])[0]["input_hash"] != run([a, b2])[0]["input_hash"]


def test_finding_hash_changes_with_geo_database_or_coordinates():
    events = [ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 600)]
    base = run(events)[0]["finding_hash"]
    other_db = detect_impossible_travel(
        events, TravelConfig(), geolocate, dict(GEO_INFO, sha256="a" * 64))[0]["finding_hash"]
    moved = detect_impossible_travel(
        events, TravelConfig(), lambda ip: (JNB if ip == "203.0.113.1" else (48.8566, 2.3522)),
        GEO_INFO)[0]["finding_hash"]
    assert len({base, other_db, moved}) == 3


def test_finding_hash_changes_with_config():
    events = [ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 600)]
    assert (run(events)[0]["finding_hash"]
            != run(events, TravelConfig(speed_threshold_kmh=800))[0]["finding_hash"])


def test_finding_links_to_exact_source_lines():
    a, b = ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.2", 600)
    f = run([a, b])[0]
    assert [(s["event_id"], s["raw_ref"]) for s in f["source_events"]] == [
        (a["event_id"], a["raw_ref"]), (b["event_id"], b["raw_ref"])]
    assert f["geo_source"] == GEO_INFO


# ----------------------------------------------------------- persistence
@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.executescript(SCHEMA.read_text(encoding="utf-8"))
    yield c
    c.close()


def _events():
    return [ev("alice", "203.0.113.1", 0, evidence="E1"),
            ev("alice", "203.0.113.2", 600, evidence="E2")]


def test_travel_finding_is_persisted_with_full_provenance(conn):
    f = run(_events())[0]
    assert record_finding(conn, f) is True
    conn.commit()
    text, out, rule, sev, title = conn.execute(
        "SELECT f.details_json, a.output_hash, f.rule_id, f.severity, f.title "
        "FROM findings f JOIN artifacts a ON a.artifact_id = f.artifact_id").fetchone()
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == out == f["finding_hash"]
    assert rule == "impossible_travel@1.1.0" and sev == "medium" and "Impossible travel" in title
    assert conn.execute("SELECT COUNT(*) FROM custody_log WHERE action='finding_created'"
                        ).fetchone()[0] == 2           # one per evidence item
    assert recompute_and_verify_chain(conn) == (True, None)


def test_detect_travel_and_record_is_idempotent(conn):
    events = _events()
    assert detect_travel_and_record(conn, events, geolocate, GEO_INFO) == 1
    assert detect_travel_and_record(conn, events, geolocate, GEO_INFO) == 0


# ------------------------------------------------------ FALSE POSITIVES
# These DEMONSTRATE the documented false positives: the rule fires on benign
# behaviour, and this is how that looks. Not bugs, known limits of the approach.
def test_FP_vpn_exit_node_same_user():
    """Alice logs in from home (Johannesburg), then 5 minutes later through a VPN
    whose exit node geolocates to Frankfurt. Same person, same hour: flagged."""
    f = run([ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.5", 300)])
    assert len(f) == 1 and f[0]["speed_kmh"] > 50_000


def test_FP_mobile_carrier_nat_gateway():
    """Alice is on home wifi in Cape Town, then switches to mobile data. The carrier's
    NAT gateway geolocates to Johannesburg (~1,270 km away) 2 minutes later: flagged."""
    f = run([ev("alice", "203.0.113.4", 0), ev("alice", "203.0.113.6", 120)])
    assert len(f) == 1 and 30_000 < f[0]["speed_kmh"] < 50_000


def test_FP_shared_corporate_egress_two_colleagues_one_service_account():
    """A shared service account used by colleagues in two offices (London and
    Johannesburg) within minutes: flagged, though no one travelled."""
    f = run([ev("svc-deploy", "203.0.113.2", 0), ev("svc-deploy", "203.0.113.1", 180)])
    assert len(f) == 1 and f[0]["key"] == "svc-deploy"


def test_NOT_FP_nearby_vpn_exit_under_min_distance_is_quiet():
    """Counter-case: a VPN exit in the same metro area (~55 km) is NOT flagged."""
    assert run([ev("alice", "203.0.113.1", 0), ev("alice", "203.0.113.3", 120)]) == []