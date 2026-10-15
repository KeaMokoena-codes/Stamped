"""Login rules must only consider login events (event_type == "auth").

Regression for a bug found by feeding the real CloudTrail parser into the rules:
failed non-login API calls looked like failed logins, and ordinary API calls from
two places looked like impossible travel.
"""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

from detect.rules import brute_force, impossible_travel
from detect.rules.brute_force import BruteForceConfig, detect
from detect.rules.impossible_travel import TravelConfig, detect_impossible_travel
from ingest.parsers.cloudtrail_json import parse_and_record_cloudtrail
from schemas.init_db import SCHEMA_PATH

BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
BF = BruteForceConfig(threshold=5, window_seconds=60, success_follow_seconds=60)
LONDON, NEW_YORK, JNB, PTA = (51.5, -0.12), (40.7, -74.0), (-26.2, 28.05), (-25.75, 28.23)
PLACES = {"1.1.1.1": LONDON, "2.2.2.2": NEW_YORK, "3.3.3.3": JNB, "4.4.4.4": PTA}
GEO_INFO = {"source": "fake.mmdb", "sha256": "f" * 64, "build_epoch": 1}


def geolocate(ip):
    return PLACES.get(ip)


_n = [0]


def ev(secs, outcome, event_type="auth", account="alice", ip="9.9.9.9"):
    _n[0] += 1
    d = {
        "event_id": f"ev{_n[0]}", "evidence_id": "E1", "raw_ref": f"line:{_n[0]}",
        "timestamp_utc": (BASE + timedelta(seconds=secs)).isoformat(),
        "outcome": outcome, "account": account, "source_ip": ip, "service": "x",
    }
    if event_type is not None:
        d["event_type"] = event_type
    return d


def travel(events):
    return detect_impossible_travel(events, TravelConfig(), geolocate, GEO_INFO)


# ------------------------------------------------------------- brute force
def test_failed_non_login_activity_is_not_a_failed_login():
    events = [ev(i, "failure", event_type="activity") for i in range(6)]
    assert detect(events, BF) == []


def test_events_without_event_type_are_ignored():
    events = [ev(i, "failure", event_type=None) for i in range(6)]
    assert detect(events, BF) == []


def test_activity_noise_does_not_change_a_real_finding():
    real = [ev(i, "failure") for i in range(5)]
    noise = [ev(i + 0.5, "failure", event_type="activity") for i in range(10)]
    clean, noisy = detect(real, BF), detect(real + noise, BF)
    assert clean == noisy
    assert all(s["event_id"].startswith("ev") for f in noisy for s in f["source_events"])
    assert {f["failure_count"] for f in noisy} == {5}


def test_activity_success_does_not_raise_severity():
    events = [ev(i, "failure") for i in range(5)] + [ev(20, "success", event_type="activity")]
    assert {f["severity"] for f in detect(events, BF)} == {"medium"}


def test_a_real_login_success_still_raises_severity():
    events = [ev(i, "failure") for i in range(5)] + [ev(20, "success")]
    assert {f["severity"] for f in detect(events, BF)} == {"high"}


def test_non_login_events_with_bad_timestamps_cannot_crash_the_rule():
    bad = ev(0, "failure", event_type="activity")
    bad["timestamp_utc"] = "2026-01-01T12:00:00"          # naive
    assert detect([bad] + [ev(i, "failure") for i in range(5)], BF)


# ------------------------------------------------------------ impossible travel
def test_ordinary_api_calls_from_two_places_are_not_impossible_travel():
    events = [ev(0, "success", "activity", ip="1.1.1.1"), ev(600, "success", "activity", ip="2.2.2.2")]
    assert travel(events) == []


def test_activity_between_two_logins_does_not_create_or_break_a_pair():
    near = [ev(0, "success", ip="3.3.3.3"), ev(3600, "success", ip="4.4.4.4")]      # JNB -> PTA
    far_activity = ev(1800, "success", "activity", ip="1.1.1.1")                    # London
    assert travel(near + [far_activity]) == []


def test_real_login_pair_is_still_flagged_with_activity_noise():
    logins = [ev(0, "success", ip="1.1.1.1"), ev(600, "success", ip="2.2.2.2")]
    noise = [ev(300, "success", "activity", ip="3.3.3.3")]
    assert len(travel(logins + noise)) == 1
    assert travel(logins + noise)[0]["finding_hash"] == travel(logins)[0]["finding_hash"]


def test_events_without_event_type_are_ignored_by_travel():
    assert travel([ev(0, "success", None, ip="1.1.1.1"), ev(600, "success", None, ip="2.2.2.2")]) == []


def test_rule_versions_were_bumped_for_the_behaviour_change():
    assert brute_force.RULE_VERSION == "1.1.0" and impossible_travel.RULE_VERSION == "1.1.0"


# ----------------------------------------- end to end with the REAL CloudTrail parser
def _record(minute, account, ip, name="GetObject", source="s3.amazonaws.com", error=None, login=None):
    r = {"userIdentity": {"type": "IAMUser", "userName": account},
         "eventTime": f"2026-10-12T10:{minute:02d}:00Z", "eventSource": source,
         "eventName": name, "sourceIPAddress": ip}
    if error:
        r["errorCode"] = error
    if login:
        r["responseElements"] = {"ConsoleLogin": login}
    return r


def _parse(tmp_path, records):
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    path = tmp_path / "ct.json"
    path.write_text(json.dumps({"Records": records}), encoding="utf-8")
    _, events, _ = parse_and_record_cloudtrail(conn, path, "evidence_ct")
    return events


def test_real_parser_non_login_activity_triggers_nothing(tmp_path):
    records = ([_record(i, "svc", "8.8.8.8", error="AccessDenied") for i in range(6)]
               + [_record(10, "alice", "1.1.1.1", name="ListBuckets"),
                  _record(20, "alice", "2.2.2.2", name="ListBuckets")])
    events = _parse(tmp_path, records)
    assert detect(events, BruteForceConfig(threshold=5, window_seconds=300)) == []
    assert travel(events) == []


def test_real_parser_actual_failed_console_logins_are_still_detected(tmp_path):
    records = [_record(i, "bob", "9.9.9.9", name="ConsoleLogin", source="signin.amazonaws.com",
                       error="Failed authentication", login="Failure") for i in range(5)]
    findings = detect(_parse(tmp_path, records), BruteForceConfig(threshold=5, window_seconds=300))
    assert {(f["grouped_by"], f["key"]) for f in findings} == {("account", "bob"), ("source_ip", "9.9.9.9")}