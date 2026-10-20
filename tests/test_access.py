import ast
import hashlib
import json
import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest

from access import data as access_data
from access import masking, roles
from access import (AccessDenied, AccessError, AccessLogError, Action, Pseudonymizer, PseudonymizerRequired,
                    Resource, Role, UnknownRoleError, authorize, can, export_custody_log, export_findings,
                    export_timeline, get_custody_log, get_evidence, get_findings, get_timeline, parse_role,
                    require, resolve_role)
from detect.findings import (detect_and_record, detect_large_access_and_record, detect_travel_and_record,
                             load_trigger_findings)
from detect.rules.brute_force import BruteForceConfig
from detect.rules.large_access import LargeAccessConfig
from seal.custody_log import append_entry, recompute_and_verify_chain, verify_chain_rows

REPO = Path(__file__).resolve().parent.parent
SCHEMA = (REPO / "schemas" / "schema.sql").read_text(encoding="utf-8")

EXAMINER, OFFICER, PROSECUTOR = Role.EXAMINER, Role.INVESTIGATING_OFFICER, Role.PROSECUTOR
ALL_ROLES = [EXAMINER, OFFICER, PROSECUTOR]
KEY = Pseudonymizer(b"test-key-0123456789abcdef-test-key")

# ---- canaries: values a restricted role must never receive -----------------------------------------------
ACCOUNTS = ["alice", "carol"]
IPS = ["9.9.9.9", "203.0.113.1", "203.0.113.2"]
COORDINATES = ["-26.2041", "28.0473", "51.5074", "-0.1278"]       # what was inferred about where an IP is
SEALED_PATH = "/srv/stamped/sealed/E1-secret-layout.log"
GEO_DB = "fake_geo_city.mmdb"
METADATA = "collector-notes-CANARY"
ORIGINAL_NAME = "alice_laptop.log"                                # a file name can name a person
ERROR_TEXT = "disk-failure-CANARY"
ATTEMPTED = "/home/examiner/incoming/CANARY.log"
PERSONAL = ACCOUNTS + IPS                                          # identifiers a prosecutor must not get
EXAMINER_INTERNAL = [SEALED_PATH, GEO_DB, METADATA, ERROR_TEXT, ATTEMPTED]   # also withheld from the officer

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)
H = 3600
BF = BruteForceConfig(threshold=5, window_seconds=60, success_follow_seconds=60)
LA = LargeAccessConfig(window_seconds=H, lookback_seconds=24 * H, min_history_seconds=12 * H,
                       min_baseline_events=5, z=3.0, min_bytes=1000)
GEO_INFO = {"source": GEO_DB, "sha256": "f" * 64, "build_epoch": 1}
PLACES = {"203.0.113.1": (-26.2041, 28.0473), "203.0.113.2": (51.5074, -0.1278)}
_n = [0]


def ev(secs, event_type, outcome, account="alice", ip="9.9.9.9", evid="E1", nbytes=None, base=BASE):
    _n[0] += 1
    d = {"event_id": f"ev{_n[0]:05d}", "evidence_id": evid, "raw_ref": f"line:{_n[0]}",
         "timestamp_utc": (base + timedelta(seconds=secs)).isoformat(), "event_type": event_type,
         "outcome": outcome, "account": account, "source_ip": ip, "service": "ssh"}
    if nbytes is not None:
        d["bytes_out"] = nbytes
    return d


def scenario_events():
    login_t = 30 * H
    baseline = [ev(6 * H + i * H + 1800, "data_access", "success", nbytes=[100, 200, 300, 200][i % 4])
                for i in range(24)]
    attack = ([ev(login_t - 50 + i * 10, "auth", "failure") for i in range(5)]
              + [ev(login_t, "auth", "success")])
    return baseline + attack + [ev(login_t + 600, "data_access", "success", nbytes=50_000)]


def travel_events():
    return [ev(0, "auth", "success", account="carol", ip="203.0.113.1", evid="E2"),
            ev(1800, "auth", "success", account="carol", ip="203.0.113.2", evid="E2")]


def seeded():
    """A database holding every kind of record that carries personal or examiner-only data."""
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT INTO evidence (evidence_id, content_hash, sealed_path, source, collector, original_name, "
        "captured_at, sealed_at, metadata_json) VALUES (?,?,?,?,?,?,?,?,?)",
        [("E1", "h1", SEALED_PATH, "webhook", "amir", ORIGINAL_NAME, "2026-03-01T00:00:00+00:00",
          "2026-03-01T00:01:00+00:00", json.dumps({"note": METADATA})),
         ("E2", "h2", "/srv/stamped/sealed/E2.log", "manual-upload", "amir", "cloudtrail.json",
          "2026-03-02T00:00:00+00:00", "2026-03-02T00:01:00+00:00", None)])
    conn.commit()
    events = scenario_events()
    detect_and_record(conn, events, BF)
    detect_travel_and_record(conn, travel_events(), lambda ip: PLACES.get(ip), GEO_INFO)
    detect_large_access_and_record(conn, events, load_trigger_findings(conn), LA)
    append_entry(conn, "amir", "examiner", "sealed", evidence_id="E1",
                 details={"content_hash": "h1", "sealed_path": SEALED_PATH})
    append_entry(conn, "ingest", "examiner", "seal_failed",
                 details={"reason": "read_error", "error": ERROR_TEXT, "attempted_path": ATTEMPTED})
    conn.commit()
    return conn, events + travel_events()


def blob(obj) -> str:
    return json.dumps(obj, sort_keys=True)


def all_keys(obj):
    """Every dictionary key anywhere inside a result."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from all_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from all_keys(item)


def count_log(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0]


def last_entries(conn, n=1):
    rows = conn.execute("SELECT actor, role, action, evidence_id, artifact_id, details_json FROM custody_log "
                        "ORDER BY entry_id DESC LIMIT ?", (n,)).fetchall()
    return rows[::-1]


def fetch_everything(conn, role, events):
    """Every dataset, through the public functions, for one role."""
    return {"evidence": get_evidence(conn, role, "tester", pseudonymizer=KEY),
            "findings": get_findings(conn, role, "tester", pseudonymizer=KEY),
            "timeline": get_timeline(conn, role, "tester", events, pseudonymizer=KEY),
            "custody": get_custody_log(conn, role, "tester", pseudonymizer=KEY)}


# =====================================================================================================
# Roles and the permissions matrix
# =====================================================================================================
def test_DOD_exactly_three_roles_are_defined():
    assert {r.value for r in Role} == {"examiner", "investigating_officer", "prosecutor"}


@pytest.mark.parametrize("bad", ["Prosecutor", " prosecutor", "prosecutor ", "PROSECUTOR", "admin", "", "root",
                                 None, 7, ["prosecutor"], "examiner\n", "detection_engine"])
def test_an_unrecognised_role_is_refused_never_defaulted(bad):
    with pytest.raises(UnknownRoleError):
        parse_role(bad)
    assert can(bad, Resource.FINDINGS, Action.VIEW) is False


EXPECTED = {   # the matrix, written out independently of access/roles.py
    ("examiner", "evidence"): {"view", "edit", "export"}, ("examiner", "timeline"): {"view", "export"},
    ("examiner", "findings"): {"view", "edit", "export"}, ("examiner", "custody_log"): {"view", "export"},
    ("investigating_officer", "evidence"): {"view"}, ("investigating_officer", "timeline"): {"view", "export"},
    ("investigating_officer", "findings"): {"view", "export"},
    ("investigating_officer", "custody_log"): {"view", "export"},
    ("prosecutor", "evidence"): {"view"}, ("prosecutor", "timeline"): {"view"},
    ("prosecutor", "findings"): {"view", "export"}, ("prosecutor", "custody_log"): {"view", "export"},
}


@pytest.mark.parametrize("role", ALL_ROLES)
@pytest.mark.parametrize("resource", list(Resource))
@pytest.mark.parametrize("action", list(Action))
def test_DOD_permissions_matrix_matches_the_written_policy_and_denies_everything_else(role, resource, action):
    expected = action.value in EXPECTED[(role.value, resource.value)]
    assert can(role, resource, action) is expected
    if expected:
        assert require(role, resource, action) is role
    else:
        with pytest.raises(AccessDenied):
            require(role, resource, action)


def test_nobody_can_edit_the_custody_log_or_the_timeline():
    for role in ALL_ROLES:
        assert not can(role, Resource.CUSTODY_LOG, Action.EDIT)
        assert not can(role, Resource.TIMELINE, Action.EDIT)


def test_only_the_examiner_can_edit_anything():
    editors = {(r.value, res.value) for r in ALL_ROLES for res in Resource if can(r, res, Action.EDIT)}
    assert editors == {("examiner", "evidence"), ("examiner", "findings")}


def test_a_resource_missing_from_the_matrix_is_denied():
    assert can(EXAMINER, "not-a-resource", Action.VIEW) is False


# =====================================================================================================
# GUARDRAIL 1: restricted fields are ABSENT from what the data functions return (no UI involved)
# =====================================================================================================
def test_canaries_exist_for_the_examiner_so_the_leak_tests_below_are_not_vacuous():
    conn, events = seeded()
    text = blob(fetch_everything(conn, EXAMINER, events))
    for canary in PERSONAL + COORDINATES + EXAMINER_INTERNAL + [ORIGINAL_NAME]:
        assert canary in text, f"canary {canary!r} never appears for the examiner; the test data is wrong"


@pytest.mark.parametrize("dataset", ["evidence", "findings", "timeline", "custody"])
def test_DOD_prosecutor_result_contains_no_personal_or_examiner_only_value(dataset):
    conn, events = seeded()
    text = blob(fetch_everything(conn, PROSECUTOR, events)[dataset])
    for canary in PERSONAL + COORDINATES + EXAMINER_INTERNAL + [ORIGINAL_NAME]:
        assert canary not in text, f"{canary!r} leaked to the prosecutor in {dataset}"


@pytest.mark.parametrize("dataset", ["evidence", "findings", "timeline", "custody"])
def test_officer_result_contains_no_examiner_only_value(dataset):
    conn, events = seeded()
    text = blob(fetch_everything(conn, OFFICER, events)[dataset])
    for canary in EXAMINER_INTERNAL:
        assert canary not in text, f"{canary!r} leaked to the officer in {dataset}"


def test_officer_does_receive_the_identifiers_they_need():
    conn, events = seeded()
    text = blob(fetch_everything(conn, OFFICER, events))
    for needed in PERSONAL + COORDINATES + [ORIGINAL_NAME]:
        assert needed in text


@pytest.mark.parametrize("dataset,examiner_only", [
    ("evidence", {"sealed_path", "metadata_json"}),
    ("findings", {"details_json", "geo_source"}),
    ("custody_log", {"details_json", "sealed_path", "attempted_path", "error"}),
])
@pytest.mark.parametrize("role", [OFFICER, PROSECUTOR])
def test_DOD_fields_flagged_examiner_only_are_absent_as_keys(dataset, examiner_only, role):
    """The flag lives in access/roles.py. The returned objects must not even contain the KEY."""
    flagged = roles.examiner_only_fields(dataset)
    assert examiner_only <= flagged, "the policy no longer flags a field this test expects to be examiner-only"
    conn, events = seeded()
    results = fetch_everything(conn, role, events)
    result = results["custody" if dataset == "custody_log" else dataset]
    assert not (set(all_keys(result)) & flagged)


def test_DOD_extra_fields_the_query_returns_are_still_not_shown_to_restricted_roles():
    """'even if the underlying query would otherwise include them': make the SQL layer return extra
    columns and nested keys, and check they do not get through."""
    original = access_data._rows

    def leaky(conn, table, columns, where, params, order):
        rows = original(conn, table, columns, where, params, order)
        for row in rows:
            row.update({"sealed_path": SEALED_PATH, "metadata_json": METADATA, "internal_note": "TOP-SECRET",
                        "original_name": ORIGINAL_NAME, "details_json": row.get("details_json")})
            if isinstance(row.get("details"), dict):
                row["details"]["api_token"] = "TOP-SECRET"
        return rows

    conn, events = seeded()
    with mock.patch.object(access_data, "_rows", side_effect=leaky):
        for role in (OFFICER, PROSECUTOR):
            text = blob([get_evidence(conn, role, "t", pseudonymizer=KEY),
                         get_findings(conn, role, "t", pseudonymizer=KEY),
                         get_custody_log(conn, role, "t", pseudonymizer=KEY)])
            for canary in ("TOP-SECRET", SEALED_PATH, METADATA, "internal_note", "api_token"):
                assert canary not in text, f"{canary!r} reached {role.value}"
        assert ORIGINAL_NAME not in blob(get_evidence(conn, PROSECUTOR, "t", pseudonymizer=KEY))
        assert "TOP-SECRET" in blob(get_evidence(conn, EXAMINER, "t"))       # the examiner is not restricted


def test_columns_a_role_may_not_see_are_not_even_selected_from_the_database():
    conn, _ = seeded()
    statements = []
    conn.set_trace_callback(statements.append)
    get_evidence(conn, PROSECUTOR, "t", pseudonymizer=KEY)
    evidence_sql = " ".join(s for s in statements if "FROM evidence" in s)
    assert "sealed_path" not in evidence_sql and "metadata_json" not in evidence_sql
    assert "original_name" not in evidence_sql
    statements.clear()
    get_evidence(conn, EXAMINER, "t")
    assert "sealed_path" in " ".join(s for s in statements if "FROM evidence" in s)


def test_an_unknown_key_inside_stored_details_is_dropped_for_restricted_roles_but_kept_for_the_examiner():
    conn, _ = seeded()
    conn.execute("INSERT INTO findings (finding_id, source_evidence_id, artifact_id, rule_id, severity, title, "
                 "description, created_at, details_json) VALUES ('FX','E1',NULL,'future_rule@1','low','t','d',"
                 "'2026-03-03T00:00:00+00:00', ?)",
                 (json.dumps({"api_token": "TOP-SECRET", "nested": {"who": "alice"}, "severity": "low"}),))
    conn.commit()
    for role in (OFFICER, PROSECUTOR):
        row = get_findings(conn, role, "t", finding_id="FX", pseudonymizer=KEY)[0]
        assert "api_token" not in row["details"] and "nested" not in row["details"]
        assert "TOP-SECRET" not in blob(row) and "alice" not in blob(row)
    exam = get_findings(conn, EXAMINER, "t", finding_id="FX")[0]
    assert exam["details"]["api_token"] == "TOP-SECRET"


def test_a_nested_value_where_a_plain_one_was_expected_is_not_passed_through():
    conn, _ = seeded()
    conn.execute("INSERT INTO findings (finding_id, source_evidence_id, artifact_id, rule_id, severity, title, "
                 "description, created_at, details_json) VALUES ('FY','E1',NULL,'future_rule@1','low','t','d',"
                 "'2026-03-03T00:00:00+00:00', ?)",
                 (json.dumps({"grouped_by": "account", "key": {"user": "alice", "ip": "9.9.9.9"}}),))
    conn.commit()
    for role in (OFFICER, PROSECUTOR):
        row = get_findings(conn, role, "t", finding_id="FY", pseudonymizer=KEY)[0]
        assert "key" not in row["details"]


def test_findings_that_embed_whole_triggering_findings_are_masked_all_the_way_down():
    conn, _ = seeded()
    rows = get_findings(conn, PROSECUTOR, "t", pseudonymizer=KEY)
    large = [r for r in rows if r["rule_id"].startswith("large_access")][0]
    triggers = large["details"]["triggered_by"]
    assert triggers, "the large-access finding should embed the findings that triggered it"
    for trigger in triggers:
        assert trigger["key"].startswith(("acct-", "ip-"))
        assert "alice" not in blob(trigger) and "9.9.9.9" not in blob(trigger)


def test_a_finding_keyed_by_ip_address_gets_an_ip_token_not_an_account_token():
    conn, _ = seeded()
    rows = get_findings(conn, PROSECUTOR, "t", pseudonymizer=KEY)
    by_ip = [r for r in rows if r["details"].get("grouped_by") == "source_ip"]
    by_account = [r for r in rows if r["details"].get("grouped_by") == "account"]
    assert by_ip and by_account
    assert all(r["details"]["key"].startswith("ip-") for r in by_ip)
    assert all(r["details"]["key"].startswith("acct-") for r in by_account)


def test_prosecutor_keeps_what_the_case_needs_while_identifiers_are_replaced():
    conn, _ = seeded()
    rows = get_findings(conn, PROSECUTOR, "t", pseudonymizer=KEY)
    travel = [r for r in rows if r["rule_id"].startswith("impossible_travel")][0]
    assert travel["details"]["distance_km"] > 1000 and travel["details"]["elapsed_seconds"] == 1800
    assert travel["details"]["input_hash"]          # integrity information stays visible to every role
    assert all("lat" not in login and "lon" not in login for login in travel["details"]["logins"])
    assert all(login["source_ip"].startswith("ip-") for login in travel["details"]["logins"])
    assert "km" in travel["title"]


def test_timeline_marks_events_and_findings_and_is_masked_for_the_prosecutor():
    conn, events = seeded()
    rows = get_timeline(conn, PROSECUTOR, "t", events, pseudonymizer=KEY)
    assert {r["entry_type"] for r in rows} == {"event", "finding"}
    assert all(r["account"] is None or r["account"].startswith("acct-") for r in rows)
    assert all("raw_ref" in r["provenance"] or "finding_id" in r["provenance"] for r in rows)


def test_a_key_the_event_parser_never_defined_is_not_shown_to_the_officer_or_prosecutor():
    conn, events = seeded()
    events = events + [dict(events[0], event_id="evX", raw_ref="line:999", password_hint="hunter2")]
    for role in (OFFICER, PROSECUTOR):
        assert "hunter2" not in blob(get_timeline(conn, role, "t", events, pseudonymizer=KEY))
    assert "hunter2" in blob(get_timeline(conn, EXAMINER, "t", events))


def test_timeline_can_be_limited_to_one_item_of_evidence():
    conn, events = seeded()
    rows = get_timeline(conn, EXAMINER, "t", events, evidence_id="E2")
    assert rows and all("E1" not in blob(r["provenance"].get("evidence_id", "")) for r in rows)
    assert not any(r["entry_type"] == "event" and r["provenance"]["evidence_id"] != "E2" for r in rows)


def test_examiner_view_of_the_custody_log_is_complete_enough_to_recompute_the_chain():
    conn, _ = seeded()
    rows = get_custody_log(conn, EXAMINER, "t")
    tuples = [(r["entry_id"], r["timestamp_utc"], r["actor"], r["role"], r["action"], r["evidence_id"],
               r["artifact_id"], r["details_json"], r["prev_hash"], r["entry_hash"]) for r in rows]
    assert verify_chain_rows(tuples) == (True, None)


def test_LIMITATION_masked_custody_view_cannot_be_used_to_recompute_the_chain():
    """Restricted roles get the parsed, projected details, not the raw text the hash covers. Verifying
    the chain is what verifier/verify.py does on a full case package, not on a role view."""
    conn, _ = seeded()
    assert all("details_json" not in r for r in get_custody_log(conn, PROSECUTOR, "t", pseudonymizer=KEY))


# =====================================================================================================
# Pseudonyms
# =====================================================================================================
def test_the_same_identifier_always_gets_the_same_token_and_different_ones_differ():
    conn, events = seeded()
    findings = get_findings(conn, PROSECUTOR, "t", pseudonymizer=KEY)
    timeline = get_timeline(conn, PROSECUTOR, "t", events, pseudonymizer=KEY)
    alice_tokens = {r["details"]["key"] for r in findings if r["details"].get("grouped_by") == "account"
                    and r["rule_id"].startswith(("brute_force", "large_access")) and "alice" not in r["title"]}
    timeline_accounts = {r["account"] for r in timeline if r["account"]}
    assert KEY.token("account", "alice") in alice_tokens | timeline_accounts
    assert KEY.token("account", "alice") != KEY.token("account", "carol")
    assert KEY.token("account", "alice") != KEY.token("ip", "alice")        # a person and an address never collide


def test_tokens_depend_on_the_secret_key():
    other = Pseudonymizer(b"a-different-secret-key-0123456789")
    assert KEY.token("ip", "9.9.9.9") != other.token("ip", "9.9.9.9")


def test_two_spellings_of_the_same_ip_address_give_the_same_token():
    assert KEY.token("ip", "::ffff:9.9.9.9") != "" and KEY.token("ip", "2001:db8::1") == KEY.token("ip", "2001:0db8:0:0:0:0:0:1")


def test_a_pseudonym_key_is_required_and_there_is_no_unkeyed_fallback():
    conn, events = seeded()
    before = count_log(conn)
    with pytest.raises(PseudonymizerRequired):
        get_findings(conn, PROSECUTOR, "t")
    with pytest.raises(PseudonymizerRequired):
        get_timeline(conn, PROSECUTOR, "t", events)
    assert count_log(conn) == before, "a refused configuration error must not be recorded as a data access"
    get_findings(conn, OFFICER, "t")       # roles that get real identifiers need no key
    get_findings(conn, EXAMINER, "t")


def test_a_short_key_is_rejected():
    with pytest.raises(ValueError):
        Pseudonymizer(b"short")
    with pytest.raises(ValueError):
        Pseudonymizer("not-bytes-but-long-enough-text")


def test_key_files_are_created_private_and_never_overwritten(tmp_path):
    path = tmp_path / "keys" / "pseudonym.key"
    Pseudonymizer.generate_key_file(path)
    assert len(path.read_bytes()) == 32
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        Pseudonymizer.generate_key_file(path)
    assert Pseudonymizer.from_key_file(path).token("ip", "1.2.3.4").startswith("ip-")


# =====================================================================================================
# Free text
# =====================================================================================================
def _finding_with_text(conn, finding_id, title, description, details=None):
    conn.execute("INSERT INTO findings (finding_id, source_evidence_id, artifact_id, rule_id, severity, title, "
                 "description, created_at, details_json) VALUES (?,?,NULL,'future_rule@1','low',?,?,"
                 "'2026-03-03T00:00:00+00:00', ?)", (finding_id, "E1", title, description, json.dumps(details or {})))
    conn.commit()


def test_any_ip_address_in_free_text_is_removed_even_when_no_field_names_it():
    conn, _ = seeded()
    _finding_with_text(conn, "T1", "Login from 198.51.100.7", "Also seen: 2001:db8::7, and at 12:30:45 UTC. 198.51.100.7.")
    row = get_findings(conn, PROSECUTOR, "t", finding_id="T1", pseudonymizer=KEY)[0]
    text = blob(row)
    assert "198.51.100.7" not in text and "2001:db8::7" not in text
    assert "12:30:45" in row["description"], "a clock time is not an address and must be left alone"
    assert row["title"].count("ip-") == 1
    assert row["description"].count("ip-") == 2        # 2001:db8::7 and 198.51.100.7; the clock time is untouched


def test_an_account_named_in_the_title_is_replaced_by_the_same_token_as_in_the_structured_field():
    conn, _ = seeded()
    _finding_with_text(conn, "T2", "Account dave-admin locked out", "dave-admin tried 9 times.",
                       {"grouped_by": "account", "key": "dave-admin"})
    row = get_findings(conn, PROSECUTOR, "t", finding_id="T2", pseudonymizer=KEY)[0]
    token = KEY.token("account", "dave-admin")
    assert row["details"]["key"] == token and token in row["title"] and token in row["description"]
    assert "dave-admin" not in blob(row)


@pytest.mark.parametrize("risky", ["1", "ab", "for", "high", "42"])
def test_an_identifier_that_cannot_be_masked_safely_inside_a_sentence_withholds_the_sentence(risky):
    conn, _ = seeded()
    _finding_with_text(conn, "T3", f"5 failed logins for account {risky}", f"{risky} failures in 60s.",
                       {"grouped_by": "account", "key": risky})
    row = get_findings(conn, PROSECUTOR, "t", finding_id="T3", pseudonymizer=KEY)[0]
    assert row["title"] == masking.WITHHELD_TEXT and row["description"] == masking.WITHHELD_TEXT
    assert row["details"]["key"].startswith("acct-")


def test_an_account_name_is_not_replaced_inside_a_longer_word():
    conn, _ = seeded()
    _finding_with_text(conn, "T4", "carolina visited by carol", "x", {"grouped_by": "account", "key": "carol"})
    title = get_findings(conn, PROSECUTOR, "t", finding_id="T4", pseudonymizer=KEY)[0]["title"]
    assert title.startswith("carolina visited by acct-")


# =====================================================================================================
# GUARDRAIL 2: reads and exports are custody entries
# =====================================================================================================
READS = {
    "evidence": (lambda c, r, e: get_evidence(c, r, "tester", pseudonymizer=KEY), "viewed_evidence"),
    "findings": (lambda c, r, e: get_findings(c, r, "tester", pseudonymizer=KEY), "viewed_findings"),
    "timeline": (lambda c, r, e: get_timeline(c, r, "tester", e, pseudonymizer=KEY), "viewed_timeline"),
    "custody_log": (lambda c, r, e: get_custody_log(c, r, "tester", pseudonymizer=KEY), "viewed_custody_log"),
}


@pytest.mark.parametrize("role", ALL_ROLES)
@pytest.mark.parametrize("dataset", list(READS))
def test_DOD_every_view_is_logged_as_a_custody_entry_even_though_it_changes_nothing(role, dataset):
    conn, events = seeded()
    before = count_log(conn)
    func, action = READS[dataset]
    func(conn, role, events)
    assert count_log(conn) == before + 1, "a READ must leave a custody entry (not only writes)"
    actor, logged_role, logged_action, *_ = last_entries(conn)[0]
    assert (actor, logged_role, logged_action) == ("tester", role.value, action)
    assert recompute_and_verify_chain(conn) == (True, None)


EXPORTS = {
    "findings": (lambda c, r, e: export_findings(c, r, "tester", pseudonymizer=KEY), "exported_findings"),
    "timeline": (lambda c, r, e: export_timeline(c, r, "tester", e, pseudonymizer=KEY), "exported_timeline"),
    "custody_log": (lambda c, r, e: export_custody_log(c, r, "tester", pseudonymizer=KEY), "exported_custody_log"),
}


@pytest.mark.parametrize("role", ALL_ROLES)
@pytest.mark.parametrize("dataset", list(EXPORTS))
def test_DOD_every_permitted_export_is_logged_with_the_hash_of_what_was_handed_over(role, dataset):
    conn, events = seeded()
    resource = Resource(dataset)
    func, action = EXPORTS[dataset]
    if not can(role, resource, Action.EXPORT):
        with pytest.raises(AccessDenied):
            func(conn, role, events)
        return
    before = count_log(conn)
    result = func(conn, role, events)
    assert count_log(conn) == before + 1
    actor, logged_role, logged_action, _, _, details = last_entries(conn)[0]
    assert (actor, logged_role, logged_action) == ("tester", role.value, action)
    logged = json.loads(details)
    assert logged["export_sha256"] == result.sha256 == hashlib.sha256(result.content.encode("utf-8")).hexdigest()
    assert logged["count"] == result.row_count == len(json.loads(result.content)["rows"])
    assert json.loads(result.content)["role"] == role.value


@pytest.mark.parametrize("dataset", list(EXPORTS))
def test_prosecutor_export_contains_no_personal_or_examiner_only_value(dataset):
    conn, events = seeded()
    if not can(PROSECUTOR, Resource(dataset), Action.EXPORT):
        return
    text = EXPORTS[dataset][0](conn, PROSECUTOR, events).content
    for canary in PERSONAL + COORDINATES + EXAMINER_INTERNAL + [ORIGINAL_NAME]:
        assert canary not in text


def test_a_filtered_view_records_the_filter_and_the_evidence_it_concerned():
    conn, _ = seeded()
    get_findings(conn, OFFICER, "tester", evidence_id="E1")
    _, _, action, evidence_id, _, details = last_entries(conn)[0]
    assert action == "viewed_findings" and evidence_id == "E1"
    assert json.loads(details)["filters"] == {"evidence_id": "E1"}


def test_viewing_a_single_finding_is_recorded_against_that_finding():
    conn, _ = seeded()
    fid = get_findings(conn, EXAMINER, "tester")[0]["finding_id"]
    get_findings(conn, EXAMINER, "tester", finding_id=fid)
    assert last_entries(conn)[0][4] == fid


def test_DOD_no_identifier_ever_reaches_the_custody_log_through_an_access_entry():
    """The log is append-only and cannot be corrected, so personal data must never be written to it."""
    conn, events = seeded()
    start = count_log(conn)
    for role in ALL_ROLES:
        fetch_everything(conn, role, events)
        for dataset, (func, _) in EXPORTS.items():
            if can(role, Resource(dataset), Action.EXPORT):
                func(conn, role, events)
    rows = conn.execute("SELECT action, details_json FROM custody_log WHERE entry_id > ?", (start,)).fetchall()
    assert len(rows) >= 12 + 8      # 4 views x 3 roles, plus the permitted exports
    text = " ".join(f"{a} {d}" for a, d in rows)
    for canary in PERSONAL + COORDINATES + [SEALED_PATH, ORIGINAL_NAME, GEO_DB]:
        assert canary not in text


def test_the_audit_trail_grows_by_exactly_one_entry_per_access_and_stays_verifiable():
    conn, events = seeded()
    start = count_log(conn)
    for _ in range(3):
        fetch_everything(conn, PROSECUTOR, events)
    assert count_log(conn) == start + 12
    assert recompute_and_verify_chain(conn) == (True, None)


# ---- denials ---------------------------------------------------------------------------------------
def test_DOD_a_refused_request_returns_nothing_and_is_itself_logged():
    conn, events = seeded()
    before = count_log(conn)
    with pytest.raises(AccessDenied):
        export_timeline(conn, PROSECUTOR, "mallory", events, pseudonymizer=KEY)
    assert count_log(conn) == before + 1
    actor, role, action, _, _, details = last_entries(conn)[0]
    assert (actor, role, action) == ("mallory", "prosecutor", "access_denied")
    assert json.loads(details) == {"action": "export", "reason": "not_permitted", "resource": "timeline"}


def test_an_unknown_role_is_refused_and_logged_without_trusting_the_claimed_role():
    conn, _ = seeded()
    with pytest.raises(UnknownRoleError):
        get_findings(conn, "God", "mallory")
    actor, role, action, _, _, details = last_entries(conn)[0]
    assert (actor, role, action) == ("mallory", "invalid", "access_denied")
    assert json.loads(details)["attempted_role"] == "God"


def test_a_very_long_claimed_role_is_truncated_in_the_log():
    conn, _ = seeded()
    with pytest.raises(UnknownRoleError):
        get_findings(conn, "x" * 5000, "mallory")
    assert len(json.loads(last_entries(conn)[0][5])["attempted_role"]) == 64


def test_authorize_is_the_gate_for_write_paths_too():
    conn, _ = seeded()
    assert authorize(conn, "ash", "examiner", Resource.FINDINGS, Action.EDIT) is EXAMINER
    with pytest.raises(AccessDenied):
        authorize(conn, "pat", "prosecutor", Resource.FINDINGS, Action.EDIT)
    assert last_entries(conn)[0][2] == "access_denied"


# ---- fail closed -----------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["get_findings", "get_evidence", "get_custody_log"])
def test_DOD_if_the_custody_entry_cannot_be_written_no_data_is_returned(name):
    conn, _ = seeded()
    before = count_log(conn)
    with mock.patch.object(access_data, "append_entry", side_effect=sqlite3.OperationalError("disk full")):
        with pytest.raises(AccessLogError):
            getattr(access_data, name)(conn, EXAMINER, "tester")
    assert count_log(conn) == before


def test_if_the_export_entry_cannot_be_written_the_export_is_not_released():
    conn, _ = seeded()
    with mock.patch.object(access_data, "append_entry", side_effect=sqlite3.OperationalError("disk full")):
        with pytest.raises(AccessLogError):
            export_findings(conn, PROSECUTOR, "tester", pseudonymizer=KEY)


def test_a_refusal_is_still_a_refusal_when_the_denial_itself_cannot_be_logged():
    conn, events = seeded()
    with mock.patch.object(access_data, "append_entry", side_effect=sqlite3.OperationalError("disk full")):
        with pytest.raises(AccessDenied):
            export_timeline(conn, PROSECUTOR, "mallory", events, pseudonymizer=KEY)


def test_a_read_only_connection_cannot_read_because_the_read_could_not_be_recorded(tmp_path):
    path = tmp_path / "case.db"
    conn, _ = seeded()
    disk = sqlite3.connect(path)
    conn.backup(disk)
    disk.close()
    readonly = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    with pytest.raises(AccessLogError):
        get_findings(readonly, EXAMINER, "tester")


def test_refuses_to_run_inside_a_transaction_the_caller_opened():
    conn, _ = seeded()
    conn.execute("BEGIN")
    with pytest.raises(AccessError):
        get_findings(conn, EXAMINER, "tester")
    conn.rollback()


@pytest.mark.parametrize("actor", ["", "   ", None, 5])
def test_an_access_with_no_named_actor_is_refused_and_nothing_is_recorded(actor):
    conn, _ = seeded()
    before = count_log(conn)
    with pytest.raises(ValueError):
        get_findings(conn, EXAMINER, actor)
    assert count_log(conn) == before


def test_filters_must_be_strings_and_are_never_interpolated_into_sql():
    conn, _ = seeded()
    with pytest.raises(TypeError):
        get_findings(conn, EXAMINER, "t", evidence_id=123)
    assert get_findings(conn, EXAMINER, "t", evidence_id="E1' OR '1'='1") == []
    assert get_evidence(conn, EXAMINER, "t", evidence_id="E1'; DROP TABLE evidence; --") == []
    assert conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 2


# ---- binding a login to a role ---------------------------------------------------------------------
def _user(conn, user_id, role, active=1):
    conn.execute("INSERT INTO users (user_id, display_name, role, created_at, active) VALUES (?,?,?,?,?)",
                 (user_id, user_id.title(), role, "2026-01-01T00:00:00+00:00", active))
    conn.commit()


def test_resolve_role_reads_the_role_from_the_users_table():
    conn, _ = seeded()
    _user(conn, "pat", "prosecutor")
    assert resolve_role(conn, "pat") is PROSECUTOR


@pytest.mark.parametrize("case", ["unknown_user", "inactive_user", "unknown_role"])
def test_resolve_role_refuses_unknown_inactive_and_misconfigured_users_and_logs_it(case):
    conn, _ = seeded()
    _user(conn, "old", "examiner", active=0)
    _user(conn, "odd", "Administrator")
    who = {"unknown_user": "ghost", "inactive_user": "old", "unknown_role": "odd"}[case]
    with pytest.raises(AccessError):
        resolve_role(conn, who)
    assert json.loads(last_entries(conn)[0][5])["reason"] == case


# =====================================================================================================
# Policy and documentation stay in step; the UI stays out of the database
# =====================================================================================================
def test_every_listed_field_is_documented():
    doc = (REPO / "docs" / "access-control.md").read_text(encoding="utf-8")
    missing = [f"{dataset}: {path}" for dataset, path, *_ in roles.policy_table() if f"`{path}`" not in doc]
    assert not missing, f"docs/access-control.md does not mention: {missing}"


def test_the_policy_table_is_the_source_of_what_the_prosecutor_is_not_shown():
    table = {(d, p): (e, o, pr) for d, p, e, o, pr in roles.policy_table()}
    assert table[("evidence", "sealed_path")] == ("full", "hidden", "hidden")
    assert table[("evidence", "original_name")] == ("full", "full", "hidden")
    assert table[("findings", "details.key")] == ("full", "full", "pseudonym")
    assert table[("findings", "details.logins[].lat")] == ("full", "full", "hidden")


UI_CANDIDATES = ["app", "ui", "dashboard", "frontend", "pages", "streamlit_app", "app.py", "streamlit_app.py",
                 "dashboard.py"]
FORBIDDEN_UI_IMPORTS = {"sqlite3", "pandas"}
FORBIDDEN_UI_CALLS = {"execute", "executemany", "read_sql", "read_sql_query"}
FORBIDDEN_UI_QUERIES = ("FROM findings", "FROM evidence", "FROM custody_log")


def _ui_database_violations(source, display_name):
    tree = ast.parse(source)
    imported = {
        node.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for node in node.names
    }
    imported.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    direct_db_calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    direct_db_calls.update(
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    )
    violations = [
        f"{display_name}: imports {module}"
        for module in imported & FORBIDDEN_UI_IMPORTS
    ]
    violations.extend(
        f"{display_name}: calls {call}"
        for call in direct_db_calls & FORBIDDEN_UI_CALLS
    )
    violations.extend(
        f"{display_name}: embeds SQL {query!r}"
        for query in FORBIDDEN_UI_QUERIES
        if query in source
    )
    return violations


@pytest.mark.parametrize(
    "source",
    [
        "import sqlite3\nconn = sqlite3.connect('case.db')\n",
        "import sqlite3\nconn.execute('SELECT * FROM evidence')\n",
        "from pandas import read_sql\n",
        "rows = read_sql_query('SELECT * FROM findings', conn)\n",
    ],
)
def test_ui_database_guardrail_rejects_direct_database_access(source):
    assert _ui_database_violations(source, "example.py")


def test_ui_database_guardrail_allows_access_layer_calls_and_documentation():
    source = (
        "from access import get_custody_log\n"
        "rows = get_custody_log(conn, role, actor)\n"
        "# custody_log is a dataset exposed through access functions.\n"
    )
    assert _ui_database_violations(source, "example.py") == []


def test_DOD_the_ui_reads_case_data_only_through_the_access_layer():
    """Starts working the moment the Streamlit code lands: it must not touch the database itself."""
    found = [REPO / name for name in UI_CANDIDATES if (REPO / name).exists()]
    if not found:
        pytest.skip("no UI code in this repository yet; this test activates when it is added")
    offenders = []
    for target in found:
        files = [target] if target.is_file() else list(target.rglob("*.py"))
        for file in files:
            source = file.read_text(encoding="utf-8", errors="ignore")
            offenders.extend(
                _ui_database_violations(source, str(file.relative_to(REPO)))
            )
    assert not offenders, f"UI code must call access.* instead of querying the database: {offenders}"


def test_the_access_layer_itself_does_not_import_the_ui():
    for file in (REPO / "access").glob("*.py"):
        tree = ast.parse(file.read_text())
        imported = {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        imported |= {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not imported & {"streamlit", "pandas", "flask"}, file.name