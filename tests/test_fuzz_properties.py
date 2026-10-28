"""Bounded generated-input checks for parsers and capture validation."""

from hypothesis import given, settings, strategies as st

from capture.listener import BundleError, Settings, parse_json, validate_bundle
from ingest.parsers.auth_log import parse_auth_log_bytes
from ingest.parsers.cloudtrail_json import parse_cloudtrail_bytes


@settings(max_examples=40, deadline=1000)
@given(st.binary(max_size=4096))
def test_auth_log_parser_is_deterministic_for_bounded_hostile_bytes(raw):
    first = parse_auth_log_bytes(raw, "synthetic-evidence")
    second = parse_auth_log_bytes(raw, "synthetic-evidence")
    assert first == second


@settings(max_examples=40, deadline=1000)
@given(st.binary(max_size=4096))
def test_cloudtrail_parser_is_deterministic_for_bounded_hostile_bytes(raw):
    first = parse_cloudtrail_bytes(raw, "synthetic-evidence")
    second = parse_cloudtrail_bytes(raw, "synthetic-evidence")
    assert first == second


@settings(max_examples=40, deadline=1000)
@given(st.binary(max_size=4096))
def test_listener_rejects_or_validates_bounded_json_without_writing(raw):
    try:
        payload = parse_json(raw)
        validate_bundle(payload, Settings())
    except BundleError as error:
        assert error.errors


def test_invalid_calendar_timestamp_is_reported_as_unparsed():
    raw = b"Feb 31 25:99:99 host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2\n"
    events, stats = parse_auth_log_bytes(raw, "synthetic-evidence")
    assert events == []
    assert stats["unparsed_lines"] == 1
