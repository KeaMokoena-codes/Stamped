"""Tests for the NormalizedEvent contract and schema (Issue #15)."""

import json
from pathlib import Path
import pytest

from schemas.normalized_event import NormalizedEvent, make_event_id, OUTCOMES


def test_normalized_event_creation():
    ev_id = make_event_id("evidence_abc", "line:10")
    event = NormalizedEvent(
        event_id=ev_id,
        evidence_id="evidence_abc",
        raw_ref="line:10",
        timestamp_utc="2026-10-12T20:00:00+00:00",
        event_type="auth",
        outcome="success",
        account="alice",
        source_ip="192.168.1.100",
        service="ssh",
    )
    assert event.event_id == ev_id
    assert event.outcome in OUTCOMES
    assert event.account == "alice"


def test_deterministic_event_id():
    id_1 = make_event_id("ev_1", "line:42")
    id_2 = make_event_id("ev_1", "line:42")
    id_diff = make_event_id("ev_1", "line:43")
    assert id_1 == id_2
    assert id_1 != id_diff


def test_invalid_outcome_raises():
    with pytest.raises(ValueError, match="outcome must be one of"):
        NormalizedEvent(
            event_id="test",
            evidence_id="ev_1",
            raw_ref="line:1",
            timestamp_utc="2026-10-12T20:00:00+00:00",
            event_type="auth",
            outcome="invalid_status",
        )


def test_sample_fixture_validates():
    fixture_path = Path(__file__).resolve().parent.parent / "data" / "sample" / "normalized_event_sample.json"
    assert fixture_path.exists(), "Sample fixture must exist per Issue #15 DoD"
    
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert len(data) >= 1
    for item in data:
        event = NormalizedEvent(**item)
        assert event.outcome in OUTCOMES