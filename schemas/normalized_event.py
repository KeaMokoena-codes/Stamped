"""
Normalized event schema (owned by Detect, consumed by Ingest and Detect).

This is a Python-level contract, NOT a database table: schemas/schema.sql is
frozen and has no events table. Ingest parsers must emit these fields.

Rules every parser must follow:
  * timestamp_utc is ISO 8601, timezone-aware, UTC (e.g. 2026-01-01T12:00:00+00:00).
  * event_id is deterministic: make_event_id(evidence_id, raw_ref).
  * raw_ref points at the exact line/offset in the sealed file.
  * outcome is one of OUTCOMES. Use "unknown" rather than guessing.
  * outcome means "did the LOGIN succeed or fail" ONLY when event_type is
    "auth". For any other event_type (e.g. "activity") it describes the
    action's own result (an API call that returned an error is not a failed
    login). Consumers MUST filter on event_type; login rules ignore
    everything that is not EVENT_TYPE_AUTH.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

OUTCOMES = ("success", "failure", "unknown")
EVENT_TYPE_AUTH = "auth"


def make_event_id(evidence_id: str, raw_ref: str) -> str:
    return hashlib.sha256(f"{evidence_id}:{raw_ref}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    evidence_id: str            # matches evidence.evidence_id
    raw_ref: str                # e.g. "line:1042" or "offset:88213"
    timestamp_utc: str
    event_type: str             # e.g. "auth"
    outcome: str                # "success" | "failure" | "unknown"
    account: Optional[str] = None
    source_ip: Optional[str] = None
    service: Optional[str] = None   # e.g. "ssh", "rdp", "web"

    def __post_init__(self):
        if self.outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {OUTCOMES}, got {self.outcome!r}")