"""
Authentication Log Parser (Issue #16).
Parses standard OpenSSH / Linux auth.log files into NormalizedEvent structures.
Registers the parsed output into the 'artifacts' table and records a custody entry.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from detect.canon import canonical_hash, canonical_json
from schemas.normalized_event import NormalizedEvent, make_event_id
from seal.custody_log import append_entry

TOOL_NAME = "auth_log_parser"
TOOL_VERSION = "1.0.0"

MONTHS: Dict[str, int] = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

LINE_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)


def parse_auth_line(
    raw_line: str,
    line_number: int,
    evidence_id: str,
    base_year: int,
) -> Tuple[Optional[NormalizedEvent], bool]:
    """
    Parses a single auth.log line into a NormalizedEvent.
    Returns (event, is_unparsed_line).
    """
    match = LINE_RE.match(raw_line)
    if not match:
        return None, True

    month_str = match.group("mon")
    if month_str not in MONTHS:
        return None, True

    month = MONTHS[month_str]
    day = int(match.group("day"))
    time_parts = [int(p) for p in match.group("time").split(":")]
    msg = match.group("msg")

    outcome = "unknown"
    account = None
    source_ip = None

    fail_m = FAILED_RE.match(msg)
    if fail_m:
        outcome = "failure"
        account = fail_m.group("user")
        source_ip = fail_m.group("ip")
    else:
        acc_m = ACCEPTED_RE.match(msg)
        if acc_m:
            outcome = "success"
            account = acc_m.group("user")
            source_ip = acc_m.group("ip")
        else:
            # Informational sshd connections or pam messages: safely ignored
            return None, False

    dt = datetime(
        base_year, month, day, time_parts[0], time_parts[1], time_parts[2], tzinfo=timezone.utc
    )
    raw_ref = f"line:{line_number}"
    event_id = make_event_id(evidence_id, raw_ref)

    event = NormalizedEvent(
        event_id=event_id,
        evidence_id=evidence_id,
        raw_ref=raw_ref,
        timestamp_utc=dt.isoformat(),
        event_type="auth",
        outcome=outcome,
        account=account,
        source_ip=source_ip,
        service="ssh",
    )
    return event, False


def parse_and_record_auth_log(
    conn: sqlite3.Connection,
    file_path: Path | str,
    source_evidence_id: str,
    base_year: int = 2026,
    actor: str = "ingest",
    role: str = "examiner",
) -> Tuple[str, List[NormalizedEvent], Dict[str, int]]:
    """
    Parses an authentication log file, inserts an entry into the 'artifacts'
    table with its provenance link, and appends a record to the custody log.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Auth log file not found: {path}")

    raw_bytes = path.read_bytes()
    # Direct cryptographic SHA-256 over raw input file bytes
    input_hash = hashlib.sha256(raw_bytes).hexdigest()

    lines = raw_bytes.decode("utf-8", errors="replace").splitlines()
    events: List[NormalizedEvent] = []
    unparsed_lines = 0

    for idx, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        event, is_unparsed = parse_auth_line(line, idx, source_evidence_id, base_year)
        if is_unparsed:
            unparsed_lines += 1
        elif event is not None:
            events.append(event)

    # Deterministic output serialization for artifact hashing
    serialized_events = [asdict(e) for e in events]
    output_hash = canonical_hash(serialized_events)
    artifact_id = f"art-{output_hash[:16]}"

    stats = {
        "total_lines": len(lines),
        "parsed_events": len(events),
        "unparsed_lines": unparsed_lines,
    }

    now_utc = datetime.now(timezone.utc).isoformat()
    metadata_json = canonical_json(stats)

    # 1. Register the derived artifact in the database
    conn.execute(
        """
        INSERT INTO artifacts (
            artifact_id, source_evidence_id, source_artifact_id,
            tool_name, tool_version, created_at, input_hash,
            output_hash, metadata_json
        ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?)
        """,
        (
            artifact_id,
            source_evidence_id,
            TOOL_NAME,
            TOOL_VERSION,
            now_utc,
            input_hash,
            output_hash,
            metadata_json,
        ),
    )

    # 2. Append an entry to the hash-chained custody log
    append_entry(
        conn=conn,
        actor=actor,
        role=role,
        action="parsed_auth_log",
        evidence_id=source_evidence_id,
        artifact_id=artifact_id,
        details={
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "events_count": len(events),
            "unparsed_count": unparsed_lines,
        },
    )

    return artifact_id, events, stats