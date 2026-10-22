"""
AWS CloudTrail JSON Log Parser (Issue #17 & Issue #18 validation updates).
Parses standard CloudTrail JSON bundles, CloudWatch Logs subscription payloads,
EventBridge wrappers, or NDJSON into NormalizedEvent structures.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from detect.canon import canonical_hash, canonical_json
from schemas.normalized_event import NormalizedEvent, make_event_id
from seal.custody_log import append_entry

TOOL_NAME = "cloudtrail_json_parser"
TOOL_VERSION = "1.1.0"


def _extract_account(user_identity: Dict[str, Any]) -> Optional[str]:
    """Extracts a stable username or identifier from CloudTrail userIdentity."""
    if not isinstance(user_identity, dict):
        return None
    if user_identity.get("userName"):
        return str(user_identity["userName"])
    if user_identity.get("arn"):
        return str(user_identity["arn"])
    if user_identity.get("principalId"):
        return str(user_identity["principalId"])
    if user_identity.get("accountId"):
        return str(user_identity["accountId"])
    return None


def _parse_timestamp(raw_ts: str) -> str:
    """Parses CloudTrail ISO 8601 timestamps and returns normalized UTC format."""
    clean_ts = str(raw_ts).strip().replace("Z", "+00:00")
    if " " in clean_ts and "T" not in clean_ts:
        clean_ts = clean_ts.replace(" ", "T", 1)
    dt = datetime.fromisoformat(clean_ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def parse_cloudtrail_record(
    record: Dict[str, Any],
    record_idx: int,
    evidence_id: str,
) -> Tuple[Optional[NormalizedEvent], bool]:
    """
    Parses a single CloudTrail record into a NormalizedEvent.
    Returns (event, is_unparsed).
    """
    if not isinstance(record, dict):
        return None, True

    # Unwrap EventBridge CloudTrail envelope if present
    if "detail" in record and isinstance(record["detail"], dict) and "eventTime" in record["detail"]:
        record = record["detail"]

    if "eventTime" not in record:
        return None, True

    try:
        ts_utc = _parse_timestamp(record["eventTime"])
    except Exception:
        return None, True

    raw_ref = f"record:{record_idx}"
    event_id = make_event_id(evidence_id, raw_ref)

    user_ident = record.get("userIdentity") or {}
    account = _extract_account(user_ident)
    raw_ip = record.get("sourceIPAddress")
    source_ip = str(raw_ip).strip() if raw_ip and str(raw_ip).strip() else None
    service = str(record.get("eventSource") or "aws")
    event_name = str(record.get("eventName") or "")

    has_error = bool(record.get("errorCode") or record.get("errorMessage"))
    resp_elements = record.get("responseElements")
    console_login_status = (
        resp_elements.get("ConsoleLogin") if isinstance(resp_elements, dict) else None
    )

    if has_error or console_login_status == "Failure":
        outcome = "failure"
    elif console_login_status == "Success" or not has_error:
        outcome = "success"
    else:
        outcome = "unknown"

    event_type = "auth" if ("Login" in event_name or "signin" in service) else "activity"

    event = NormalizedEvent(
        event_id=event_id,
        evidence_id=evidence_id,
        raw_ref=raw_ref,
        timestamp_utc=ts_utc,
        event_type=event_type,
        outcome=outcome,
        account=account,
        source_ip=source_ip,
        service=service,
    )
    return event, False


def _extract_raw_records(raw_bytes: bytes) -> Tuple[List[Any], int]:
    """
    Extracts candidate CloudTrail record dicts from standard Records arrays,
    CloudWatch Logs subscription envelopes (logEvents[].message), single objects,
    or NDJSON lines. Returns (records_list, pre_parse_errors).
    """
    unparsed = 0
    text = raw_bytes.decode("utf-8", errors="replace")
    try:
        content = json.loads(text)
        if isinstance(content, dict):
            if isinstance(content.get("Records"), list):
                return content["Records"], 0
            if isinstance(content.get("logEvents"), list):
                extracted = []
                for item in content["logEvents"]:
                    if isinstance(item, dict) and isinstance(item.get("message"), str):
                        try:
                            inner = json.loads(item["message"])
                            if isinstance(inner, dict) and isinstance(inner.get("Records"), list):
                                extracted.extend(inner["Records"])
                            else:
                                extracted.append(inner)
                        except Exception:
                            unparsed += 1
                    else:
                        unparsed += 1
                return extracted, unparsed
            return [content], 0
        if isinstance(content, list):
            return content, 0
        return [content], 0
    except Exception:
        raw_list = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw_list.append(json.loads(line))
            except Exception:
                unparsed += 1
        return raw_list, unparsed


def parse_cloudtrail_bytes(
    raw_bytes: bytes,
    source_evidence_id: str,
) -> Tuple[List[NormalizedEvent], Dict[str, int]]:
    """Parse CloudTrail bytes without writing artifacts or custody entries."""
    raw_list, unparsed_records = _extract_raw_records(raw_bytes)
    events: List[NormalizedEvent] = []
    total_records = len(raw_list) + unparsed_records

    for index, record in enumerate(raw_list):
        event, is_unparsed = parse_cloudtrail_record(record, index, source_evidence_id)
        if is_unparsed:
            unparsed_records += 1
        elif event is not None:
            events.append(event)

    return events, {
        "total_records": total_records,
        "parsed_events": len(events),
        "unparsed_records": unparsed_records,
    }


def parse_and_record_cloudtrail(
    conn: sqlite3.Connection,
    file_path: Path | str,
    source_evidence_id: str,
    actor: str = "ingest",
    role: str = "examiner",
) -> Tuple[str, List[NormalizedEvent], Dict[str, int]]:
    """
    Parses a CloudTrail JSON file, writes an artifacts row, and appends a custody entry.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"CloudTrail file not found: {path}")

    raw_bytes = path.read_bytes()
    input_hash = hashlib.sha256(raw_bytes).hexdigest()
    events, stats = parse_cloudtrail_bytes(raw_bytes, source_evidence_id)

    serialized_events = [asdict(e) for e in events]
    output_hash = canonical_hash(serialized_events)
    artifact_id = f"art-{output_hash[:16]}"

    now_utc = datetime.now(timezone.utc).isoformat()
    metadata_json = canonical_json(stats)

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

    append_entry(
        conn=conn,
        actor=actor,
        role=role,
        action="parsed_cloudtrail_log",
        evidence_id=source_evidence_id,
        artifact_id=artifact_id,
        details={
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "events_count": len(events),
            "unparsed_count": stats["unparsed_records"],
        },
    )

    return artifact_id, events, stats