"""
Unified Incident Timeline Construction (Issue #19).

Merges NormalizedEvent records from all ingestion parsers (auth_log, cloudtrail_json)
and flagged detection findings (either in-memory dicts from detect rules or rows from
the SQLite 'findings' table) into a single chronologically ordered UTC timeline.

Every timeline entry retains its full provenance link back to the sealed evidence
or derived artifact record.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from schemas.normalized_event import NormalizedEvent


def normalize_utc_timestamp(value: str | datetime) -> Tuple[datetime, str]:
    """
    Validates that a timestamp is timezone-aware, converts it to UTC,
    and returns (utc_datetime, canonical_iso_string).
    Raises ValueError if the timestamp is naive or malformed.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        cleaned = value.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        if " " in cleaned and "T" not in cleaned:
            cleaned = cleaned.replace(" ", "T", 1)
        dt = datetime.fromisoformat(cleaned)
    else:
        raise TypeError(f"Expected str or datetime for timestamp, got {type(value).__name__}")

    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"Timeline requires timezone-aware timestamp, got naive value: {value!r}")

    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc, dt_utc.isoformat()


def _event_to_timeline_item(event: NormalizedEvent | Dict[str, Any]) -> Tuple[datetime, Dict[str, Any]]:
    """Converts a NormalizedEvent (or dict) into a standardized timeline entry."""
    ev_dict = (
        asdict(event)
        if is_dataclass(event) and not isinstance(event, type)
        else dict(event)
    )

    for req in ("event_id", "evidence_id", "raw_ref", "timestamp_utc", "event_type", "outcome"):
        if not ev_dict.get(req):
            raise ValueError(f"Normalized event missing required field {req!r}")

    dt_utc, ts_iso = normalize_utc_timestamp(ev_dict["timestamp_utc"])

    account = ev_dict.get("account")
    source_ip = ev_dict.get("source_ip")
    service = ev_dict.get("service") or "unknown"
    outcome = ev_dict["outcome"]
    event_type = ev_dict["event_type"]

    actor_label = account or "unknown_account"
    ip_label = f" from {source_ip}" if source_ip else ""
    summary = f"[{service}] {event_type} ({outcome}) for {actor_label}{ip_label}"

    severity = "low" if outcome == "failure" else "info"

    normalized_details = dict(ev_dict)
    normalized_details["timestamp_utc"] = ts_iso

    item = {
        "entry_type": "event",
        "id": str(ev_dict["event_id"]),
        "timestamp_utc": ts_iso,
        "event_type": str(event_type),
        "outcome": str(outcome),
        "severity": severity,
        "service": str(service),
        "account": account,
        "source_ip": source_ip,
        "summary": summary,
        "provenance": {
            "evidence_id": str(ev_dict["evidence_id"]),
            "raw_ref": str(ev_dict["raw_ref"]),
            "event_id": str(ev_dict["event_id"]),
        },
        "details": normalized_details,
    }
    return dt_utc, item


def _finding_to_timeline_item(finding: Dict[str, Any]) -> Tuple[datetime, Dict[str, Any]]:
    """
    Converts either an in-memory finding dict (from detect/rules/*.py) or a database
    finding row dict (from the 'findings' table) into a standardized timeline entry.
    """
    f_dict = dict(finding)

    # If loaded from SQLite 'findings' table, unpack details_json if present
    details_payload: Dict[str, Any] = {}
    if isinstance(f_dict.get("details_json"), str):
        try:
            details_payload = json.loads(f_dict["details_json"])
        except Exception:
            details_payload = {}

    merged = {**details_payload, **f_dict}

    finding_id = str(
        merged.get("finding_id")
        or merged.get("finding_hash")
        or merged.get("artifact_id")
        or ""
    )
    if not finding_id:
        raise ValueError("Finding is missing finding_id / finding_hash")

    # Place the finding at the timestamp when the suspicious pattern completed (last_seen),
    # falling back to timestamp_utc, first_seen, or created_at.
    raw_ts = (
        merged.get("timestamp_utc")
        or merged.get("last_seen")
        or merged.get("first_seen")
        or merged.get("created_at")
    )
    if not raw_ts:
        raise ValueError(f"Finding {finding_id!r} has no timestamp field")

    dt_utc, ts_iso = normalize_utc_timestamp(raw_ts)

    rule_id = merged.get("rule_id")
    if not rule_id and merged.get("rule_name"):
        rule_ver = merged.get("rule_version", "1.0.0")
        rule_id = f"{merged['rule_name']}@{rule_ver}"
    rule_id = str(rule_id or "detection_rule")

    grouped_by = merged.get("grouped_by")
    key_val = merged.get("key")
    account = merged.get("account") or (str(key_val) if grouped_by == "account" and key_val else None)
    source_ip = merged.get("source_ip") or (str(key_val) if grouped_by == "source_ip" and key_val else None)

    title = merged.get("title")
    if not title:
        if "failure_count" in merged and grouped_by and key_val:
            title = f"{merged['failure_count']} failed logins for {grouped_by} {key_val}"
            if merged.get("followed_by_success"):
                title += ", followed by a success"
        else:
            title = merged.get("description") or f"Flagged finding ({rule_id})"

    source_events = merged.get("source_events") or []
    evidence_ids = sorted(
        {
            str(e["evidence_id"])
            for e in source_events
            if isinstance(e, dict) and e.get("evidence_id")
        }
        | (
            {str(merged["source_evidence_id"])}
            if merged.get("source_evidence_id")
            else set()
        )
    )

    provenance = {
        "finding_id": finding_id,
        "artifact_id": str(merged.get("artifact_id") or finding_id),
        "rule_id": rule_id,
        "input_hash": merged.get("input_hash"),
        "evidence_ids": evidence_ids,
        "source_events": source_events,
    }

    item = {
        "entry_type": "finding",
        "id": finding_id,
        "timestamp_utc": ts_iso,
        "event_type": "finding",
        "outcome": "flagged",
        "severity": str(merged.get("severity") or "medium"),
        "service": rule_id,
        "account": account,
        "source_ip": source_ip,
        "summary": str(title),
        "provenance": provenance,
        "details": merged,
    }
    return dt_utc, item


def load_findings_from_db(
    conn: sqlite3.Connection,
    evidence_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Loads persisted findings from the SQLite 'findings' table."""
    sql = (
        "SELECT finding_id, source_evidence_id, artifact_id, rule_id, severity, "
        "title, description, created_at, details_json FROM findings"
    )
    params: Tuple[Any, ...] = ()
    if evidence_id is not None:
        sql += " WHERE source_evidence_id = ?"
        params = (evidence_id,)
    sql += " ORDER BY created_at ASC, finding_id ASC"

    rows = conn.execute(sql, params).fetchall()
    results: List[Dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "finding_id": row[0],
                "source_evidence_id": row[1],
                "artifact_id": row[2],
                "rule_id": row[3],
                "severity": row[4],
                "title": row[5],
                "description": row[6],
                "created_at": row[7],
                "details_json": row[8],
            }
        )
    return results


def build_timeline(
    events: Iterable[NormalizedEvent | Dict[str, Any]],
    findings: Optional[Iterable[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """
    Combines normalized events (from any parser) and detection findings into
    a single chronologically ordered UTC timeline.

    Tie-breaking at the exact same timestamp is deterministic:
      1. Raw events appear immediately before findings triggered at that timestamp.
      2. Ties within the same entry_type are ordered by entry id.
    """
    decorated: List[Tuple[datetime, int, str, Dict[str, Any]]] = []

    for ev in events:
        dt_utc, item = _event_to_timeline_item(ev)
        # Priority 0 so raw events precede findings at the exact same instant
        decorated.append((dt_utc, 0, item["id"], item))

    if findings:
        for f in findings:
            dt_utc, item = _finding_to_timeline_item(f)
            decorated.append((dt_utc, 1, item["id"], item))

    decorated.sort(key=lambda r: (r[0], r[1], r[2]))
    return [r[3] for r in decorated]