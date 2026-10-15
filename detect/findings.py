"""
Persist findings: one artifacts row, one findings row, and one custody-log
entry per source evidence item. Conforms to the frozen schemas/schema.sql;
it never changes the schema.

Mapping
  artifacts.tool_name/tool_version = rule name/version
  artifacts.input_hash             = finding["input_hash"] (events examined)
  artifacts.output_hash            = finding_hash = SHA-256 of findings.details_json
  findings.finding_id/artifact_id  = finding_hash (deterministic => idempotent)
  findings.rule_id                 = "<rule_name>@<rule_version>"
  findings.source_evidence_id      = evidence of the earliest examined event;
                                     ALL evidence ids are in artifacts.metadata_json
                                     and in the per-evidence custody entries.
  custody_log: actor="detect", action="finding_created", artifact_id=finding_hash

Rules may supply "title"/"description" in the finding (impossible_travel does);
brute_force_login does not, and keeps its original wording and hashes.

Wall-clock time is used only for created_at columns, never inside the hash.
Callers own the transaction (append_entry does not commit either).
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from detect.canon import canonical_json
from detect.rules.brute_force import BruteForceConfig, detect
from detect.rules.impossible_travel import TravelConfig, detect_impossible_travel
from seal.custody_log import append_entry

ACTOR = "detect"
ROLE = "detection_engine"   # TODO: confirm role string with Ash
ACTION = "finding_created"


def record_finding(conn, finding: dict) -> bool:
    """Write one finding. Does NOT commit. True if new, False if it already existed."""
    fid = finding["finding_hash"]
    body = {k: v for k, v in finding.items() if k != "finding_hash"}
    text = canonical_json(body)
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != fid:
        raise ValueError("finding_hash does not match finding content")

    if conn.execute("SELECT 1 FROM findings WHERE finding_id = ?", (fid,)).fetchone():
        return False

    events = finding["source_events"]          # sorted by (time, event_id)
    evidence_ids = sorted({e["evidence_id"] for e in events})
    primary = events[0]["evidence_id"]
    rule_id = f"{finding['rule_name']}@{finding['rule_version']}"
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO artifacts
           (artifact_id, source_evidence_id, source_artifact_id, tool_name,
            tool_version, created_at, input_hash, output_hash, metadata_json)
           VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?)""",
        (fid, primary, finding["rule_name"], finding["rule_version"], now,
         finding["input_hash"], fid, canonical_json({"evidence_ids": evidence_ids})),
    )

    if "title" in finding:                      # rule supplies its own wording
        title, description = finding["title"], finding["description"]
    else:                                       # brute_force_login wording (v1.x)
        title = f"{finding['failure_count']} failed logins for {finding['grouped_by']} {finding['key']}"
        if finding["followed_by_success"]:
            title += ", followed by a success"
        cfg = finding["config"]
        description = (
            f"{finding['failure_count']} failures between {finding['first_seen']} and "
            f"{finding['last_seen']} (threshold {cfg['threshold']} in {cfg['window_seconds']}s). "
            f"Rule {rule_id}."
        )
    conn.execute(
        """INSERT INTO findings
           (finding_id, source_evidence_id, artifact_id, rule_id, severity,
            title, description, created_at, details_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (fid, primary, fid, rule_id, finding["severity"], title, description, now, text),
    )

    for evidence_id in evidence_ids:
        append_entry(
            conn, ACTOR, ROLE, ACTION,
            evidence_id=evidence_id,
            artifact_id=fid,
            details={
                "rule_id": rule_id,
                "input_hash": finding["input_hash"],
                "finding_hash": fid,
                "severity": finding["severity"],
                "source_events": [e for e in events if e["evidence_id"] == evidence_id],
            },
        )
    return True


def record_all(conn, findings) -> int:
    """Persist findings from ANY rule in ONE transaction (all or nothing).
    Returns the number of newly recorded findings."""
    try:
        new = sum(1 for f in findings if record_finding(conn, f))
        conn.commit()
        return new
    except Exception:
        conn.rollback()
        raise


def detect_and_record(conn, events, cfg: BruteForceConfig = BruteForceConfig()) -> int:
    """Run the brute-force rule and persist every finding in ONE transaction."""
    return record_all(conn, detect(events, cfg))


def detect_travel_and_record(conn, events, geolocate, geo_info,
                             cfg: TravelConfig = TravelConfig()) -> int:
    """Run the impossible-travel rule and persist every finding in ONE transaction."""
    return record_all(conn, detect_impossible_travel(events, cfg, geolocate, geo_info))