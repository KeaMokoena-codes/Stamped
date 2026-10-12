"""
Validation-only loader for the public Loghub OpenSSH dataset (sshd auth log).

This is NOT the ingest stage. Abdi's parsers own real ingestion. This adapter
exists so the brute-force rule can be validated against public data without
waiting on ingest. It emits the same NormalizedEvent contract, so the rule sees
identical input either way.

Dataset: Loghub "OpenSSH", real sshd log, ~655k lines over ~28 days.
         https://github.com/logpai/loghub  (cite the Loghub paper when used)
         The dataset has NO attack labels. See weak-label notes below.

Parsing decisions (document these in the validation notes):
  * failure  = "Failed password for [invalid user] X from IP port N"
               One line per attempt, so counts are not inflated by the PAM,
               "Invalid user", or "Connection closed" lines of the same attempt.
  * success  = "Accepted password|publickey for X from IP port N"
  * ignored  = "Failed none" probes, pam_unix lines, disconnects, etc.
  * The log has no year. The caller supplies one; the year rolls forward when
    the month number decreases (Dec -> Jan).
  * The log has no timezone. Timestamps are treated as UTC. Only relative
    timing matters for this rule, but state the assumption.

WEAK LABELS (the dataset has no ground truth, so these are an approximation):
  malicious = IP that tried at least one username that does not exist
              ("Invalid user ..."). Legitimate users do not do this.
  benign    = IP with an "Accepted" login and no invalid-user attempts.
  everything else is UNLABELLED and excluded from precision/recall.
  Known weakness: a lab server has very few legitimate logins, so the benign
  set may be tiny and precision poorly measured. Report the counts.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from schemas.normalized_event import NormalizedEvent, make_event_id

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*?)\s*$"
)
_FAILED = re.compile(rf"^Failed password for (?:invalid user )?(?P<user>\S+) from {_IP} port \d+")
_ACCEPTED = re.compile(rf"^Accepted (?:password|publickey) for (?P<user>\S+) from {_IP} port \d+")
_INVALID = re.compile(rf"^Invalid user (?P<user>\S*)\s+from {_IP}")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


@dataclass
class ParseResult:
    evidence_id: str
    events: list
    invalid_user_ips: set = field(default_factory=set)
    accepted_ips: set = field(default_factory=set)
    total_lines: int = 0
    unparsed_lines: int = 0

    @property
    def malicious_ips(self) -> set:
        return set(self.invalid_user_ips)

    @property
    def benign_ips(self) -> set:
        return self.accepted_ips - self.invalid_user_ips


def parse_openssh(path, year: int) -> ParseResult:
    raw = Path(path).read_bytes()
    evidence_id = hashlib.sha256(raw).hexdigest()      # same definition as evidence.evidence_id
    res = ParseResult(evidence_id=evidence_id, events=[])
    prev_month, cur_year = None, year

    for n, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
        res.total_lines += 1
        m = _LINE.match(line)
        if not m:
            res.unparsed_lines += 1
            continue
        month = _MONTHS.get(m["mon"])
        if month is None:
            res.unparsed_lines += 1
            continue
        if prev_month is not None and month < prev_month:
            cur_year += 1
        prev_month = month

        msg = m["msg"]
        inv = _INVALID.match(msg)
        if inv:
            res.invalid_user_ips.add(inv["ip"])
            continue
        fail, ok = _FAILED.match(msg), _ACCEPTED.match(msg)
        if not (fail or ok):
            continue

        hh, mm, ss = map(int, m["time"].split(":"))
        ts = datetime(cur_year, month, int(m["day"]), hh, mm, ss, tzinfo=timezone.utc)
        hit = fail or ok
        if fail and msg.startswith("Failed password for invalid user"):
            res.invalid_user_ips.add(hit["ip"])
        if ok:
            res.accepted_ips.add(hit["ip"])
        ref = f"line:{n}"
        res.events.append(NormalizedEvent(
            event_id=make_event_id(evidence_id, ref), evidence_id=evidence_id, raw_ref=ref,
            timestamp_utc=ts.isoformat(), event_type="auth",
            outcome="failure" if fail else "success",
            account=hit["user"], source_ip=hit["ip"], service="ssh",
        ))
    return res