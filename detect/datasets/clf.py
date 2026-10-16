"""
Validation-only loader for Common Log Format web logs, e.g. the public NASA-HTTP
trace (Internet Traffic Archive, Kennedy Space Center, July 1995).

NOT the ingest stage. It emits volume events for detect.rules.large_access:
  event_type="data_access", account=<requesting host>, bytes_out=<reply bytes>.
NASA-HTTP has no logins and no user accounts, so the requesting HOST stands in for
the account. That is enough to exercise the BASELINE method on real, heavy-tailed
byte counts, and nothing more. It cannot say whether the rule finds real attacks.

Line format:  host - - [01/Jul/1995:00:00:01 -0400] "GET /x HTTP/1.0" 200 6245
  * success   = status 200..299; bytes_out is the reply size ("-" means none)
  * any other status is outcome "failure" with no volume
  * timestamps are converted from the logged offset to UTC
  * evidence_id = SHA-256 of the file exactly as given (.gz is hashed compressed;
    raw_ref line numbers refer to the decompressed text)

PRIVACY: the archive asks users not to analyse beyond general traffic patterns.
Report aggregate results only (counts, rates). Never publish individual hosts.
"""
from __future__ import annotations

import gzip
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from schemas.normalized_event import make_event_id

_LINE = re.compile(r'^(?P<host>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>.*)"\s+'
                   r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s*$')
_TS = re.compile(r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d\d):(\d\d):(\d\d)\s+([+-])(\d\d)(\d\d)$")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


@dataclass
class ClfResult:
    evidence_id: str
    events: list
    total_lines: int = 0
    unparsed_lines: int = 0


def _parse_ts(text: str):
    m = _TS.match(text)
    if not m or m[2] not in _MONTHS:
        return None
    sign = -1 if m[7] == "-" else 1
    tz = timezone(sign * timedelta(hours=int(m[8]), minutes=int(m[9])))
    try:
        return datetime(int(m[3]), _MONTHS[m[2]], int(m[1]), int(m[4]), int(m[5]), int(m[6]), tzinfo=tz).astimezone(timezone.utc)
    except ValueError:
        return None


def parse_clf(path) -> ClfResult:
    raw = Path(path).read_bytes()
    evidence_id = hashlib.sha256(raw).hexdigest()
    text = (gzip.decompress(raw) if str(path).endswith(".gz") else raw).decode("latin-1")
    res = ClfResult(evidence_id=evidence_id, events=[])
    for n, line in enumerate(text.splitlines(), start=1):
        res.total_lines += 1
        m = _LINE.match(line)
        ts = _parse_ts(m["ts"]) if m else None
        if not m or ts is None:
            res.unparsed_lines += 1
            continue
        ok = 200 <= int(m["status"]) < 300
        ref = f"line:{n}"
        res.events.append({
            "event_id": make_event_id(evidence_id, ref), "evidence_id": evidence_id, "raw_ref": ref,
            "timestamp_utc": ts.isoformat(), "event_type": "data_access",
            "outcome": "success" if ok else "failure", "account": m["host"], "source_ip": None,
            "service": "http",
            "bytes_out": int(m["bytes"]) if ok and m["bytes"] != "-" else None,
        })
    return res