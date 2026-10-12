"""
Brute-force login detection rule  (rule_name=brute_force_login, version 1.0.0)

WHAT IT FLAGS
  >= `threshold` failed logins for one account, or from one source IP, within
  `window_seconds`. Severity is "high" if a success for the same account/IP
  follows the burst within `success_follow_seconds`, otherwise "medium".

CONFIG (BruteForceConfig)
  threshold               failures needed inside the window       (default 5)
  window_seconds          sliding window length, inclusive        (default 300)
  success_follow_seconds  how long after the last failure a
                          success still counts as "followed by"   (default 300)
  Defaults are starting points. Tune them against the PUBLIC dataset only.

BEHAVIOUR
  * Grouped twice: by account (targeted guessing) and by source_ip (spraying).
  * One finding per burst: overlapping windows are merged, so one long attack
    is one finding, not dozens.
  * Deterministic: events are sorted by (timestamp, event_id); no wall clock.
  * Window edges are inclusive: events exactly window_seconds apart count
    together. A success at exactly the same instant as the last failure is
    NOT counted as following it.
  * The same attack seen by both groupings yields two findings (one per
    dimension). The dashboard may choose to group them.

PROVENANCE
  input_hash   = hash of ONLY the events examined (burst failures + matched
                 success). Not the dataset, not a constant.
  finding_hash = hash of the whole finding (includes config, rule version and
                 input_hash), so changing config changes the hash.

False-positive scenarios: docs/validation/brute_force_fp.md
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timedelta, timezone

from detect.canon import canonical_hash

RULE_NAME = "brute_force_login"
RULE_VERSION = "1.0.0"
DIMENSIONS = ("account", "source_ip")


@dataclass(frozen=True)
class BruteForceConfig:
    threshold: int = 5
    window_seconds: int = 300
    success_follow_seconds: int = 300

    def __post_init__(self):
        if self.threshold < 2:
            raise ValueError("threshold must be >= 2")
        if self.window_seconds <= 0 or self.success_follow_seconds < 0:
            raise ValueError("window_seconds must be > 0 and success_follow_seconds >= 0")


def _as_dict(e) -> dict:
    return asdict(e) if is_dataclass(e) and not isinstance(e, type) else dict(e)


def _parse_ts(value) -> datetime:
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(
        str(value).replace("Z", "+00:00")  # Python 3.10 cannot parse a trailing Z
    )
    if dt.tzinfo is None:
        raise ValueError(f"timestamp must be timezone-aware UTC, got naive value {value!r}")
    return dt.astimezone(timezone.utc)


def _bursts(times, cfg):
    """Merged (start, end) index ranges over time-sorted failure timestamps."""
    win = timedelta(seconds=cfg.window_seconds)
    out, left, cur = [], 0, None
    for right in range(len(times)):
        while times[right] - times[left] > win:
            left += 1
        if right - left + 1 >= cfg.threshold:
            if cur and left <= cur[1]:
                cur = (min(cur[0], left), right)
            else:
                if cur:
                    out.append(cur)
                cur = (left, right)
    if cur:
        out.append(cur)
    return out


def detect(events, cfg: BruteForceConfig = BruteForceConfig()) -> list[dict]:
    rows = sorted(
        ((_parse_ts(e["timestamp_utc"]), e) for e in map(_as_dict, events)),
        key=lambda r: (r[0], str(r[1]["event_id"])),
    )
    findings = []

    for dim in DIMENSIONS:
        fails, wins = defaultdict(list), defaultdict(list)
        for ts, ev in rows:
            key = ev.get(dim)
            if key is None:
                continue
            if ev.get("outcome") == "failure":
                fails[key].append((ts, ev))
            elif ev.get("outcome") == "success":
                wins[key].append((ts, ev))

        for key in sorted(fails, key=str):
            f = fails[key]
            for start, end in _bursts([t for t, _ in f], cfg):
                burst = f[start:end + 1]
                last = burst[-1][0]
                horizon = last + timedelta(seconds=cfg.success_follow_seconds)
                success = next(
                    ((t, e) for t, e in wins.get(key, []) if last < t <= horizon), None
                )
                examined = burst + ([success] if success else [])
                examined.sort(key=lambda r: (r[0], str(r[1]["event_id"])))

                finding = {
                    "rule_name": RULE_NAME,
                    "rule_version": RULE_VERSION,
                    "config": asdict(cfg),
                    "grouped_by": dim,
                    "key": str(key),
                    "severity": "high" if success else "medium",
                    "failure_count": len(burst),
                    "followed_by_success": success is not None,
                    "first_seen": burst[0][0].isoformat(),
                    "last_seen": last.isoformat(),
                    "source_events": [
                        {
                            "event_id": str(e["event_id"]),
                            "evidence_id": e["evidence_id"],
                            "raw_ref": e["raw_ref"],
                        }
                        for _, e in examined
                    ],
                    # hash of ONLY the events this finding examined
                    "input_hash": canonical_hash([e for _, e in examined]),
                }
                finding["finding_hash"] = canonical_hash(finding)
                findings.append(finding)

    return findings