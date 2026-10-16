"""
Large data access shortly after a flagged login  (rule_name=large_access, version 1.0.0)

QUESTION IT ANSWERS: "what did they take?"  It is NOT a standalone volume alarm.
It runs only for accounts that have a login already flagged by another rule, and
asks whether that account moved far more data than usual right after that login.

TRIGGERS (real stored findings, passed in)
  * brute_force_login that was followed_by_success -> the login is the success
  * impossible_travel                             -> the login is the second login
  A brute-force burst with no success has no login to follow, so it is skipped.
  Several triggers on the same login (e.g. the account and IP groupings) become
  ONE finding that lists all of them.

VOLUME EVENTS
  event_type == "data_access", outcome == "success", an account, and an integer
  bytes_out >= 0. Anything else is ignored (never guessed). Volume is attributed
  to the ACCOUNT, not to the login's IP, so activity by the legitimate owner in
  the same window is also counted. That can only raise a finding, never hide one.

BASELINE (explicit, per account, uses ONLY the past)
  login_t        = time of the flagged login
  bucket         = window_seconds                     (default 1 hour)
  lookback       = lookback_seconds                   (default 14 days)
  baseline data  = this account's volume events with login_t - lookback <= t < login_t
  buckets        = lookback / bucket consecutive buckets ending AT login_t
  totals         = bytes per bucket (empty buckets count as 0, so a quiet account
                   has a low mean and a spiky one has a high spread)
  mean, std      = population mean and standard deviation of those totals
  threshold      = mean + z * std                      (z default 3.0)
  window volume  = bytes in login_t <= t < login_t + window_seconds
  FLAG when window volume >= min_bytes AND window volume > threshold.

  NO FUTURE LEAKAGE. The baseline stops strictly before the login and the window
  starts at it, so the two never overlap and nothing after login_t + window is
  read. Tests prove this: appending data after the window changes nothing, and
  re-running on data truncated at the end of the window gives identical findings.

  NOT FLAGGED (never guessed): an account with fewer than min_baseline_events
  baseline events, or less than min_history_seconds of observed history, has no
  trustworthy baseline. It is reported as "insufficient_baseline" by assess_triggers.

PROVENANCE
  input_hash   = hash of EXACTLY what was read: the trigger finding hashes, the
                 login event, the window events and every baseline event.
  finding_hash = hash of the whole finding (config, baseline stats, triggers, ...).
  triggered_by = list of {finding_hash, ...} of the real triggering findings. The
                 hash is part of the finding, and detect.findings refuses to store
                 a finding whose trigger is not already a stored finding.
  A trigger whose finding_hash does not match its content is rejected.

LIMITS: statistics on heavy-tailed volume data are noisy; z and min_bytes are
starting points and are NOT tuned on labelled data (none exists). See
docs/validation/large_access.md.
"""
from __future__ import annotations

import math
from bisect import bisect_left
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import timedelta

from detect.canon import canonical_hash
from detect.rules.brute_force import _as_dict, _parse_ts
from schemas.normalized_event import EVENT_TYPE_AUTH

RULE_NAME = "large_access"
RULE_VERSION = "1.0.0"
EVENT_TYPE_DATA_ACCESS = "data_access"
TRIGGER_RULES = ("brute_force_login", "impossible_travel")


@dataclass(frozen=True)
class LargeAccessConfig:
    window_seconds: int = 3600
    lookback_seconds: int = 14 * 24 * 3600
    min_history_seconds: int = 7 * 24 * 3600
    min_baseline_events: int = 10
    z: float = 3.0
    min_bytes: int = 100_000_000

    def __post_init__(self):
        if self.window_seconds <= 0 or self.lookback_seconds <= 0:
            raise ValueError("window_seconds and lookback_seconds must be > 0")
        if self.lookback_seconds % self.window_seconds:
            raise ValueError("lookback_seconds must be a whole number of windows")
        if self.min_history_seconds < 0 or self.min_bytes < 0 or self.z < 0:
            raise ValueError("min_history_seconds, min_bytes and z must be >= 0")
        if self.min_baseline_events < 1:
            raise ValueError("min_baseline_events must be >= 1")


def _volume(ev):
    b = ev.get("bytes_out")
    return b if isinstance(b, int) and not isinstance(b, bool) and b >= 0 else None


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1000.0


class AccountIndex:
    """One account's volume events, sorted by time, with baseline/window queries."""

    def __init__(self, rows):
        # rows: (epoch_seconds, datetime, bytes, event_dict), sorted by (epoch, event_id)
        self.rows = rows
        self.epochs = [r[0] for r in rows]

    def assess(self, login_dt, cfg: LargeAccessConfig) -> dict:
        login = login_dt.timestamp()
        bucket = cfg.window_seconds
        n_buckets = cfg.lookback_seconds // bucket
        lo = login - cfg.lookback_seconds
        i0 = bisect_left(self.epochs, lo)
        i1 = bisect_left(self.epochs, login)              # first row AT/AFTER login
        j1 = bisect_left(self.epochs, login + bucket)
        base, win = self.rows[i0:i1], self.rows[i1:j1]

        totals = [0] * n_buckets
        for epoch, _, nbytes, _ in base:                  # bucket k covers (k*B, (k+1)*B] before login
            k = min(max(math.ceil((login - epoch) / bucket) - 1, 0), n_buckets - 1)
            totals[k] += nbytes
        mean = math.fsum(totals) / n_buckets
        std = math.sqrt(math.fsum((x - mean) ** 2 for x in totals) / n_buckets)
        threshold = mean + cfg.z * std
        window_bytes = sum(r[2] for r in win)

        first = self.epochs[0] if self.epochs and self.epochs[0] < login else None
        history = None if first is None else login - first
        if first is None or history < cfg.min_history_seconds or len(base) < cfg.min_baseline_events:
            status = "insufficient_baseline"
        elif window_bytes >= cfg.min_bytes and window_bytes > threshold:
            status = "flagged"
        else:
            status = "below_threshold"
        return {
            "status": status, "n_baseline_events": len(base), "n_buckets": n_buckets,
            "mean": mean, "std": std, "threshold": threshold,
            "window_bytes": window_bytes, "window_events": len(win),
            "history_seconds": history, "base_rows": base, "win_rows": win,
        }


def build_indexes(events) -> dict:
    """account -> AccountIndex, from volume events only."""
    per = defaultdict(list)
    for e in events:
        if e.get("event_type") != EVENT_TYPE_DATA_ACCESS or e.get("outcome") != "success":
            continue
        account, vol = e.get("account"), _volume(e)
        if account is None or vol is None:
            continue
        ts = _parse_ts(e["timestamp_utc"])
        per[str(account)].append((ts.timestamp(), ts, vol, e))
    for rows in per.values():
        rows.sort(key=lambda r: (r[0], str(r[3]["event_id"])))
    return {a: AccountIndex(rows) for a, rows in per.items()}


def _resolve_trigger(trig: dict, by_id: dict):
    """(True, login_event_id) if the trigger points at a valid login, else (False, reason)."""
    if trig.get("rule_name") not in TRIGGER_RULES:
        return False, "not_a_login_trigger"
    body = {k: v for k, v in trig.items() if k != "finding_hash"}
    if canonical_hash(body) != trig.get("finding_hash"):
        return False, "finding_hash_mismatch"
    if trig["rule_name"] == "brute_force_login" and not trig.get("followed_by_success"):
        return False, "no_successful_login"
    src = trig.get("source_events") or []
    if not src:
        return False, "no_source_events"
    ev = by_id.get(str(src[-1]["event_id"]))
    if ev is None:
        return False, "login_event_not_in_events"
    if ev.get("event_type") != EVENT_TYPE_AUTH or ev.get("outcome") != "success" or ev.get("account") is None:
        return False, "login_event_not_a_valid_login"
    return True, str(src[-1]["event_id"])


def _evaluate(events, trigger_findings, cfg):
    evs = [_as_dict(e) for e in events]
    by_id = {str(e["event_id"]): e for e in evs}
    index = build_indexes(evs)

    assessments, by_login = [], defaultdict(list)
    for trig in sorted(trigger_findings, key=lambda t: str(t.get("finding_hash"))):
        ok, res = _resolve_trigger(trig, by_id)
        if ok:
            by_login[res].append(trig)
        else:
            assessments.append({"trigger": trig.get("finding_hash"), "status": "trigger_unresolved", "reason": res})

    order = sorted(by_login, key=lambda i: (_parse_ts(by_id[i]["timestamp_utc"]), i))
    findings = []
    for login_id in order:
        login_ev = by_id[login_id]
        login_dt = _parse_ts(login_ev["timestamp_utc"])
        account = str(login_ev["account"])
        trigs = by_login[login_id]
        idx = index.get(account)
        empty = {"status": "insufficient_baseline", "n_baseline_events": 0, "mean": 0.0, "std": 0.0,
                 "threshold": 0.0, "window_bytes": 0, "window_events": 0, "history_seconds": None,
                 "base_rows": [], "win_rows": [], "n_buckets": cfg.lookback_seconds // cfg.window_seconds}
        a = idx.assess(login_dt, cfg) if idx else empty
        assessments.append({
            "login_event_id": login_id, "account": account, "status": a["status"],
            "triggers": sorted(t["finding_hash"] for t in trigs),
            **{k: a[k] for k in ("n_baseline_events", "mean", "std", "threshold",
                                 "window_bytes", "window_events", "history_seconds")}})
        if a["status"] != "flagged":
            continue

        base_events = [r[3] for r in a["base_rows"]]
        win_events = [r[3] for r in a["win_rows"]]
        triggered_by = [{"finding_hash": t["finding_hash"], "rule_name": t["rule_name"],
                         "rule_version": t["rule_version"], "grouped_by": t.get("grouped_by"),
                         "key": t.get("key")} for t in sorted(trigs, key=lambda t: t["finding_hash"])]
        examined = sorted([login_ev] + win_events,
                          key=lambda e: (_parse_ts(e["timestamp_utc"]), str(e["event_id"])))
        window_end = login_dt + timedelta(seconds=cfg.window_seconds)
        multiple = None if a["mean"] == 0 else round(a["window_bytes"] / a["mean"], 2)

        finding = {
            "rule_name": RULE_NAME, "rule_version": RULE_VERSION, "config": asdict(cfg),
            "grouped_by": "account", "key": account, "severity": "high",
            "triggered_by": triggered_by,
            "first_seen": login_dt.isoformat(),
            "last_seen": window_end.isoformat(),
            "login": {"event_id": login_id, "timestamp_utc": login_dt.isoformat(),
                      "source_ip": login_ev.get("source_ip")},
            "window": {"start": login_dt.isoformat(),
                       "end": window_end.isoformat(),
                       "bytes": a["window_bytes"], "event_count": a["window_events"],
                       "source_ips": sorted({str(e.get("source_ip")) for e in win_events if e.get("source_ip")})},
            "baseline": {
                "lookback_seconds": cfg.lookback_seconds, "bucket_seconds": cfg.window_seconds,
                "n_buckets": a["n_buckets"], "n_events": a["n_baseline_events"],
                "mean_bytes_per_bucket": round(a["mean"], 3), "std_bytes_per_bucket": round(a["std"], 3),
                "threshold_bytes": round(a["threshold"], 3), "window_multiple_of_mean": multiple,
                "events_hash": canonical_hash(base_events),
                "evidence_ids": sorted({e["evidence_id"] for e in base_events}),
            },
            "source_events": [{"event_id": str(e["event_id"]), "evidence_id": e["evidence_id"],
                               "raw_ref": e["raw_ref"]} for e in examined],
            # hash of EVERYTHING this finding read: triggers, login, window and baseline events
            "input_hash": canonical_hash({
                "triggers": [t["finding_hash"] for t in triggered_by],
                "login": login_ev, "window_events": win_events, "baseline_events": base_events}),
        }
        names = " and ".join(sorted({t["rule_name"] for t in triggered_by}))
        finding["title"] = (f"Large data access after flagged login for account {account}: "
                            f"{_fmt_bytes(a['window_bytes'])} in {cfg.window_seconds}s")
        finding["description"] = (
            f"After a login flagged by {names}, account {account} transferred "
            f"{_fmt_bytes(a['window_bytes'])} in {cfg.window_seconds}s, against a baseline of "
            f"{_fmt_bytes(a['mean'])} per window (threshold {_fmt_bytes(a['threshold'])}, "
            f"{a['n_baseline_events']} events over {cfg.lookback_seconds // 86400} days before the login). "
            f"Volume is attributed to the account, not the login's IP. Rule {RULE_NAME}@{RULE_VERSION}.")
        finding["finding_hash"] = canonical_hash(finding)
        findings.append(finding)
    return findings, assessments


def detect_large_access(events, trigger_findings, cfg: LargeAccessConfig = LargeAccessConfig()) -> list[dict]:
    """Findings only. `trigger_findings` are finding dicts from brute_force / impossible_travel."""
    return _evaluate(events, trigger_findings, cfg)[0]


def assess_triggers(events, trigger_findings, cfg: LargeAccessConfig = LargeAccessConfig()) -> list[dict]:
    """One row per login/trigger with its status (flagged, below_threshold,
    insufficient_baseline, trigger_unresolved). Use this to see WHY nothing was flagged."""
    return _evaluate(events, trigger_findings, cfg)[1]