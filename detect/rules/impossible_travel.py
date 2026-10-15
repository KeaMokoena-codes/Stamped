"""
Impossible-travel detection rule  (rule_name=impossible_travel, version 1.1.0)

WHAT IT FLAGS
  Two SUCCESSFUL logins for the same account, from different IPs, whose
  geolocated positions are at least `min_distance_km` apart and would need an
  average speed above `speed_threshold_kmh` to cover in the time between them.

CONFIG (TravelConfig)
  speed_threshold_kmh  flag above this average speed        (default 900.0)
                       ~ cruising speed of a passenger jet. Anything faster
                       cannot be physical travel.
  min_distance_km      ignore pairs closer than this         (default 300.0)
                       Offline IP geolocation is often off by tens to hundreds
                       of km at city level. Without this floor, two logins from
                       the same city that geolocate to different suburbs would
                       "travel" at absurd speed. Raising it lowers false
                       positives and misses short real hops; lowering it
                       does the opposite.
  Defaults are starting points, not tuned numbers: there is no labelled public
  dataset to tune them against (see docs/validation/impossible_travel_fp.md).

GEOLOCATION (injected, see detect/geo.py)
  detect_impossible_travel(events, cfg, geolocate, geo_info)
    geolocate(ip) -> (lat, lon) | None      offline database lookup
    geo_info      -> dict naming the database (file, sha256, build time)
  The rule is a pure function of its arguments. Coordinates come from a
  database with real accuracy limits; every distance and speed here is an
  ESTIMATE. Never present a finding as proof the account was shared.

BEHAVIOUR
  * Only LOGIN events are used: event_type == "auth", outcome == "success",
    with an account and a source_ip. Ordinary activity (e.g. API calls) is
    ignored, so it can neither create a login pair nor sit between two.
  * Per account, logins are sorted by (timestamp, event_id) and CONSECUTIVE
    logins from different IPs are compared. Same-IP logins never count.
  * Logins whose IP cannot be located (private, reserved, not in the database)
    are dropped and counted in the stats, never guessed.
  * Two logins at the same instant from far-apart IPs are flagged with
    speed_kmh = null and instantaneous = true (infinity is not valid in the
    canonical JSON / custody log).
  * Deterministic: no wall clock; distances/speeds/coordinates are rounded so
    the hash does not depend on float noise.
  * Severity is always "medium": geolocation is too imprecise to justify more.

PROVENANCE (same shape as brute_force_login, so detect/findings.py stores it)
  input_hash   = hash of ONLY the two login events examined.
  finding_hash = hash of the whole finding, which includes the config, the rule
                 version, the coordinates used and geo_info. A different
                 database or coordinate therefore gives a different hash.
  source_events link back to the exact evidence lines.

FALSE POSITIVES (demonstrated in tests/test_impossible_travel.py)
  VPN / proxy exit nodes, mobile carrier NAT gateways, shared corporate egress.
  See docs/validation/impossible_travel_fp.md.

VERSION HISTORY
  1.1.0  Only event_type == "auth" events are used. 1.0.0 treated any
         successful event with an account and IP as a login, so ordinary
         API calls from two places could be flagged. SSH results unchanged.
  1.0.0  Initial release.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import timedelta

from detect.canon import canonical_hash
from detect.rules.brute_force import _as_dict, _parse_ts
from schemas.normalized_event import EVENT_TYPE_AUTH

RULE_NAME = "impossible_travel"
RULE_VERSION = "1.1.0"
EARTH_RADIUS_KM = 6371.0088


@dataclass(frozen=True)
class TravelConfig:
    speed_threshold_kmh: float = 900.0
    min_distance_km: float = 300.0

    def __post_init__(self):
        if self.speed_threshold_kmh <= 0:
            raise ValueError("speed_threshold_kmh must be > 0")
        if self.min_distance_km < 0:
            raise ValueError("min_distance_km must be >= 0")


def haversine_km(a, b) -> float:
    """Great-circle distance in km between (lat, lon) points in degrees."""
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = (math.sin((lat2 - lat1) / 2) ** 2
         + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2)
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(h)))


def _empty_stats():
    return {"successful_logins": 0, "unlocatable_logins": 0, "pairs_compared": 0,
            "pairs_same_ip": 0, "pairs_below_min_distance": 0,
            "pairs_evaluated": 0, "flagged": 0}


def detect_with_stats(events, cfg: TravelConfig, geolocate, geo_info: dict):
    """Return (findings, stats). `stats` is for validation reports only."""
    rows = sorted(
        ((_parse_ts(e["timestamp_utc"]), e) for e in map(_as_dict, events)
         if e.get("event_type") == EVENT_TYPE_AUTH
         and e.get("outcome") == "success" and e.get("account") is not None
         and e.get("source_ip") is not None),
        key=lambda r: (r[0], str(r[1]["event_id"])),
    )
    stats, findings = _empty_stats(), []
    by_account = defaultdict(list)
    cache = {}
    for ts, ev in rows:
        stats["successful_logins"] += 1
        ip = ev["source_ip"]
        if ip not in cache:
            cache[ip] = geolocate(ip)
        pos = cache[ip]
        if pos is None:
            stats["unlocatable_logins"] += 1
            continue
        by_account[ev["account"]].append((ts, ev, (round(pos[0], 4), round(pos[1], 4))))

    for account in sorted(by_account, key=str):
        logins = by_account[account]
        for (t1, e1, p1), (t2, e2, p2) in zip(logins, logins[1:]):
            stats["pairs_compared"] += 1
            if e1["source_ip"] == e2["source_ip"]:
                stats["pairs_same_ip"] += 1
                continue
            dist = haversine_km(p1, p2)
            if dist < cfg.min_distance_km:
                stats["pairs_below_min_distance"] += 1
                continue
            stats["pairs_evaluated"] += 1
            elapsed = (t2 - t1).total_seconds()
            if elapsed <= 0:
                speed = None                        # instantaneous
            else:
                speed = dist / (elapsed / 3600.0)
                if speed <= cfg.speed_threshold_kmh:
                    continue
            stats["flagged"] += 1

            examined = [(t1, e1, p1), (t2, e2, p2)]
            speed_txt = "instantaneous" if speed is None else f"{speed:,.0f} km/h"
            finding = {
                "rule_name": RULE_NAME,
                "rule_version": RULE_VERSION,
                "config": asdict(cfg),
                "geo_source": dict(geo_info),
                "grouped_by": "account",
                "key": str(account),
                "severity": "medium",
                "first_seen": t1.isoformat(),
                "last_seen": t2.isoformat(),
                "distance_km": round(dist, 1),
                "elapsed_seconds": elapsed,
                "speed_kmh": None if speed is None else round(speed, 1),
                "instantaneous": speed is None,
                "logins": [
                    {"event_id": str(e["event_id"]), "source_ip": e["source_ip"],
                     "timestamp_utc": t.isoformat(), "lat": p[0], "lon": p[1]}
                    for t, e, p in examined
                ],
                "source_events": [
                    {"event_id": str(e["event_id"]), "evidence_id": e["evidence_id"],
                     "raw_ref": e["raw_ref"]}
                    for _, e, _ in examined
                ],
                # hash of ONLY the two events this finding examined
                "input_hash": canonical_hash([e for _, e, _ in examined]),
                "title": (f"Impossible travel for account {account}: "
                          f"{dist:,.0f} km in {timedelta(seconds=elapsed)} ({speed_txt})"),
                "description": (
                    f"Successful logins from {e1['source_ip']} and {e2['source_ip']} are about "
                    f"{dist:,.0f} km apart (estimated from IP geolocation) but "
                    f"{timedelta(seconds=elapsed)} apart, implying {speed_txt} "
                    f"(threshold {cfg.speed_threshold_kmh:g} km/h, minimum distance "
                    f"{cfg.min_distance_km:g} km). Geolocation is approximate; VPNs, proxies, "
                    f"mobile carrier gateways and shared egress IPs can cause false positives. "
                    f"Rule {RULE_NAME}@{RULE_VERSION}."),
            }
            finding["finding_hash"] = canonical_hash(finding)
            findings.append(finding)
    return findings, stats


def detect_impossible_travel(events, cfg: TravelConfig, geolocate, geo_info: dict) -> list[dict]:
    return detect_with_stats(events, cfg, geolocate, geo_info)[0]