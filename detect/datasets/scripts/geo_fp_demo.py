"""
Run the impossible-travel rule on a false-positive scenario using a REAL geolocation database.

  python detect/datasets/scripts/geo_fp_demo.py --geo-db city.mmdb --home-ip A --other-ip B [--minutes 5]

Scenario: one account logs in successfully from --home-ip, then --minutes later from --other-ip.
Use a pair you EXPECT to be benign, for example your normal IP and the exit IP of a VPN you
use, or your home IP and your phone's mobile-data IP. The script prints where the database
puts each IP, the distance, the implied speed, and whether the rule flags it, so the false-positive
note in docs/validation/impossible_travel_fp.md is checked against reality, not just asserted.

Do NOT commit your own IPs. Record the result (cities, distance, flagged yes/no) in the notes.
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from detect.geo import open_geo                                             # noqa: E402
from detect.rules.impossible_travel import (                                # noqa: E402
    TravelConfig, detect_with_stats, haversine_km)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--geo-db", required=True)
    ap.add_argument("--home-ip", required=True)
    ap.add_argument("--other-ip", required=True)
    ap.add_argument("--minutes", type=float, default=5)
    a = ap.parse_args()

    geolocate, info = open_geo(a.geo_db)
    p1, p2 = geolocate(a.home_ip), geolocate(a.other_ip)
    print(f"Database : {info['source']} (build_epoch {info['build_epoch']})")
    print(f"{a.home_ip:>16} -> {p1}")
    print(f"{a.other_ip:>16} -> {p2}")
    if p1 is None or p2 is None:
        print("Result   : at least one IP is not locatable (private, reserved, or not in the database): rule cannot judge.")
        return
    print(f"Distance : {haversine_km(p1, p2):,.0f} km (estimate)")

    t0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    events = [{"event_id": f"e{i}", "evidence_id": "demo", "raw_ref": f"line:{i}",
               "event_type": "auth", "outcome": "success",
               "timestamp_utc": (t0 + timedelta(minutes=a.minutes * i)).isoformat(),
               "account": "demo-user", "source_ip": ip}
              for i, ip in enumerate([a.home_ip, a.other_ip])]
    findings, stats = detect_with_stats(events, TravelConfig(), geolocate, info)
    if findings:
        print(f"Result   : FLAGGED, {findings[0]['speed_kmh']} km/h implied over {a.minutes:g} min (benign scenario = false positive)")
    elif stats["pairs_below_min_distance"]:
        print("Result   : not flagged, the IPs resolve closer than min_distance_km")
    else:
        print("Result   : not flagged, speed is within the threshold")


if __name__ == "__main__":
    main()