"""
Run the impossible-travel rule over the public Loghub OpenSSH log and print COUNTS.

  python detect/datasets/scripts/validate_impossible_travel.py path/to/SSH.log --year 2015 --geo-db path/to/city.mmdb

This does NOT report precision or recall. Loghub OpenSSH has no travel labels, it is a
single lab server with few successful logins, and nothing says which logins were the same
person. The honest output is how many candidate pairs exist and how many the rule flags,
under a few settings. Quote those as counts with the limitation, never as accuracy.
The year is an assumption (the log has none); timestamps are treated as UTC.
"""
import argparse
import sys
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from detect.datasets.openssh import parse_openssh                           # noqa: E402
from detect.geo import open_geo                                             # noqa: E402
from detect.rules.impossible_travel import TravelConfig, detect_with_stats  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--year", type=int, required=True)
    ap.add_argument("--geo-db", required=True, help="path to a GeoIP2/GeoLite2/DB-IP City .mmdb")
    ap.add_argument("--speeds", type=float, nargs="+", default=[500, 900, 1500])
    ap.add_argument("--min-distances", type=float, nargs="+", default=[100, 300, 500])
    a = ap.parse_args()

    res = parse_openssh(a.log, a.year)
    events = [asdict(e) for e in res.events]
    geolocate, geo_info = open_geo(a.geo_db)

    ips_by_account = defaultdict(set)
    for e in events:
        if e["outcome"] == "success":
            ips_by_account[e["account"]].add(e["source_ip"])
    multi = {acc: ips for acc, ips in ips_by_account.items() if len(ips) > 1}

    print(f"Dataset sha256    : {res.evidence_id}")
    print(f"Geo database      : {geo_info['source']} (sha256 {geo_info['sha256'][:16]}..., build_epoch {geo_info['build_epoch']})")
    print(f"Lines / events    : {res.total_lines} lines, {len(events)} failure/success events")
    print(f"Accounts with a successful login      : {len(ips_by_account)}")
    print(f"Accounts with successes from 2+ IPs   : {len(multi)}")
    print("LIMITATION        : no travel labels exist, so precision/recall are NOT measurable.")
    print()
    print("| speed_kmh | min_distance_km | successful logins | unlocatable | pairs compared | same IP | below min distance | evaluated | flagged |")
    print("|---|---|---|---|---|---|---|---|---|")
    for sp in a.speeds:
        for md in a.min_distances:
            _, s = detect_with_stats(events, TravelConfig(sp, md), geolocate, geo_info)
            print(f"| {sp:g} | {md:g} | {s['successful_logins']} | {s['unlocatable_logins']} | {s['pairs_compared']} "
                  f"| {s['pairs_same_ip']} | {s['pairs_below_min_distance']} | {s['pairs_evaluated']} | {s['flagged']} |")


if __name__ == "__main__":
    main()