"""
Run the brute-force rule against the public Loghub OpenSSH log and print a
precision/recall sweep as a Markdown table for docs/validation/brute_force_fp.md.

    python detect/datasets/scripts/validate_brute_force.py path/to/SSH.log --year 2015

Use the FULL log (Zenodo, ~70 MB). The 2k-line GitHub sample is a smoke test only.
The year is an assumption: the log has none. Labels are weak (see detect/datasets/openssh.py).
"""
import argparse
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from detect.datasets.openssh import parse_openssh          # noqa: E402
from detect.validation import sweep_labeled                # noqa: E402


def fmt(x):
    return "n/a" if x is None else f"{x:.3f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--year", type=int, required=True)
    ap.add_argument("--dimension", default="source_ip", choices=["source_ip", "account"])
    ap.add_argument("--thresholds", type=int, nargs="+", default=[3, 5, 10, 20])
    ap.add_argument("--windows", type=int, nargs="+", default=[60, 300, 900])
    a = ap.parse_args()

    res = parse_openssh(a.log, a.year)
    events = [asdict(e) for e in res.events]
    mal, ben = res.malicious_ips, res.benign_ips
    print(f"Dataset sha256 : {res.evidence_id}")
    print(f"Lines          : {res.total_lines} total, {res.unparsed_lines} unparsed")
    print(f"Events         : {len(events)} (failure/success only)")
    print(f"Weak labels    : {len(mal)} malicious IPs, {len(ben)} benign IPs")
    if len(ben) < 10:
        print("WARNING        : very few benign IPs, so precision is barely measured. Say so in the notes.")
    print()

    rows = sweep_labeled(events, mal, ben, a.thresholds, a.windows, a.dimension)
    print("| threshold | window_s | TP | FP | FN | unlabelled flagged | precision | recall |")
    print("|---|---|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['threshold']} | {r['window_seconds']} | {r['tp']} | {r['fp']} | {r['fn']} "
              f"| {r['unlabelled_flagged']} | {fmt(r['precision'])} | {fmt(r['recall'])} |")


if __name__ == "__main__":
    main()