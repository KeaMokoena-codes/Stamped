"""
Baseline BASE-RATE check of the large_access method on a public web trace
(NASA-HTTP). AGGREGATE OUTPUT ONLY: no host is ever printed.

  python detect/datasets/scripts/validate_large_access.py path/to/NASA_access_log_Jul95[.gz]

What it measures (and what it does not):
  * Every account that has enough history gets hypothetical "login" times spread
    along its own timeline. For each, the rule's baseline asks: did the next
    window exceed mean + z*std? The share that do is the BASE RATE of the volume
    test on natural, benign traffic. It is how often a volume-only alarm would
    cry wolf, which is exactly why large_access fires only after a flagged login.
  * LEAK CHECK on real data: for a sample of those times the assessment is repeated
    on data truncated at the end of the window (what a live system would have
    seen). Any difference is future leakage. The count must be 0.
  * It does NOT measure detection accuracy: this trace has no logins and no labels.
"""
import argparse
import sys
from bisect import bisect_left
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from detect.datasets.clf import parse_clf                                   # noqa: E402
from detect.rules.large_access import AccountIndex, LargeAccessConfig, build_indexes   # noqa: E402


def key(a):
    return (a["status"], a["window_bytes"], round(a["mean"], 6), round(a["std"], 6), a["n_baseline_events"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--window-seconds", type=int, default=3600)
    ap.add_argument("--lookback-days", type=int, default=7)
    ap.add_argument("--min-history-days", type=int, default=3)
    ap.add_argument("--min-baseline-events", type=int, default=10)
    ap.add_argument("--z", type=float, default=3.0)
    ap.add_argument("--min-bytes", type=int, default=0, help="default 0 to expose the raw statistical base rate")
    ap.add_argument("--leak-sample", type=int, default=1000)
    a = ap.parse_args()

    cfg = LargeAccessConfig(window_seconds=a.window_seconds, lookback_seconds=a.lookback_days * 86400,
                            min_history_seconds=a.min_history_days * 86400,
                            min_baseline_events=a.min_baseline_events, z=a.z, min_bytes=a.min_bytes)
    res = parse_clf(a.log)
    index = build_indexes(res.events)
    print(f"Dataset sha256 : {res.evidence_id}")
    print(f"Lines          : {res.total_lines} total, {res.unparsed_lines} unparsed")
    print(f"Volume events  : {sum(len(i.rows) for i in index.values())} across {len(index)} accounts (hosts)")
    print(f"Config         : window {cfg.window_seconds}s, lookback {a.lookback_days}d, history >= {a.min_history_days}d, "
          f"min events {cfg.min_baseline_events}, z {cfg.z}, min_bytes {cfg.min_bytes}")

    status, candidates = Counter(), []
    for account in sorted(index):
        idx, last = index[account], None
        for epoch, dt, _, _ in idx.rows:
            if last is not None and epoch - last < cfg.window_seconds:
                continue                                     # keep hypothetical logins one window apart
            last = epoch
            a_ = idx.assess(dt, cfg)
            status[a_["status"]] += 1
            candidates.append((account, dt, key(a_)))

    evaluable = status["flagged"] + status["below_threshold"]
    print(f"\nHypothetical login times assessed: {sum(status.values())}")
    for k in ("flagged", "below_threshold", "insufficient_baseline"):
        print(f"  {k:<22}{status[k]}")
    if evaluable:
        print(f"\nBASE RATE (flagged / evaluable): {status['flagged'] / evaluable:.4f}  ({status['flagged']} of {evaluable})")
    else:
        print("\nNo evaluable times: lower --min-history-days / --min-baseline-events or use a longer trace.")

    step = max(1, len(candidates) // max(1, a.leak_sample))
    sample, mismatches = candidates[::step][:a.leak_sample], 0
    for account, dt, before in sample:
        idx = index[account]
        cut = bisect_left(idx.epochs, dt.timestamp() + cfg.window_seconds)      # only what a live system had seen
        after = AccountIndex(idx.rows[:cut]).assess(dt, cfg)
        mismatches += key(after) != before
    print(f"\nLEAK CHECK: {len(sample)} sampled times re-assessed on data truncated at the end of the window; "
          f"mismatches = {mismatches}  (must be 0)")


if __name__ == "__main__":
    main()