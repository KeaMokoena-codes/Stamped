# Brute-force rule: validation notes and false positives

Rule: `brute_force_login` v1.1.0 (`detect/rules/brute_force.py`)

**Scope (v1.1.0):** only login events (`event_type == "auth"`) are counted. v1.0.0 counted any
event whose outcome was `failure`, so failed non-login actions such as CloudTrail `AccessDenied`
API calls could look like failed logins. Found by running the real CloudTrail parser into the rule;
covered by `tests/test_event_type_filter.py`. The SSH results in section 3 were produced with
v1.0.0. SSH logs contain only auth events, so v1.1.0 gives the same findings on them (re-run
`validate_brute_force.py` to confirm the table is unchanged).

## 1. Known false-positive scenarios

| Scenario | Why it triggers | How an examiner tells it apart |
|---|---|---|
| Legitimate password-reset or lockout-recovery flow | A user mistypes repeatedly, then succeeds, which looks like "failures then success" (high severity) | One account, one IP, usually the user's normal IP; failure cadence is slow and human; a reset or lockout-clear event nearby in the log |
| Stale saved password on a phone or mail client | The device retries automatically with the old password | Same account and device IP, regular retry interval (e.g. every 60s), failures continue for hours and never succeed |
| Shared or service account | Many users or jobs fail against the same account | Failures come from many distinct source IPs, not one; check the account type |
| Many users behind one NAT or proxy IP | The IP grouping sees combined failures from unrelated users | Failures span many distinct accounts with normal per-account counts; compare the account grouping |
| Monitoring or health checks, vulnerability scanners run by IT | Automated, high-rate failed attempts | Known scanner IP, fixed intervals, authorised change window |
| Misconfigured scheduled task or script | A job retries a bad credential | Perfectly regular timing, one account, one host, repeats daily |
| Account lockout cascade | Failures after lockout are counted as attempts | Failure reason in the raw log says "locked out" (parser should capture this if available) |

## 2. Known false negatives (not detected)

* Low-and-slow attacks that stay under `threshold` per `window_seconds`.
* Distributed attacks: one account, many IPs, each below threshold (the account grouping may still catch it).
* Attacks whose failures the parser labels `unknown`.
* Anything altered before sealing (outside Stamped's guarantees).

## 3. Validation on a public dataset

* Dataset: Loghub OpenSSH (real sshd auth log, 655,147 lines, ~28 days), loghub v8.
  SHA-256 of the file tested: `89eee9e36c182722f9fadc6e5617a4818ffc66109e7e222b8f9e8b78fc3aa2f3`
* Source and licence: https://doi.org/10.5281/zenodo.8196385, CC BY 4.0. Loghub requires
  citing the repository (https://github.com/logpai/loghub) and the Loghub paper.
  Citation: Curated by LOGPAI (2023). Loghub: A Large Collection of System Log Datasets
  for AI-driven Log Analytics [Dataset]. Zenodo.
* Ground-truth labels: the dataset has no attack labels, so these are WEAK labels.
  Malicious = an IP that tried at least one username that does not exist ("Invalid user").
  Benign = an IP with an "Accepted" login and no invalid-user attempts. Everything else is
  unlabelled and excluded from precision/recall.
* Contains benign traffic? Yes, but little: 663 malicious IPs and 42 benign IPs.
  Precision is measured on only 42 benign IPs, so treat it as indicative, not exact.
* Dimension scored: source_ip
* Parsing assumptions: the log has no year (2015 assumed) or timezone (treated as UTC).
  Only "Failed password" lines count as failures, one per attempt. All 655,147 lines parsed;
  160,609 became failure/success events.

Results, via `detect.validation.sweep_labeled`:

| threshold | window_s | TP | FP | FN | unlabelled flagged | precision | recall |
|---|---|---|---|---|---|---|---|
| 3 | 60 | 414 | 0 | 249 | 51 | 1.000 | 0.624 |
| 3 | 300 | 422 | 1 | 241 | 52 | 0.998 | 0.637 |
| 3 | 900 | 423 | 1 | 240 | 52 | 0.998 | 0.638 |
| 5 | 60 | 383 | 0 | 280 | 49 | 1.000 | 0.578 |
| 5 | 300 | 383 | 0 | 280 | 51 | 1.000 | 0.578 |
| 5 | 900 | 388 | 0 | 275 | 51 | 1.000 | 0.585 |
| 10 | 60 | 117 | 0 | 546 | 23 | 1.000 | 0.176 |
| 10 | 300 | 128 | 0 | 535 | 45 | 1.000 | 0.193 |
| 10 | 900 | 129 | 0 | 534 | 45 | 1.000 | 0.195 |
| 20 | 60 | 31 | 0 | 632 | 16 | 1.000 | 0.047 |
| 20 | 300 | 89 | 0 | 574 | 29 | 1.000 | 0.134 |
| 20 | 900 | 89 | 0 | 574 | 37 | 1.000 | 0.134 |

Chosen defaults: threshold 5, window 300s. Precision stays at 1.000 with recall 0.578,
the best recall before threshold 3 introduces a false positive. Threshold 10 (the original
default) found only 19% of the weakly-labelled attackers.

Caveats: the labels are heuristic. The "malicious" set is defined by invalid-user attempts,
which the rule does not look at, so the measurement is not circular. But most of the 285
missed IPs (FN) are probably low-and-slow attackers below the threshold (see section 2),
and the 51 unlabelled flagged IPs may be real attackers using valid usernames. Because the
benign set is only 42 IPs, a precision of 1.000 does not mean zero false positives in
production.