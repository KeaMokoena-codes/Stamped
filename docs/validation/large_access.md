# Large access after a flagged login: method and validation notes

Rule: `large_access` v1.0.0 (`detect/rules/large_access.py`)

## 1. What it answers

"What did they take?" It is **not** a standalone volume alarm. It runs only for a login that another rule
already flagged, and asks whether that account moved far more data than usual in the window right after it.

| Trigger | Login used |
|---|---|
| `brute_force_login` with `followed_by_success` | the success that followed the burst |
| `impossible_travel` | the second login |

A brute-force burst with no success has no login to follow and is skipped. Several triggers on one login
(account and IP groupings) produce one finding that lists all of them.

## 2. Baseline definition 

Per account, using only the past:

1. `login_t` = time of the flagged login. Buckets are `window_seconds` long (default 1 hour).
2. The lookback (default 14 days) is split into consecutive buckets that **end at `login_t`**.
3. Each bucket's total is the bytes of that account's volume events in it. **Empty buckets count as zero**,
   so a quiet account has a low mean and a bursty account has a high spread.
4. `baseline mean` and `baseline std` are the population mean and standard deviation of those totals.
5. `threshold = mean + z * std` (default z = 3).
6. `window volume` = bytes in `login_t <= t < login_t + window_seconds`.
7. **Flag** when `window volume >= min_bytes` (default 100 MB) **and** `window volume > threshold`.

An account with fewer than `min_baseline_events` baseline events (default 10) or less than
`min_history_seconds` of observed history (default 7 days) has no trustworthy baseline. It is **not flagged**
and `assess_triggers()` reports it as `insufficient_baseline`. We do not guess.

Volume events are `event_type == "data_access"`, `outcome == "success"`, with an account and an integer
`bytes_out >= 0`. Volume is attributed to the **account**, not to the login's IP, so the legitimate owner's
activity in the same window is also counted. That can only raise a finding, never hide one.

## 3. No future data in the baseline (guardrail)

The baseline stops strictly before `login_t` and the window starts at it, so they never overlap, and nothing
after `login_t + window_seconds` is read. This is tested, not just asserted:

* appending data after the window changes neither the finding nor its hashes;
* a "streaming" run on data cut off at the end of the window produces **identical** findings to the full run;
* an event exactly at `login_t` counts as window, not baseline;
* moving the trigger earlier does not let a later spike leak backwards;
* deliberately breaking the baseline (including the window, or using the whole history) makes these tests
  fail. This was tried, so the tests can detect the bug they exist for.

On real data the same check runs in `validate_large_access.py` (section 6).

## 4. The link to the earlier finding is stored data (guardrail)

* Every finding carries `triggered_by`: the `finding_hash` of each real triggering finding. The hashes are part
  of the finding's `input_hash` and `finding_hash`.
* A trigger whose `finding_hash` does not match its own content is rejected (`finding_hash_mismatch`).
* `detect.findings.record_finding` **refuses to store** the finding unless every trigger is already a stored
  finding, so the link can never point at nothing.
* In the database, `artifacts.source_artifact_id` is set to the (first, sorted) trigger finding and
  `source_evidence_id` is NULL (the frozen schema requires exactly one source). All triggers are in
  `artifacts.metadata_json` and in every custody-log entry. A SQL join from the new finding to the trigger
  finding is tested.

Schema note for Ash: this uses the existing `source_artifact_id` as designed. No schema change. It does mean a
large-access artifact has no direct `source_evidence_id`; its evidence is reached through the trigger and is
listed in `metadata_json`.

## 5. Provenance

`input_hash` covers exactly what the rule read: the trigger hashes, the login event, every window event and
every baseline event (also summarised by `baseline.events_hash`). Unrelated accounts' events do not change it;
changing any baseline event does. `source_events` links the login and the window events back to raw lines;
the baseline's evidence ids are in `baseline.evidence_ids` and get custody entries too.

## 6. Public-dataset validation: what exists and what does not

**No public dataset contains both flagged logins and per-account data volume**, so end-to-end accuracy
(precision/recall of "what they took") **cannot be measured on public data**. Nothing here claims it.

* **CERT insider-threat data (CMU):** public and widely used, but synthetic, and its logon records carry no IP
  addresses and no failures. It cannot produce brute-force or travel triggers. (Its volume fields were not
  verified from here.)
* **NASA-HTTP (Internet Traffic Archive, July 1995):** real traffic with real reply sizes per requesting host,
  3.4M requests. It has no logins. The archive asks users not to analyse beyond general traffic patterns, so
  **only aggregate numbers are reported, never individual hosts.**

What we can measure on real data is the **baseline method itself**:

* **Base rate:** treating each host as an "account", hypothetical login times are placed along its timeline.
  The share whose next window exceeds `mean + z*std` is how often a volume-only alarm would fire on natural
  traffic. A high rate is the reason this rule requires a flagged login first.
* **Leak check:** a sample of those times is re-assessed on data truncated at the end of the window.
  Mismatches must be 0.

Run: `python detect/datasets/scripts/validate_large_access.py <NASA July log>`

Results :
* Dataset: NASA-HTTP, July 1995 (`NASA_access_log_Jul95.gz`), SHA-256 199109ed0f273e095da6ccd5fc9dc4cd8bb58daa06d62135e62090fea9d27488
* Lines: 1,891,717 total, 5 unparsed. Volume events: 1,701,451 across 81,075 accounts (hosts)
* Config: window 3600 s, lookback 7 d, history >= 3 d, min events 10, z 3.0, min_bytes 0
  (the rule's own defaults are 14 d / 7 d / 100 MB; the script lowers them to fit a one-month trace and
  sets min_bytes 0 to expose the raw statistical rate)
* Assessed 158,045 hypothetical login times: flagged 14,240, below threshold 23,865, insufficient baseline 119,940
* Base rate (flagged / evaluable): 0.3737 (14,240 of 38,105)
* Leak check: 1,000 sampled times re-assessed on data truncated at the end of the window; mismatches = 0


About 37% of evaluable moments on ordinary traffic exceed mean + 3σ. The cause is heavy-tailed traffic: with so many empty hours, the mean and spread are tiny, so a single normal burst crosses the threshold. A volume-only alarm would be unusable, so the rule runs only after a flagged login and also needs min_bytes. This number measures how noisy the baseline test is, not detection accuracy. No labelled data exists to measure that.

## 7. Known limits

* z, `min_bytes` and the window are starting points, not tuned (no labelled data exists).
* Volume data is heavy-tailed, so a mean + z*std threshold is noisy. See the base rate above.
* Bulk downloads are legitimate for some accounts (backups, exports). The mean and spread absorb regular ones.
* Attribution is by account (section 2). An attacker using a different account is not covered.
* Staged exfiltration across many windows or below `min_bytes` is not detected.
* Only events after the login within one window are checked, so slow exfiltration is missed.

## 8. Integration dependencies

* **Volume field.** `NormalizedEvent` has no byte count, so parsed events cannot carry volume yet. This rule
  and its loader use dict events with `event_type="data_access"` and an integer `bytes_out`. Proposal for
  Abdi, not applied: optional `bytes_out: Optional[int] = None` and `resource: Optional[str] = None` on
  `NormalizedEvent`. Note that adding fields changes the dict that other rules hash, so `input_hash` values
  of findings made before the change will not reproduce; regenerate them.
* **CloudTrail.** S3 data events reportedly carry `additionalEventData.bytesTransferredOut`. Verify on real
  logs before relying on it.
* **Demo data.** A bundle needs at least `min_history_seconds` of ordinary activity for an account, then a
  flagged login, then a large transfer, or the rule will correctly say "insufficient baseline".
* **Contract.** Parsers must emit `data_access` only for real transfers, with `outcome` meaning the transfer
  succeeded.