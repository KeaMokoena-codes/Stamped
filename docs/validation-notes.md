# Ingestion Parser Validation Notes (Issue #18)

Both ingestion parsers (`ingest/parsers/auth_log.py` and `ingest/parsers/cloudtrail_json.py`) were validated against public, third-party datasets committed under `data/public_samples/` to ensure parsing logic does not overfit to internal synthetic fixtures.

---

## 1. Public Datasets Sourced

| Dataset File | Format | Source & License | Scope |
|---|---|---|---|
| `data/public_samples/OpenSSH_2k.log` | OpenSSH `sshd` syslog | **Loghub (LOGPAI)** — `https://github.com/logpai/loghub` (CC BY 4.0; J. Zhu et al., ISSRE 2023) | 2,000 real server log lines from a lab OpenSSH server |
| `data/public_samples/aws_cloudtrail_public.json` | AWS CloudTrail via CloudWatch Logs | **AWS Archives** — `https://github.com/amazon-archives/cloudwatch-logs-subscription-consumer` (Apache-2.0) | CloudWatch `DATA_MESSAGE` subscription payload containing serialized CloudTrail `AwsApiCall` records |

---

## 2. What Broke on First Attempt and What Was Fixed

### 2.1 `ingest/parsers/auth_log.py` (v1.0.0 -> v1.1.0)
### 2.1 `ingest/parsers/auth_log.py` (v1.0.0 -> v1.1.0)
1. **Unaccounted Routine `sshd` Lines in Audit Metadata:**
   * **First attempt:** Out of 2,000 lines in `OpenSSH_2k.log`, 518 lines were `Failed password` or `Accepted password` events (`parsed_events = 518`) and `unparsed_lines = 0`. The remaining 1,482 lines were valid `sshd` messages (`Invalid user`, `pam_unix(sshd:auth)`, `Received disconnect`, `Connection closed`) that were silently skipped without being tallied in `stats`, making `parsed_events + unparsed_lines` (518) disagree with `total_lines` (2,000).
   * **Fix:** Added an explicit `ignored_lines` counter in `stats` and custody log details (`parsed_events: 518, ignored_lines: 1482, unparsed_lines: 0`) so every line in a sealed file is accounted for.
2. **December-to-January Year Rollover:**
   * **First attempt:** Standard `syslog` / `auth.log` timestamps lack a 4-digit year (`Dec 10 06:55:46`). Passing a static `base_year` causes multi-week logs that cross New Year's Eve (`Dec` -> `Jan`) to stamp January events 11 months *before* December events, breaking chronological timeline ordering.
   * **Fix:** Added monotonic month tracking (`prev_month`); when `line_month < prev_month`, `cur_year` increments by 1 automatically.

### 2.2 `ingest/parsers/cloudtrail_json.py` (v1.0.0 -> v1.1.0)
1. **CloudWatch Logs Subscription & EventBridge Envelopes:**
   * **First attempt:** When run against `aws_cloudtrail_public.json`, the parser expected a top-level `{"Records": [...]}` key. Because CloudWatch Logs subscription filters wrap CloudTrail events inside `{"messageType": "DATA_MESSAGE", "logEvents": [{"id": "...", "message": "{\"eventVersion\":\"1.02\",...}"}]}`, the initial parser treated the outer wrapper as a single malformed record (`parsed_events: 0, unparsed_records: 1`).
   * **Fix:** Updated `_extract_raw_records()` and `parse_cloudtrail_record()` to automatically unwrap CloudWatch `"logEvents"` (decoding each inner JSON `"message"` string) and EventBridge `"detail"` envelopes alongside standard `"Records"` lists.
2. **Root Identity Fallback & Empty `sourceIPAddress`:**
   * **First attempt:** The public CloudTrail sample includes `Root` account actions where `userIdentity.userName` is absent (only `arn` and `principalId` are populated), and some S3/internal CloudTrail records supply `""` for `sourceIPAddress`.
   * **Fix:** Confirmed hierarchical fallback (`userName` -> `arn` -> `principalId` -> `accountId`) and normalized blank `sourceIPAddress` strings to `None`.

---

## 3. Honest Limitations (For Pitch & Claims Audit)

* **Syslog Year & Timezone Inference:** Traditional `auth.log` files do not record a year or timezone offset. `auth_log.py` requires the caller to supply `base_year` and treats syslog timestamps as UTC. If a host logged in local non-UTC time without ISO 8601 headers, relative ordering within that file holds, but cross-source merging with UTC CloudTrail logs would be offset by the host's timezone unless configured.
* **Single-Line per Login Attempt Policy:** To avoid inflating brute-force failure counts on a single login attempt, `auth_log.py` only emits `NormalizedEvent` records for `Failed password` and `Accepted password|publickey` lines, categorizing companion `Invalid user` and `pam_unix` lines as `ignored_lines`.