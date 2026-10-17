# Reproducible findings: pick any finding, show it can be re-derived

Code: `detect/reproduce.py`  ·  Tests: `tests/test_reproducibility.py`  ·  Demo: `scripts/repro_demo.py`

## 1. The claim, stated precisely

> Given **only the database and the sealed evidence**, any stored finding can be re-derived by re-running
> the **same parser and rule versions** with the **stored config**, and the result is **identical** to what
> was stored.

`reproduce(conn, finding_id, geo_db=None)` takes a database connection and a finding id. It is never handed
events, a finding, or a config, so it cannot "pass" by re-running a function on the variables the finding was
just computed from. It also never writes to the database (tested: no row changes, file bytes unchanged).

## 2. What it checks, in order

| # | Step | Passes when | Fails with |
|---|---|---|---|
| 1 | `stored_records` | `findings` and `artifacts` rows exist; `sha256(details_json) == finding_id == artifacts.output_hash`; rule name/version and `input_hash` agree in both tables | `mismatch` (edited record) / `cannot_reproduce` (no such finding) |
| 2 | `rule_version` | this build contains the exact `rule@version` that made the finding | `cannot_reproduce`. It never runs a different version in its place |
| 3 | `custody` | the custody hash chain verifies and a `finding_created` entry exists for the finding | `mismatch` |
| 4 | `evidence_sealed` | every evidence file named in `source_events` exists and still hashes to its `evidence_id` | `mismatch` (changed file) / `cannot_reproduce` (file missing) |
| 5 | `events_rederived` | the stored parser (same name **and version**) is re-run on the sealed file and reproduces the parser artifact's recorded `output_hash` (the hash of all parsed events) | `mismatch` (parser drift) / `cannot_reproduce` (parser version not in this build) |
| 6 | `input_hash` | the events named in `source_events` are picked from the re-derived events and their canonical hash equals the stored `input_hash` | `mismatch` |
| 7 | `rule_rerun` | the stored rule version, run with the stored config on exactly those events, regenerates the stored finding byte for byte | `mismatch` / `cannot_reproduce` (geolocation database missing or different) |

Results: **`reproduced`**, **`mismatch`** (something stored does not match what is re-derived: tampering,
corruption, or a rule/parser that changed behaviour without a version bump), or **`cannot_reproduce`**
(information needed is not available here). `cannot_reproduce` is **not** a pass, and the command exits non-zero.

There is no events table, so "re-fetch the exact input events by hash" is done by re-deriving them from the
sealed file: events are deterministic (`event_id` = hash of evidence id and line), the parser's recorded
`output_hash` proves the re-derived set is the original set, and `input_hash` proves the examined subset is.

## 3. Demo: "pick any finding, show it can be reproduced"

```powershell
python scripts/repro_demo.py build demo_out                      # seal a log, parse it, run the rules, store findings
python -m detect.reproduce --db demo_out\stamped.db --all --summary
python -m detect.reproduce --db demo_out\stamped.db 83de512d938b57b1      # every step for one finding (use an id prefix printed by --summary)
python scripts/repro_demo.py tamper demo_out                     # flip ONE bit of the sealed evidence
python -m detect.reproduce --db demo_out\stamped.db --all --summary   # MISMATCH at evidence_sealed
python scripts/repro_demo.py restore demo_out
```

Finding ids are shown by `build` and `--summary` as their first 16 characters; the CLI accepts any unique prefix
(8 or more characters), so you can paste what you see. For impossible-travel findings add `--geo-db path\to\the-same.mmdb`.

Result recorded on the public Loghub OpenSSH 2k sample (`data/public_samples/OpenSSH_2k.log`, year 2015 assumed):
518 parsed events, 17 findings, **17 reproduced**. After flipping one bit of the sealed file: **17 mismatch**, all at
`evidence_sealed`. After restoring it: 17 reproduced.

## 4. This was tested for the failure it exists to catch

The harness tests build the world through the real path (seal, parse, detect, record) into a database **file**,
drop everything in memory, and reopen the file with a fresh connection. Negative tests then damage one stored
thing at a time and require the failure at the intended step: edited finding, changed tool version, changed
`input_hash`, tampered or missing evidence, broken custody chain, unknown finding id, a rule or parser **version
this build lacks** (never substituted), a rule or parser that **changed without a version bump**, a missing or
different geolocation database, and **forged but internally consistent findings** (every hash recomputed) whose
only defect is a wrong `input_hash`, a false claim about the burst, or a pointer to the wrong source line.

The harness itself was sabotaged to confirm the tests can fail: skipping the input-hash comparison, the rule
re-run comparison, the sealed-file hash check, the parser output-hash check, the stored-details hash check, the
custody-chain check, or the "use the stored version" rule each made at least one test fail. (The first attempt at
the input-hash sabotage was NOT caught; that exposed a missing test for forged-but-consistent findings, now added.)

## 5. Limits (read before quoting the claim)

* **Only current versions can be re-run.** This build contains one version of each rule and parser. A finding stored
  under an older version (for example `brute_force_login@1.0.0`) reports `cannot_reproduce` until a frozen copy of
  that version is kept. When a rule changes, bump its version; do not edit it in place.
* **Impossible travel needs the exact geolocation database.** Its SHA-256 is stored in the finding; a missing or
  different file gives `cannot_reproduce`, never a pass. The database is not in git.
* **The auth.log year is not recorded by the parser.** The harness tries the years around the finding's own
  timestamps and accepts only one that reproduces the parser's recorded `output_hash`, and says so in its output.
  Recording `base_year` in the parser artifact's `metadata_json` would remove the inference (a change to Abdi's file,
  not made here).
* **`large_access` is not supported** (`cannot_reproduce` at `rule_version`): no parser emits its `data_access`
  events yet, so there is nothing real to re-derive them from.
* **The timeline (#19) is not a finding.** It has no stored hash or version, so there is nothing to re-derive from a
  stored hash. What is tested is that it is rebuilt identically from stored findings and re-derived events and that
  every finding entry points at a stored finding.
* **Scope of the proof.** This shows the finding follows from the sealed evidence and the recorded versions. It does
  not show the rule is *correct* (see the validation notes), and it cannot detect an attacker who rewrites the
  database, the custody log and the evidence file consistently; external anchoring (`seal/anchor.py`) addresses that.
* A future change to `NormalizedEvent` (for example adding `bytes_out`) changes event hashes, so findings stored
  before it will stop reproducing. This is the harness working as intended; regenerate findings after such a change.