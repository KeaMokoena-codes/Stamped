# Role-based access (Issue #9)

Stamped has three roles. What each may see, edit and export is enforced **in the data-access layer**
(`access/`), not in the interface. The Streamlit UI must read case data only through the functions in
`access/`; it must never query the database itself. If someone manipulates the interface, or calls these
functions directly with no interface at all, a restricted role still receives a restricted object: the
forbidden fields are **absent from what is returned**, not hidden when drawn.

| File | Job |
|---|---|
| `access/roles.py` | The three roles, the permissions matrix and the field-by-field visibility policy. Pure data. |
| `access/masking.py` | Applies the policy: allow-list projection, pseudonyms, free-text scrubbing. |
| `access/data.py` | The functions the UI calls. Authorize, fetch, project, **log**, then return. |

## How the UI uses it

```python
from access import (Pseudonymizer, get_findings, get_timeline, get_custody_log, export_findings, resolve_role)

pz = Pseudonymizer.from_key_file("keys/pseudonym.key")        # once, at start-up
role = resolve_role(conn, user_id)                            # from the users table, not from a drop-down
rows = get_findings(conn, role, user_id, pseudonymizer=pz)    # already restricted for this role
timeline = get_timeline(conn, role, user_id, events, pseudonymizer=pz)
report = export_findings(conn, role, user_id, pseudonymizer=pz)   # report.content, report.sha256
```

Every function takes the connection, the **role**, and the **actor** (who is asking), and returns plain
dicts. The connection must be writable and have no transaction open, because each call records itself in
the custody log (below). `can(role, Resource.FINDINGS, Action.EXPORT)` is available for showing or hiding a
button, but it is only a convenience: the functions enforce the same rule themselves.

Generate the pseudonym key once per deployment and keep it with the other secrets (`*.key` and `keys/` are
already in `.gitignore`):

```python
Pseudonymizer.generate_key_file("keys/pseudonym.key")         # random, owner-only, refuses to overwrite
```

## Role-specific dashboards

The Streamlit landing view is organized around each role's workflow:

* **Examiner:** full-fidelity evidence register and analysis findings, with the verification demo in the sidebar.
* **Investigating officer:** operational leads, a severity filter, and the evidence available for investigation.
* **Prosecutor:** a case brief with findings, the evidence schedule, and the chain-of-custody record.

The sidebar identifies the active workflow for the role resolved from the signed-in user. The dashboard tables
are populated only by the `get_evidence`, `get_findings`, and `get_custody_log` access-layer
functions. The officer's severity filter is applied only after `get_findings` has returned projected rows.
Page visibility and navigation are presentation choices, not authorization: opening a page directly or
manipulating its Streamlit route still executes the same page function and access-layer projection for the
registered user's role. Do not query case tables from a page or use UI-only masking.

## Who may do what

`view`, `edit`, `export` per resource. Anything not listed is refused.

| Resource | Examiner | Investigating officer | Prosecutor |
|---|---|---|---|
| Evidence | view, edit, export | view | view |
| Timeline | view, export | view, export | view |
| Findings | view, edit, export | view, export | view, export |
| Custody log | view, export | view, export | view, export |

Nobody can edit the custody log; it is append-only. Edit rights matter at the places that *write*:
sealing evidence and recording findings should call `access.authorize(conn, actor, role, resource, Action.EDIT)`
first. (They do not yet; see "What this does not do".)

Why each role gets what it gets (change the tables in `access/roles.py` if your organisation decides otherwise):

* **Examiner** acquires, seals and analyses evidence, so sees everything, raw.
* **Investigating officer** pursues the suspect and needs real account names and IP addresses to do it. Does
  not need the examiner's internal data: file-system paths, free-form collection metadata, the name of the
  geolocation database.
* **Prosecutor** builds the case from the findings and the chain of custody. Does not need third parties'
  account names or IP addresses, so they are replaced with pseudonyms, and the coordinates inferred for an IP
  address are withheld. Distances, speeds, counts, times, hashes and rule wording stay, so the case can still
  be argued and checked.

## Which pages each role is offered

The menu offers a role only the pages it needs, and each page also checks this itself, so a page opened by its
address behaves the same way. The rules are `PAGE_ACCESS` in `access/roles.py` (default deny: a page that is
not listed cannot be opened). This decides what is shown; the data functions still enforce the permissions
above on every read.

| Page | Needs | Examiner | Investigating officer | Prosecutor |
|---|---|---|---|---|
| Case overview | view evidence and findings | yes | yes | yes |
| Timeline | view timeline | yes | yes | yes |
| Findings | view findings | yes | yes | yes |
| Custody history | view custody log | yes | yes | yes |
| Verification (tamper-detection demo) | edit evidence | yes | no | no |
| Reports | export at least one dataset | yes | yes | yes |

Before anyone has signed in, the screen shows only the sign-in box. It does not mention the database, how to
set the system up, whether an ID exists or is disabled, or any case data.

## Which personal identifiers are masked, for which roles

| Identifier | Examiner | Investigating officer | Prosecutor |
|---|---|---|---|
| Account names (`account`, a finding's `key` when grouped by account) | real | real | pseudonym `acct-xxxxxxxxxx` |
| Source IP addresses (`source_ip`, `logins[].source_ip`, `login.source_ip`, `window.source_ips`, a finding's `key` when grouped by IP) | real | real | pseudonym `ip-xxxxxxxxxx` |
| Coordinates inferred from an IP (`logins[].lat`, `logins[].lon`) | real | real | **hidden** |
| Original file name of evidence (`original_name`) | real | real | **hidden** |
| Account names and IP addresses written inside titles, descriptions and summaries | real | real | replaced by the same pseudonyms; any other IP address in the text is also replaced |
| File-system paths, free-form collection metadata, geolocation database name, raw stored JSON text | real | **hidden** | **hidden** |

Collector and actor names (the staff who handled evidence) are shown to all roles: the chain of custody is
meaningless without them.

### Names for the screen (`get_directory`)

The dashboard and the custody report show a user's `display_name`, an evidence item's `original_name` and
capture time, and a finding's title instead of bare identifiers. `get_directory()` supplies those names. It is
**display only**: the names are never written into a custody entry, never hashed, and never added to an
`export_*` result or the verifier package, which keep using the stored identifiers. The identifier is still
shown beside the name in the report and under "Technical details" in the dashboard, and an identifier with no
matching record (a missing user, a deleted evidence item, a process such as `ingest`) is simply shown as it is.

A name never reveals more than the same role can already read elsewhere: evidence names and finding titles are
built from the same projected rows as `get_evidence` / `get_findings` (a prosecutor gets no `original_name`,
so sees "Evidence item" and a short id, and finding titles arrive with identifiers already masked). A user's
`display_name` follows the same rule as the custody-log `actor` (shown to every role); to hide it from a role,
change that one line (`USER_FIELDS` in `access/roles.py`).

### Full field-by-field policy

"shown" means the stored value. A field that is not in these tables is **hidden from every role except the
examiner** (this is an allow-list, so a column or JSON key added later is invisible to restricted roles until it
is listed here and in `access/roles.py`). This section is checked against the code by
`tests/test_access.py::test_every_listed_field_is_documented`.

#### Evidence (`get_evidence`)

| Field | Examiner | Investigating officer | Prosecutor |
|---|---|---|---|
| `evidence_id` | shown | shown | shown |
| `content_hash` | shown | shown | shown |
| `source` | shown | shown | shown |
| `collector` | shown | shown | shown |
| `captured_at` | shown | shown | shown |
| `sealed_at` | shown | shown | shown |
| `original_name` | shown | shown | **hidden** |
| `sealed_path` | shown | **hidden** | **hidden** |
| `metadata_json` | shown | **hidden** | **hidden** |

#### Findings (`get_findings`, and findings inside the timeline)

| Field | Examiner | Investigating officer | Prosecutor |
|---|---|---|---|
| `finding_id` | shown | shown | shown |
| `source_evidence_id` | shown | shown | shown |
| `artifact_id` | shown | shown | shown |
| `rule_id` | shown | shown | shown |
| `severity` | shown | shown | shown |
| `created_at` | shown | shown | shown |
| `title` | shown | shown | **pseudonym** |
| `description` | shown | shown | **pseudonym** |
| `details_json` | shown | **hidden** | **hidden** |
| `details.finding_id` | shown | shown | shown |
| `details.source_evidence_id` | shown | shown | shown |
| `details.artifact_id` | shown | shown | shown |
| `details.rule_id` | shown | shown | shown |
| `details.created_at` | shown | shown | shown |
| `details.finding_hash` | shown | shown | shown |
| `details.input_hash` | shown | shown | shown |
| `details.rule_name` | shown | shown | shown |
| `details.rule_version` | shown | shown | shown |
| `details.config` | shown | shown | shown |
| `details.severity` | shown | shown | shown |
| `details.grouped_by` | shown | shown | shown |
| `details.key` | shown | shown | **pseudonym** |
| `details.title` | shown | shown | **pseudonym** |
| `details.description` | shown | shown | **pseudonym** |
| `details.first_seen` | shown | shown | shown |
| `details.last_seen` | shown | shown | shown |
| `details.failure_count` | shown | shown | shown |
| `details.followed_by_success` | shown | shown | shown |
| `details.distance_km` | shown | shown | shown |
| `details.elapsed_seconds` | shown | shown | shown |
| `details.speed_kmh` | shown | shown | shown |
| `details.instantaneous` | shown | shown | shown |
| `details.logins[].event_id` | shown | shown | shown |
| `details.logins[].timestamp_utc` | shown | shown | shown |
| `details.logins[].source_ip` | shown | shown | **pseudonym** |
| `details.logins[].lat` | shown | shown | **hidden** |
| `details.logins[].lon` | shown | shown | **hidden** |
| `details.login.event_id` | shown | shown | shown |
| `details.login.timestamp_utc` | shown | shown | shown |
| `details.login.source_ip` | shown | shown | **pseudonym** |
| `details.window.start` | shown | shown | shown |
| `details.window.end` | shown | shown | shown |
| `details.window.bytes` | shown | shown | shown |
| `details.window.event_count` | shown | shown | shown |
| `details.window.source_ips[]` | shown | shown | **pseudonym** |
| `details.baseline.lookback_seconds` | shown | shown | shown |
| `details.baseline.bucket_seconds` | shown | shown | shown |
| `details.baseline.n_buckets` | shown | shown | shown |
| `details.baseline.n_events` | shown | shown | shown |
| `details.baseline.mean_bytes_per_bucket` | shown | shown | shown |
| `details.baseline.std_bytes_per_bucket` | shown | shown | shown |
| `details.baseline.threshold_bytes` | shown | shown | shown |
| `details.baseline.window_multiple_of_mean` | shown | shown | shown |
| `details.baseline.events_hash` | shown | shown | shown |
| `details.baseline.evidence_ids[]` | shown | shown | shown |
| `details.source_events[].event_id` | shown | shown | shown |
| `details.source_events[].evidence_id` | shown | shown | shown |
| `details.source_events[].raw_ref` | shown | shown | shown |
| `details.geo_source` | shown | **hidden** | **hidden** |
| `details.details_json` | shown | **hidden** | **hidden** |

#### Timeline entries that are events (`get_timeline`)

| Field | Examiner | Investigating officer | Prosecutor |
|---|---|---|---|
| `entry_type` | shown | shown | shown |
| `id` | shown | shown | shown |
| `timestamp_utc` | shown | shown | shown |
| `event_type` | shown | shown | shown |
| `outcome` | shown | shown | shown |
| `severity` | shown | shown | shown |
| `service` | shown | shown | shown |
| `account` | shown | shown | **pseudonym** |
| `source_ip` | shown | shown | **pseudonym** |
| `summary` | shown | shown | **pseudonym** |
| `provenance.evidence_id` | shown | shown | shown |
| `provenance.raw_ref` | shown | shown | shown |
| `provenance.event_id` | shown | shown | shown |
| `provenance.finding_id` | shown | shown | shown |
| `provenance.artifact_id` | shown | shown | shown |
| `provenance.rule_id` | shown | shown | shown |
| `provenance.input_hash` | shown | shown | shown |
| `provenance.evidence_ids[]` | shown | shown | shown |
| `provenance.source_events[].event_id` | shown | shown | shown |
| `provenance.source_events[].evidence_id` | shown | shown | shown |
| `provenance.source_events[].raw_ref` | shown | shown | shown |
| `details.event_id` | shown | shown | shown |
| `details.evidence_id` | shown | shown | shown |
| `details.raw_ref` | shown | shown | shown |
| `details.timestamp_utc` | shown | shown | shown |
| `details.event_type` | shown | shown | shown |
| `details.outcome` | shown | shown | shown |
| `details.service` | shown | shown | shown |
| `details.bytes_out` | shown | shown | shown |
| `details.account` | shown | shown | **pseudonym** |
| `details.source_ip` | shown | shown | **pseudonym** |

#### Timeline entries that are findings (`get_timeline`)

| Field | Examiner | Investigating officer | Prosecutor |
|---|---|---|---|
| `entry_type` | shown | shown | shown |
| `id` | shown | shown | shown |
| `timestamp_utc` | shown | shown | shown |
| `event_type` | shown | shown | shown |
| `outcome` | shown | shown | shown |
| `severity` | shown | shown | shown |
| `service` | shown | shown | shown |
| `account` | shown | shown | **pseudonym** |
| `source_ip` | shown | shown | **pseudonym** |
| `summary` | shown | shown | **pseudonym** |
| `provenance.evidence_id` | shown | shown | shown |
| `provenance.raw_ref` | shown | shown | shown |
| `provenance.event_id` | shown | shown | shown |
| `provenance.finding_id` | shown | shown | shown |
| `provenance.artifact_id` | shown | shown | shown |
| `provenance.rule_id` | shown | shown | shown |
| `provenance.input_hash` | shown | shown | shown |
| `provenance.evidence_ids[]` | shown | shown | shown |
| `provenance.source_events[].event_id` | shown | shown | shown |
| `provenance.source_events[].evidence_id` | shown | shown | shown |
| `provenance.source_events[].raw_ref` | shown | shown | shown |
| `details.finding_id` | shown | shown | shown |
| `details.source_evidence_id` | shown | shown | shown |
| `details.artifact_id` | shown | shown | shown |
| `details.rule_id` | shown | shown | shown |
| `details.created_at` | shown | shown | shown |
| `details.finding_hash` | shown | shown | shown |
| `details.input_hash` | shown | shown | shown |
| `details.rule_name` | shown | shown | shown |
| `details.rule_version` | shown | shown | shown |
| `details.config` | shown | shown | shown |
| `details.severity` | shown | shown | shown |
| `details.grouped_by` | shown | shown | shown |
| `details.key` | shown | shown | **pseudonym** |
| `details.title` | shown | shown | **pseudonym** |
| `details.description` | shown | shown | **pseudonym** |
| `details.first_seen` | shown | shown | shown |
| `details.last_seen` | shown | shown | shown |
| `details.failure_count` | shown | shown | shown |
| `details.followed_by_success` | shown | shown | shown |
| `details.distance_km` | shown | shown | shown |
| `details.elapsed_seconds` | shown | shown | shown |
| `details.speed_kmh` | shown | shown | shown |
| `details.instantaneous` | shown | shown | shown |
| `details.logins[].event_id` | shown | shown | shown |
| `details.logins[].timestamp_utc` | shown | shown | shown |
| `details.logins[].source_ip` | shown | shown | **pseudonym** |
| `details.logins[].lat` | shown | shown | **hidden** |
| `details.logins[].lon` | shown | shown | **hidden** |
| `details.login.event_id` | shown | shown | shown |
| `details.login.timestamp_utc` | shown | shown | shown |
| `details.login.source_ip` | shown | shown | **pseudonym** |
| `details.window.start` | shown | shown | shown |
| `details.window.end` | shown | shown | shown |
| `details.window.bytes` | shown | shown | shown |
| `details.window.event_count` | shown | shown | shown |
| `details.window.source_ips[]` | shown | shown | **pseudonym** |
| `details.baseline.lookback_seconds` | shown | shown | shown |
| `details.baseline.bucket_seconds` | shown | shown | shown |
| `details.baseline.n_buckets` | shown | shown | shown |
| `details.baseline.n_events` | shown | shown | shown |
| `details.baseline.mean_bytes_per_bucket` | shown | shown | shown |
| `details.baseline.std_bytes_per_bucket` | shown | shown | shown |
| `details.baseline.threshold_bytes` | shown | shown | shown |
| `details.baseline.window_multiple_of_mean` | shown | shown | shown |
| `details.baseline.events_hash` | shown | shown | shown |
| `details.baseline.evidence_ids[]` | shown | shown | shown |
| `details.source_events[].event_id` | shown | shown | shown |
| `details.source_events[].evidence_id` | shown | shown | shown |
| `details.source_events[].raw_ref` | shown | shown | shown |
| `details.geo_source` | shown | **hidden** | **hidden** |
| `details.details_json` | shown | **hidden** | **hidden** |

#### Custody log (`get_custody_log`)

| Field | Examiner | Investigating officer | Prosecutor |
|---|---|---|---|
| `entry_id` | shown | shown | shown |
| `timestamp_utc` | shown | shown | shown |
| `actor` | shown | shown | shown |
| `role` | shown | shown | shown |
| `action` | shown | shown | shown |
| `evidence_id` | shown | shown | shown |
| `artifact_id` | shown | shown | shown |
| `prev_hash` | shown | shown | shown |
| `entry_hash` | shown | shown | shown |
| `details_json` | shown | **hidden** | **hidden** |
| `details.reason` | shown | shown | shown |
| `details.note` | shown | shown | shown |
| `details.content_hash` | shown | shown | shown |
| `details.tool_name` | shown | shown | shown |
| `details.tool_version` | shown | shown | shown |
| `details.events_count` | shown | shown | shown |
| `details.ignored_count` | shown | shown | shown |
| `details.unparsed_count` | shown | shown | shown |
| `details.rule_id` | shown | shown | shown |
| `details.input_hash` | shown | shown | shown |
| `details.finding_hash` | shown | shown | shown |
| `details.severity` | shown | shown | shown |
| `details.source_events[].event_id` | shown | shown | shown |
| `details.source_events[].evidence_id` | shown | shown | shown |
| `details.source_events[].raw_ref` | shown | shown | shown |
| `details.triggered_by[]` | shown | shown | shown |
| `details.anchor_id` | shown | shown | shown |
| `details.anchored_entry_id` | shown | shown | shown |
| `details.anchored_entry_hash` | shown | shown | shown |
| `details.seq` | shown | shown | shown |
| `details.location_assurance` | shown | shown | shown |
| `details.sealed_path` | shown | **hidden** | **hidden** |
| `details.attempted_path` | shown | **hidden** | **hidden** |
| `details.error` | shown | **hidden** | **hidden** |
| `details.dataset` | shown | shown | shown |
| `details.resource` | shown | shown | shown |
| `details.action` | shown | shown | shown |
| `details.count` | shown | shown | shown |
| `details.ids[]` | shown | shown | shown |
| `details.ids_truncated` | shown | shown | shown |
| `details.filters.evidence_id` | shown | shown | shown |
| `details.filters.finding_id` | shown | shown | shown |
| `details.identifiers` | shown | shown | shown |
| `details.export_sha256` | shown | shown | shown |
| `details.export_bytes` | shown | shown | shown |
| `details.events` | shown | shown | shown |
| `details.findings` | shown | shown | shown |
| `details.evidence_ids[]` | shown | shown | shown |
| `details.first_entry_id` | shown | shown | shown |
| `details.last_entry_id` | shown | shown | shown |
| `details.attempted_role` | shown | **hidden** | **hidden** |

#### Users (`get_directory`)

| Field | Examiner | Investigating officer | Prosecutor |
|---|---|---|---|
| `user_id` | shown | shown | shown |
| `display_name` | shown | shown | shown |
| `role` | shown | shown | shown |

## Pseudonyms

A pseudonym is `HMAC-SHA256(secret key, kind + value)` shortened to 10 hex characters. The same account (or
address) always gets the same token, so a prosecutor can follow "`acct-3fa91c2d7b` failed 12 logins, then
`acct-3fa91c2d7b` moved 500 MB", and tokens are the same in the findings view and in the timeline. Without the
key a token cannot be reversed or checked against a guessed name. The key is **required**: there is deliberately
no fallback to an unkeyed hash, because there are only about four billion IPv4 addresses and an unkeyed hash of
one can be reversed by trying them all. Asking for data as a prosecutor without a key raises
`PseudonymizerRequired`.

Pseudonymised is not anonymous. Whoever holds the key can re-link a token to a person, and a prosecutor who also
holds other information (a name that appears elsewhere in the case file) may be able to work out who a token is.
Treat the key like a signing key. Rotating it changes every token.

### Free text

Rules write sentences such as "Impossible travel for account bob ... from 1.2.3.4". For a pseudonymising role,
every identifier found in the structured fields of the same result is replaced in the sentence by its token, and
afterwards *any* IP address still in the text is replaced as well. If an identifier is too short or common to
replace safely inside a sentence (an account called `1`, `ab` or `for`), the whole sentence is withheld instead
of being garbled or leaked; the structured fields still carry the facts. Over-masking is the safe failure.

## Reads and exports are custody entries

Every call writes a custody entry **before** any data is returned, using the existing append-only log:

| Action | Written when | Details recorded |
|---|---|---|
| `viewed_evidence`, `viewed_findings`, `viewed_timeline`, `viewed_custody_log`, `viewed_directory` | a view (`viewed_directory` is the look-up of names for the screen; it records counts, never the names) | dataset, record count, record ids (hashes), filters, whether identifiers were raw or pseudonymized |
| `exported_findings`, `exported_timeline`, `exported_custody_log` | an export | the above plus `export_sha256` and `export_bytes` of exactly what was handed over |
| `access_denied` | a refusal (wrong role, unknown role, unknown or inactive user) | resource, action, reason; an unrecognised role is truncated to 64 characters |

The entry carries the actor and the role. It **never** contains an account name, an IP address, a path or any
other identifier: the log cannot be corrected afterwards, so personal data must not be written into it.

Fail-closed behaviour (each is a test):

* If the custody entry cannot be written (disk full, read-only connection), **no data is returned**.
* A refusal is still a refusal even if the denial itself cannot be logged.
* A call with no named actor is rejected and nothing is recorded.
* Calling while the connection has a transaction open is refused, so a rollback can never silently erase the
  record that a read happened.
* An unrecognised role is never defaulted or fuzzily matched: `"Prosecutor"`, `" prosecutor"`, `"admin"` and
  `None` are all refused.

## What this does not do

* **The role is trusted input.** This layer enforces the role it is given. Tying a login to a role is
  `resolve_role()` (reads the `users` table, refuses unknown or inactive users); authenticating the person is
  the UI's job. A role drop-down that is only a drop-down lets anyone pick "examiner".
* **A raw database file or a verifier export package is not role-filtered.** `stamped.db` contains everything.
  Never hand it to a restricted role; hand them an `export_*` result instead. (The verifier package for a third
  party is a deliberate full copy, because verification needs the exact stored bytes.)
* **A masked custody log cannot be hash-verified.** Restricted roles receive the parsed, projected details, not
  the raw text the hash covers. Chain verification is what `verifier/verify.py` does on a full package.
* **Events are not in the database.** `get_timeline` takes the events the parsers produced. Do not give those raw
  events to the UI any other way.
* **Write paths do not enforce roles yet.** `seal_evidence`, the parsers and `record_finding` still take a
  caller-supplied `role` string that is only recorded. They should call `authorize(..., Action.EDIT)` first.
* **Re-identification.** Timestamps, volumes and distances remain visible and may help someone who already holds
  other facts to guess whose activity a pseudonym is.
* **Free text from a future rule.** Identifiers are scrubbed by matching the ones found in the structured fields
  plus any IP address. If a new rule writes an identifier into a sentence without also placing it in a listed
  structured field, it will not be recognised; add the field to the policy when adding the rule.

This design supports POPIA-style safeguards (minimisation, purpose-limited views, an accountability record of who
accessed what). It does not make an organisation compliant on its own.