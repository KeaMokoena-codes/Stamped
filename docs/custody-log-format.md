# Custody log hash format

This is the canonical reference for how a custody log entry's hash is
computed. Any code that recomputes or verifies entry hashes, including the
independent verifier (Issue #1.5), must match this exactly. Implementation:
`seal/custody_log.py`. Pinned by golden-vector tests in
`tests/test_custody_log.py`.

## 1. Canonical serialization

Every serialization uses exactly these settings:

```python
json.dumps(x, sort_keys=True, separators=(",", ":"),
           ensure_ascii=True, allow_nan=False)
```

| Setting | Why it is pinned |
|---|---|
| `sort_keys=True` | Output must not depend on dict insertion order. |
| `separators=(",", ":")` | No spaces, so there is one possible byte layout. |
| `ensure_ascii=True` | Non-ASCII becomes `\uXXXX` (astral characters become surrogate pairs), so the output is pure ASCII and cannot differ by encoding or locale. |
| `allow_nan=False` | `NaN`/`Infinity` are not valid JSON and would hash differently across implementations; they are rejected with `ValueError`. |

None of these may be left to library defaults. If two correct implementations
serialize differently, the verifier reports tampering when nothing was changed.

**Guidance for `details`:** use strings, integers, booleans, `null`, lists and
objects. Avoid floats (store them as strings) because float formatting is not
guaranteed identical in other languages.

## 2. Fields included in the hash

```
{
  "timestamp_utc": "<ISO 8601 UTC string>",
  "actor":         "<string>",
  "role":          "<string>",
  "action":        "<string>",
  "evidence_id":   "<string>" | null,
  "artifact_id":   "<string>" | null,
  "details_json":  "<string>"
}
```

- `details_json` is itself the canonical JSON **string** of the `details`
  object (`{}` if none), embedded as a string value. It is therefore escaped a
  second time inside the outer JSON. This double encoding is intentional and
  is the most common mistake when re-implementing the format.
- `entry_id` and `entry_hash` are **not** included. `entry_id` is a database row
  locator, not evidence, and `entry_hash` is the output.
- `prev_hash` is not inside the JSON; it is appended (see below).

## 3. Hash formula

```
entry_hash = SHA256( canonical_json(fields) + prev_hash )
```

The input is the canonical JSON string followed directly by the 64-character
lowercase hex `prev_hash`, encoded as UTF-8. The output is lowercase hex.

## 4. Genesis entry

The first entry uses a fixed `prev_hash` of 64 `'0'` characters, never
`null` or empty:

```python
GENESIS_PREV_HASH = "0" * 64
```

## 5. Worked example (a test vector)

Computed by a standalone script that does not import `seal`. A verifier in any
language should reproduce it.

Fields:

```
timestamp_utc = 2026-10-05T08:30:00+00:00
actor         = ash
role          = examiner
action        = sealed
evidence_id   = abababababababababababababababababababababababababababababababab
artifact_id   = null
details       = {"note": "café", "n": 1}
prev_hash     = 0000000000000000000000000000000000000000000000000000000000000000
```

`details_json`:

```
{"n":1,"note":"caf\u00e9"}
```

Canonical JSON of the fields (single line):

```
{"action":"sealed","actor":"ash","artifact_id":null,"details_json":"{\"n\":1,\"note\":\"caf\\u00e9\"}","evidence_id":"abababababababababababababababababababababababababababababababab","role":"examiner","timestamp_utc":"2026-10-05T08:30:00+00:00"}
```

Resulting `entry_hash`:

```
2b2f3fb66296aede41737bf9d88bffac73de8abdacd9885c7716e909db27ef38
```

## 6. Verification

Walk entries in `entry_id` order. For each entry:

1. `prev_hash` must equal the previous entry's `entry_hash` (the genesis value for
   the first entry).
2. Recomputing the hash from the stored fields must equal the stored `entry_hash`.

The first entry that fails either check is reported. Changing any field of an
entry breaks that entry; deleting or reordering entries breaks the next link.

## 7. What protects the log, and what does not

**Database guards** (`schemas/schema.sql`): triggers abort any `UPDATE`,
`DELETE`, or `INSERT` that collides with an existing entry (this also blocks
`INSERT OR REPLACE`, which would otherwise delete a row without firing the
delete trigger), and a unique index on `prev_hash` makes a forked chain
impossible. No `update_entry`/`delete_entry` function exists anywhere in the
codebase (enforced by a test and by CI). These stop bugs and accidental or
application-level changes. They do **not** stop someone with direct access to
the database file, who can drop the triggers.

**Concurrent writers:** `append_entry` takes the database write lock before
reading the chain head, so two writers cannot read the same head and fork the
chain. A writer that cannot get the lock fails with "database is locked"
instead of writing a stale entry; callers should retry.

**What the chain alone cannot detect** (both are documented as tests):

- Removing the newest entries: a shorter chain is still self-consistent.
- An attacker who edits an entry and recomputes every later hash.

Detecting these requires an externally anchored copy of the head hash. That
is implemented in Issue #7 (`seal/anchor.py`, `verifier/anchor_check.py`); see
`docs/anchoring.md`. It only helps if the anchors are stored where the
application cannot rewrite them, and entries added after the newest anchor
remain unprotected until the next one. Do not describe the log as tamper-proof.