# Custody log hash format

This is the canonical reference for how a custody log entry's hash is
computed. Any code that recomputes or verifies entry hashes — including
the independent verifier (Issue #1.5) — must match this exactly.

## Canonical serialization

Fields are serialized with:

```python
json.dumps(fields, sort_keys=True, separators=(",", ":"))
```

`sort_keys=True` and fixed `separators` are required so the output is
byte-identical regardless of Python version or dict insertion order.
Without this, two correct implementations could compute different hashes
for the same logical entry — which would look exactly like tampering
even when nothing was actually changed.

## Fields included in the hash

```
{
  "timestamp_utc": "...",
  "actor": "...",
  "role": "...",
  "action": "...",
  "evidence_id": "..." | null,
  "artifact_id": "..." | null,
  "details_json": "..."   # already a canonical JSON string itself
}
```

`entry_id` and `entry_hash` are **not** included — `entry_id` is a
database row identifier, not evidentiary content, and `entry_hash` is the
output being computed.

## Hash formula

```
entry_hash = SHA256(canonical_json(fields) + prev_hash)
```

Where `prev_hash` is the `entry_hash` of the immediately preceding entry.

## Genesis entry

The very first entry in the log uses a fixed `prev_hash` of 64 `'0'`
characters — never `None` or an empty string — so the hash computation
never needs a special case for "no predecessor."

```python
GENESIS_PREV_HASH = "0" * 64
```

## Why this matters

Because each entry's hash depends on the one before it, changing any
past entry changes its own hash, which no longer matches the `prev_hash`
stored in the next entry, and so on for every entry after it. Verification
walks the chain in order and reports the first entry where this breaks —
that's what makes it possible to pinpoint exactly where tampering
occurred, rather than just saying "something in this log is wrong."