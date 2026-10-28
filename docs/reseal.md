# Re-sealing (evidence renewal)

Implements Issue #10. Implementation: `seal/reseal.py`. Independent check:
`verifier/verify.py` (check 4). Pinned by `tests/test_reseal.py`.

## Why

A case sealed in 2026 may be challenged in 2041. By then the signatures on its
anchors (Ed25519 + ML-DSA-65) may no longer be trusted. Re-sealing wraps an old
stretch of the custody log in a **new checkpoint signed with a newer or
stronger suite** (Ed448 + ML-DSA-87), without breaking or rewriting the
historical record.

## What a re-seal is

One new custody-log entry with `action = "resealed"`, appended at the end of
the chain like any other entry. It therefore sits inside the SHA-256 hash chain
and inside later anchors. Its `details_json` is the canonical JSON of:

```json
{
  "format": "stamped-reseal/1",
  "payload": { ... },
  "payload_hash": "<sha256 hex of canonical_json(payload)>",
  "signatures": { "ed448": "<base64>", "ml_dsa_87": "<base64>" }
}
```

Payload fields (all signed):

| Field | Meaning |
|---|---|
| `format` | `stamped-reseal/1` |
| `case_id` | Case the keys belong to |
| `seq` | 1, 2, 3 ... in the order re-seals were made; a gap means one was removed |
| `resealed_at` | Application clock, ISO 8601 UTC. Not a trusted timestamp. |
| `from_entry_id`, `to_entry_id` | The range being wrapped. Must be earlier than the re-seal entry itself. |
| `entry_count` | Number of entries in that range |
| `first_entry_prev_hash` | `prev_hash` of the first entry in the range |
| `last_entry_hash` | `entry_hash` of the last entry in the range |
| `range_digest` | See below |
| `key_id` | Which renewal key set signed this |
| `suite` | `{"classical": "Ed448", "post_quantum": "ML-DSA-87"}` |
| `renews` | The suite being renewed, for the reader: `Ed25519` + `ML-DSA-65` |

```
range_digest = SHA256( canonical_json([entry_hash_1, entry_hash_2, ...]) )
```

The list holds every entry in the range, oldest first, as 64-character hex
strings. `canonical_json` is the pinned serialization from
`docs/custody-log-format.md`.

The signed message is `canonical_json(payload)` encoded as UTF-8. Both
signatures are over exactly those bytes.

## What it does not change

A re-seal **references** old hashes; it never replaces them.

* No existing custody entry is read for modification, updated, re-hashed or
  re-signed. Doing so would change its hash and look exactly like tampering.
* Existing anchors and their Ed25519 / ML-DSA-65 signatures are untouched and
  keep verifying.
* The database's append-only triggers apply to a re-seal like any other entry.

## Renewal keys

Separate from the case's original signing keys:

* private: `keys/<case>/reseal/<key_id>/` (`ed448_private.bin`, `mldsa87_private.bin`, owner-only, git-ignored)
* public: `keys/<case>/public/reseal/<key_id>.json`

`key_id` is the first 32 hex characters of `SHA256(ed448_public + mldsa87_public)`,
so a key file cannot be swapped for different keys without its id changing. The
public `reseal/` folder travels inside the exported `public/` folder.

## How the verifier checks it

For every `resealed` entry, `verifier/verify.py` (no imports from `seal`):

1. parses the record and recomputes `payload_hash`;
2. checks `seq` runs 1, 2, 3 ... with no gap;
3. checks the range is earlier than the re-seal and that the **live** log still
   has exactly `entry_count` entries in it, the same `first_entry_prev_hash`,
   the same `last_entry_hash` and the same `range_digest`;
4. finds the public keys by `key_id`, checks the key file matches its own id and
   case, and verifies **both** signatures (Ed448 and ML-DSA-87). One valid
   half is a failure.

| Outcome | Result | Exit code |
|---|---|---|
| everything matches and both signatures verify | `PASS` | 0 |
| the range, numbering, key file or a signature is wrong | `FAIL`, entry named | 1 |
| renewal public keys not supplied, or liboqs missing | `ERROR`, never a pass | 2 |

A log with no re-seals is verified exactly as before (no check 4, no
`reseals` block in the JSON report).

Why this catches the perfect forgery: someone who rewrites an old entry and
recomputes every later hash makes the chain consistent again, but the re-seal
signed the **original** hashes. The range no longer matches, and the verifier
reports `reseal_range_mismatch` with the range that was rewritten.

## Trust: what this does and does not prove

Stated plainly, as in `docs/anchoring.md`:

* The application holds the renewal private keys. Someone who controls the
  application **and** the keys can sign a new re-seal. A re-seal is only as
  strong as where it is exported to and whether the `key_id` shown by the
  verifier matches a copy obtained separately.
* It protects the **record of what the log said**, under a newer algorithm. It
  does not make the evidence itself more genuine, and it does not prove that
  an entry was honest when it was written.
* If the original algorithms are broken **before** a re-seal is made, the
  re-seal cannot repair history that could already have been forged. Re-seal
  while the old suite is still trustworthy, and again when the new one ages.
* `resealed_at` is the application's clock.

## Use

```bash
# once per case: create the renewal key set (Ed448 + ML-DSA-87)
python -m seal.reseal create-keys --case CASE_ID

# wrap entries 1 to 40 (omit --to for "through the newest entry")
python -m seal.reseal reseal --db data/stamped.db --case CASE_ID --from 1 --to 40

# demo: show an old record, re-seal it, run the verifier (add --tamper to see a forgery rejected)
python scripts/reseal_demo.py --tamper
```

Export the case as usual (include the whole `public/` folder), then:

```bash
python verifier/verify.py --case-export <exported-case>
```

Re-sealing is a Tier 3 stretch: do it only after the Tier 1 chain, anchors and
verifier are demo-tested.