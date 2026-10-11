# External anchoring (Issue #7)

Code: `seal/anchor.py` (creates anchors) and `verifier/anchor_check.py`
(independent check). Tests: `tests/test_anchor.py`.

## 1. Why it exists

The hash chain makes edits to the custody log *detectable*, but on its own it
has two blind spots (both are pinned as `LIMITATION` tests in
`tests/test_custody_log.py`):

1. **Deleting the newest entries.** A shorter chain is still self-consistent.
2. **Rewriting an entry and recomputing every later hash.** The result is a
   perfectly consistent chain that tells a different story.

An *anchor* closes both. It records, outside the application, "the log looked
like this at this time": the id and hash of the newest entry, how many entries
existed, and a link to the previous anchor. If history is later cut short or
rewritten, the live log can no longer match the anchor.

## 2. What an anchor contains

One JSON file per anchor, named `anchor_000001.json`, `anchor_000002.json`, ...

```
payload (signed):
  format            "stamped-anchor/1"
  case_id           which case's keys signed it
  seq               1, 2, 3, ... (also the file number)
  anchored_at       ISO 8601 UTC, from the application's clock
  head_entry_id     id of the newest custody entry covered
  head_entry_hash   its entry_hash
  entry_count       how many entries existed up to and including it
  prev_anchor_hash  anchor_hash of the previous anchor (64 zeros for #1)
anchor_hash         SHA-256 of the canonical payload bytes
signatures          ed25519 and ml_dsa_65, base64, BOTH over the payload bytes
meta (unsigned)     location_assurance: "separate_device" | "same_device"
```

The signed bytes are the payload serialized exactly like custody log fields:

```python
json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
```

encoded as UTF-8. Both signatures must verify (hybrid rule, see
`docs/key-management.md`). The `format` field is inside the signed payload, so
an anchor signature cannot be mistaken for any other kind of signature.

Test vector (computed by a script that does not import the app):

```
payload   {"anchored_at":"2026-10-11T08:30:00+00:00","case_id":"case1","entry_count":5,"format":"stamped-anchor/1","head_entry_hash":"abab...ab","head_entry_id":5,"prev_anchor_hash":"000...0","seq":1}
sha256    c96231e574ab2c2258afb1297660f6f7a2dad4a9c1153905d21918cdc994b749
```

(ML-DSA signatures are randomized, so signatures themselves cannot be pinned.)

## 3. Where anchors must be stored, and why the app cannot silently rewrite them

**The protection comes from where the anchor is kept, not from the signature.**
The application holds the signing keys. Anyone who controls the application can
therefore *sign* a new anchor. What they must not be able to do is *change or
delete an anchor that already exists*. That is only true if the anchor sits on
storage the application cannot write to.

What the code enforces (tested):

- It **refuses** an anchor directory that is, contains, or sits inside the
  application directory or the database's directory (including through a
  symlink). "A different file in the same writable folder" proves nothing.
- It **does not create** the anchor directory. If a USB stick is not mounted,
  creating the path would silently write to the local disk instead.
- Anchor files are created with exclusive-create (never overwrite), flushed to
  disk, and set read-only.
- Anchors are numbered and hash-linked, so removing or replacing one in the
  middle of the sequence is detected.
- Each anchor records whether the directory is on a different device from the
  database (`separate_device`) or the same one (`same_device`). The command line
  prints a warning for `same_device`.

What the code **cannot** enforce, and what the deployment must provide:

| Level | Where anchors live | What it protects against |
|---|---|---|
| Development | Any folder outside the repo and the database folder | Mistakes and casual edits only. A person with access to the machine can still change it. Labelled `same_device`. |
| Separate medium | A USB drive or second disk, unplugged after anchoring | An attacker who compromises the running server cannot reach it. |
| Held by someone else | A copy given to a second party: another machine, the prosecutor, or an append-only remote such as a Git repository whose branch forbids force-push and deletion | An attacker who controls the whole machine, because the evidence of what the log said sits with a party they do not control. |

Linux hardening idea for the separate-medium case (a recommended setup that the
project has **not** tested): mount the anchor disk, run the application as an
unprivileged user, and have an administrator mark the directory append-only
(`chattr +a`) and each finished file immutable (`chattr +i`). Without
something like this, a process running as the same user that wrote the file can
change its permissions and overwrite it.

**What to say when asked "can the app rewrite the anchors?"** Not once they sit
on storage it cannot write to, which is a property of how you deploy it, not of
the software alone. On a single laptop with a plain folder, the honest answer
is "that is a development setup and the anchor says so."

## 4. What anchoring does and does not protect against

| Attack | Result |
|---|---|
| Edit an old entry, leave stored hashes alone | Caught (chain recompute) |
| Edit an old entry and recompute every later hash | Caught (`anchored_hash_mismatch`) |
| Delete the newest entries | Caught (`anchored_entry_missing`) |
| Delete or reorder a middle entry | Caught |
| Edit an anchor file | Caught (hash and both signatures) |
| Remove an anchor from the middle or start of the sequence | Caught (`anchor_sequence_gap`, `anchor_link_broken`) |
| Forge an anchor with different keys | Caught (signature) |
| Anchor an already-tampered log | Refused at creation, both when the chain is broken and when a clean-looking chain contradicts an earlier anchor |
| **Rewrite entries added AFTER the newest anchor** | **Not caught.** Window of exposure = the anchoring interval. The checker reports how many entries are unprotected. |
| **Delete the newest anchor file** | **Not caught.** The log then matches the previous anchor. This is why the storage must be append-only or held by someone else. |
| **Attacker with the signing keys writes a false anchor onto writable storage** | Not caught. Same reason. |

Also true: `anchored_at` is the application's clock, not a trusted timestamp
(an RFC 3161 timestamp would add one; not implemented). Private keys are not
passphrase-encrypted (see `docs/key-management.md`).

## 5. How checking works (`verifier/anchor_check.py`)

The checker imports nothing from the application (CI and a test enforce this),
reads the database through a read-only connection, and **fails closed**: no
anchors, an unreadable file, or a missing liboqs is never a pass.

It (1) recomputes the entire hash chain, (2) reads every anchor, (3) checks each
anchor's file hash, both signatures, link to the previous anchor, and that the
sequence has no gaps and never goes backwards, and (4) compares each anchor with
the live log. Recomputing the chain is essential: comparing only the stored
hash would miss an attacker who edits an old entry and leaves its stored hash
untouched.

| Failure code | Meaning |
|---|---|
| `chain_broken` | the log does not recompute (first bad entry reported) |
| `no_anchors` | nothing external to compare against |
| `anchored_hash_mismatch` | history was rewritten after the anchor |
| `anchored_entry_missing` | entries were deleted after the anchor |
| `anchored_entry_count_mismatch` | entries removed or inserted before the anchored one |
| `anchor_signature_invalid` | either signature failed (the message names which) |
| `anchor_hash_mismatch` | the anchor file was edited |
| `anchor_link_broken` / `anchor_sequence_gap` | an anchor was removed, replaced or reordered |
| `anchor_regression` | an anchor covers less of the log than the one before it |
| `anchor_unreadable` / `anchor_seq_mismatch` | malformed or misnumbered file |

Exit codes: `0` PASS, `1` FAIL, `2` could not run the check.

**Status of the verifier ticket (#1.5):** `verifier/verify.py` does not exist
yet. When it is written, it must call `check_anchors()` and treat `ok == False`
(or exit code 1/2) as an overall failure. Until then the anchor check is its own
command, and the end-to-end test in `tests/test_anchor.py` exercises it through
the real command line.

## 6. Commands

Create one anchor (manual, e.g. at case close or on stage):

```
python -m seal.anchor create --db data/stamped.db --case CASE_ID \
    --anchor-dir /media/usb/stamped-anchors
```

Anchor automatically while the system runs (only when something new happened):

```
python -m seal.anchor watch --db data/stamped.db --case CASE_ID \
    --anchor-dir /media/usb/stamped-anchors --interval 300
```

Check the log against the anchors, from any machine that has the database copy,
the anchor folder, and the case's exported `public/` keys:

```
python verifier/anchor_check.py --db data/stamped.db \
    --anchors /media/usb/stamped-anchors --public-keys keys/CASE_ID/public
```

### Demo script (about 90 seconds)

1. Seal some evidence, then `python -m seal.anchor create ...` (shows the entry covered).
2. Run `anchor_check.py` -> **PASS**.
3. Open the database, drop the guard triggers, edit an old entry and recompute
   the later hashes (this fools the chain alone).
4. Run `anchor_check.py` again -> **FAIL** with `anchored_hash_mismatch`.
5. Try `python -m seal.anchor create ...` -> **refused**: it will not anchor a
   log that contradicts an earlier anchor.

## 7. Operational notes

- The anchor interval is the window in which new entries are unprotected.
  Anchor at case close and after any significant event, not only on a timer.
- Copy the anchor folder to a second party when a case is handed over.
- The `anchors` table inside the database is only an index for convenience. The
  files on separate storage are authoritative; the checker never reads the table.
- If recording an anchor in the database fails after the file was written, the
  error says so and the external anchor remains valid.