# Evidence bundle format

This is the canonical reference for the **evidence bundle**: the JSON payload
the capture webhook expects, and how each part of it is handed to
`seal_evidence()` (`seal/intake.py`, Issue 1.1). The capture listener must
accept exactly this format. The example fixture is
`data/sample/bundle_example.json`.

The format is derived from what `seal_evidence()` actually accepts, not from a
generic alert-webhook template. Where the two disagree, `seal_evidence()` wins.

## 1. What `seal_evidence()` constrains

```python
seal_evidence(conn, file_path, metadata=None, actor="system",
              role="examiner", sealed_dir=DEFAULT_SEALED_DIR) -> evidence_id
```

These facts shape the bundle:

| Fact about `seal_evidence()` | Consequence for the bundle |
|---|---|
| It seals **one file path** per call. | A bundle with N files means N calls. Inline content must be written to a staged file (raw bytes, unchanged) before sealing. |
| `evidence_id` is the SHA-256 of the file's bytes. | The payload never supplies an evidence ID. An optional declared `sha256` is only a cross-check (section 4). |
| `original_name` is taken from the staged file's name. | The listener stages each file under its validated `name`, so `original_name` shows it. A `name` is only accepted if it is a plain single name (section 3), so it can never act as a path. |
| Only `source`, `collector` and `captured_at` are read from `metadata` into columns. The whole dict is also stored as `metadata_json`. | Everything else the bundle carries rides in `metadata_json`. There is no bundle table, and the schema is frozen. |
| Identical bytes give the same `evidence_id`. A second seal logs `re_intake`, returns the existing ID and does **not** update the metadata. | Two files with identical content in one bundle, or across bundles, become one evidence item. The second bundle's metadata is not stored (section 5). |
| Each call commits on its own. | A bundle is not atomic. Some files can seal while others fail (section 5). |

## 2. Payload

A bundle is one JSON object, UTF-8, sent as the webhook request body.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `format_version` | string | yes | Must be `"stamped-bundle/1"`. Anything else is rejected. |
| `bundle_id` | string | yes | Unique ID for this bundle, chosen by the sender. Used only to group the files in metadata. |
| `source_system` | string | yes | Name of the system that raised the alert or supplied the files. Free text. |
| `alert_type` | string | yes | Short label for the alert category. Free text; the listener does not interpret it. |
| `alert_id` | string | no | The source system's own alert reference, if it has one. |
| `alert_timestamp` | string | yes | When the alert fired. ISO 8601 with an explicit UTC offset. |
| `captured_at` | string | yes | When the evidence was captured. Same format as above. |
| `collector` | string | yes | Identity of the person or process that collected the evidence. |
| `files` | array | yes | One or more file entries (section 3). An empty list is rejected. |

Unknown top-level fields are rejected, not ignored, so a misspelt field cannot
silently drop information.

**Timestamps.** Both must carry an explicit offset and be UTC (`Z` or
`+00:00`). A naive timestamp or a non-UTC offset is rejected rather than
guessed. The listener rewrites `Z` to `+00:00` before sealing, matching the
form the custody log and parsers already use.

## 3. File entry

| Field | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | yes | File name, 1 to 128 characters. Must be a plain single name: no `/`, `\`, `:`, `<`, `>`, `"`, `\|`, `?`, `*`, no control characters, not `.` or `..`, no trailing space or dot, not a Windows device name (`CON`, `NUL`, `COM1` ...). Rejected if it breaks any rule; never cleaned up. |
| `kind` | string | yes | Which parser applies. Allowed values: `auth_log`, `cloudtrail_json`. |
| `path` | string | one of `path` / `content_b64` | A file the listener host can read, relative to the listener's configured staging root (for example `cloudtrail_sample.json` when the root is `data/sample`). Rejected outright if the listener has no staging root. |
| `content_b64` | string | one of `path` / `content_b64` | The file's bytes, standard base64. |
| `sha256` | string | no | Lowercase hex SHA-256 the sender expects for the file's bytes. |
| `base_year` | integer | no | Only for `auth_log`, 1970 to 2100. Syslog-style lines carry no year, so this supplies it (the parser defaults to 2026 if omitted). |

Exactly one of `path` and `content_b64` must be present; both or neither is
rejected.

`kind` values come from the parsers that exist today
(`ingest/parsers/auth_log.py`, `ingest/parsers/cloudtrail_json.py`). Adding a
new parser means adding its `kind` here.

## 4. Mapping to `seal_evidence()`

For each file entry, the listener stages the bytes as a file and calls
`seal_evidence()` once.

| Source in the payload | Goes to |
|---|---|
| File bytes (`path` content or decoded `content_b64`) | `file_path`, a staged file with the bytes unchanged |
| `source_system` | `metadata["source"]` (becomes `evidence.source`) |
| `collector` | `metadata["collector"]` (becomes `evidence.collector`) |
| `captured_at` | `metadata["captured_at"]` (becomes `evidence.captured_at`) |
| `bundle_id`, `alert_type`, `alert_id`, `alert_timestamp` | `metadata` keys of the same names (stored only in `metadata_json`) |
| the file entry's `kind` | `metadata["kind"]` (stored only in `metadata_json`) |
| the file entry's `base_year` | `metadata["base_year"]` (stored only in `metadata_json`) |
| the file entry's `name` | `metadata["declared_name"]` (stored only in `metadata_json`) |
| *(not from the payload)* | `actor`, `role`, `sealed_dir`: set by the listener, see below |

`alert_id` and `base_year` are left out of `metadata` when the payload omits them.

**`actor` and `role`.** These come from the listener's own configuration, never
from the payload. The `role` column in the custody log is free text, and
existing code already uses process-style values (`detection_engine` in detect,
`examiner` as the default). The capture listener's pair is still to be decided
with Ash, the same open question as the `TODO` in `detect/findings.py`.
`capture-listener` is proposed for `actor`.

**Declared `sha256`.** If present, the listener hashes the staged bytes before
sealing and rejects the file if they differ. This catches truncation or
corruption in transit. It does not replace the hash `seal_evidence()` computes.

**Line endings.** Hashes are over the exact bytes on disk. A `path` file that a
checkout rewrites (Git's CRLF conversion on Windows, for example) hashes
differently on different machines, so a declared `sha256` on a `path` entry
only holds where the file is stored byte-for-byte. For inline content the
base64 text fixes the bytes, so a declared hash is reliable there. The example
fixture therefore declares `sha256` on its inline entry only. Evidence files
must never be line-ending converted before sealing.

**`path` safety.** The listener resolves `path` against its staging root and
rejects absolute paths, `..` segments and anything that resolves outside the
root, including through symlinks.

## 5. Behaviour the format inherits

These follow from `seal_evidence()` and are documented here so nobody is
surprised by them.

1. **Metadata is not covered by the hash chain.** The `sealed` custody entry
   records only `content_hash` and `sealed_path`. The alert type, source system
   and collector sit in `evidence.metadata_json`, which is outside the chain and
   the signatures. The file bytes are protected; the context around them is not.
2. **Duplicate content keeps the first metadata.** If a file's bytes are already
   sealed, `seal_evidence()` logs `re_intake` and keeps the original row. The new
   `bundle_id` and alert context are not recorded against it.
3. **Partial bundles are possible.** If file 2 of 3 fails (`IntakeError`, with a
   `seal_failed` custody entry), file 1 stays sealed. The listener must report
   a per-file result (`sealed`, `re_intake` or `failed`) and must not claim the
   bundle succeeded unless every file did.
4. **Order is preserved but not meaningful.** Files are sealed in list order.
   Nothing downstream depends on that order.

## 6. Rejection rules

The listener rejects the whole bundle, before sealing anything, if:

- the body is not valid JSON, or the top level is not an object;
- `format_version` is missing or not `"stamped-bundle/1"`;
- a required field is missing, empty, or the wrong type;
- an unknown field appears at the top level or in a file entry;
- a timestamp is naive or not UTC;
- `files` is empty;
- a file entry has both or neither of `path` and `content_b64`;
- `kind` is not one of the allowed values;
- `content_b64` is not valid base64;
- `base_year` is present on a `kind` other than `auth_log`, or is not an integer in range (a boolean is not an integer);
- a `name` breaks the rules in section 3;
- a `path` fails the safety rules in section 4, or the listener has no staging root;
- a limit is exceeded (section 8).

A declared `sha256` mismatch rejects that file, and per section 5 the bundle is
then reported as partial if earlier files were already sealed. To avoid that,
the listener checks every declared hash during validation, before it seals the
first file.

## 7. Example

`data/sample/bundle_example.json` is a complete valid bundle with one file by
`path` (`cloudtrail_sample.json`, relative to a staging root of `data/sample`)
and one inline (`auth.log`, three lines). The inline entry's hash was computed
from its actual bytes, and the whole bundle is exercised against the real
`seal_evidence()` by `tests/test_listener.py`.

## 8. Listener limits and behaviour

The capture listener (`capture/listener.py`) implements this format.

| Limit | Default |
|---|---|
| Request body | 16 MiB (`413` if exceeded) |
| Files per bundle | 10 |
| One file, after decoding | 8 MiB |
| All files together | 32 MiB |

Responses are JSON. `201` means every file was sealed (or logged as a
`re_intake`); `207` means some files sealed and some failed, with a result for
each; `400` is an invalid bundle with the reasons listed and nothing sealed;
`413` and `415` are an oversize body and a non-JSON content type; `503` means
the evidence database is unavailable. Error bodies never contain stack traces
or server paths.

The listener has no authentication and binds to `127.0.0.1` by default. It is a
stand-in for a real alerting pipeline, for the demo only.

### Trying it

```
python schemas/init_db.py
python -m capture.listener --staging-root data/sample
python scripts/send_example_alert.py
```

or, with curl (use `curl.exe` in Windows PowerShell, where `curl` is a
different command):

```
curl.exe -X POST http://127.0.0.1:5000/alert -H "Content-Type: application/json" --data-binary "@data/sample/bundle_example.json"
```