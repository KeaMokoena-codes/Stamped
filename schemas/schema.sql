CREATE TABLE IF NOT EXISTS evidence (
    evidence_id   TEXT PRIMARY KEY, -- SHA-256 hex digest of the sealed file; stable evidence identifier.
    content_hash  TEXT NOT NULL,    -- SHA-256 hex digest of the original file bytes.
    sealed_path   TEXT NOT NULL,    -- Filesystem path to the read-only sealed copy.
    source        TEXT,              -- Collection source, such as "webhook" or "manual-upload".
    collector     TEXT,              -- Person or process that collected the evidence.
    original_name TEXT,              -- Original filename for display; never use it as a path.
    captured_at   TEXT,              -- ISO 8601 UTC time of capture, if known.
    sealed_at     TEXT NOT NULL,     -- ISO 8601 UTC time the file was sealed.
    metadata_json TEXT               -- Caller-supplied collection metadata encoded as JSON.
);

-- Append-only custody log. Do not add foreign keys: failed and out-of-band
-- actions must remain recordable even when their evidence/artifact is absent.
CREATE TABLE IF NOT EXISTS custody_log (
    entry_id      INTEGER PRIMARY KEY AUTOINCREMENT, -- Append-order locator only; never used to compute entry_hash.
    timestamp_utc TEXT NOT NULL,                     -- ISO 8601 UTC time the action was recorded.
    actor         TEXT NOT NULL,                     -- User or process that performed the action.
    role          TEXT NOT NULL,                     -- Actor's role at the time of the action.
    action        TEXT NOT NULL,                     -- Action name, e.g. "sealed", "seal_failed", or "re_intake".
    evidence_id   TEXT,                              -- Related evidence identifier, when applicable.
    artifact_id   TEXT,                              -- Related derived artifact identifier, when applicable.
    details_json  TEXT,                              -- Canonical JSON action details included in the hash.
    prev_hash     TEXT NOT NULL,                     -- Previous entry's SHA-256 hash; genesis is 64 zeroes.
    entry_hash    TEXT NOT NULL UNIQUE               -- SHA-256 of canonical entry content plus prev_hash, not a row ID.
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id         TEXT PRIMARY KEY, -- Stable application-generated identifier for this derived output.
    source_evidence_id  TEXT,             -- Evidence identifier when derived directly from evidence.
    source_artifact_id  TEXT,             -- Artifact identifier when derived from another artifact.
    tool_name           TEXT NOT NULL,    -- Parser, detector, or other tool that produced this output.
    tool_version        TEXT NOT NULL,    -- Exact tool version used to produce this output.
    created_at          TEXT NOT NULL,    -- ISO 8601 UTC time the output was created.
    input_hash          TEXT NOT NULL,    -- SHA-256 of the exact input bytes or canonical input representation.
    output_hash         TEXT NOT NULL,    -- SHA-256 of the produced artifact bytes.
    metadata_json       TEXT,             -- Optional artifact-specific metadata encoded as JSON.
    CHECK (
        (source_evidence_id IS NOT NULL AND source_artifact_id IS NULL)
        OR (source_evidence_id IS NULL AND source_artifact_id IS NOT NULL)
    )                                   -- Each artifact has exactly one immediate source.
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id         TEXT PRIMARY KEY, -- Stable application-generated identifier for this finding.
    source_evidence_id TEXT NOT NULL,    -- Evidence item the finding ultimately concerns.
    artifact_id        TEXT,             -- Derived artifact that produced this finding, if applicable.
    rule_id            TEXT NOT NULL,    -- Detection rule identifier and versioned rule namespace.
    severity           TEXT NOT NULL,    -- Finding severity assigned by the detection rule.
    title              TEXT NOT NULL,    -- Short human-readable finding summary.
    description        TEXT NOT NULL,    -- Explanation of the detected condition and its significance.
    created_at         TEXT NOT NULL,    -- ISO 8601 UTC time the finding was created.
    details_json       TEXT              -- Structured finding context and supporting data encoded as JSON.
);

CREATE TABLE IF NOT EXISTS anchors (
    anchor_id         TEXT PRIMARY KEY, -- Stable application-generated identifier for this anchor.
    entry_hash        TEXT NOT NULL,    -- Custody-log SHA-256 hash that was externally anchored.
    anchor_type       TEXT NOT NULL,    -- Anchor mechanism or service, such as a trusted timestamp.
    anchored_at       TEXT NOT NULL,    -- ISO 8601 UTC time the external anchor was obtained.
    external_reference TEXT,            -- Provider-specific receipt, transaction, or lookup identifier.
    proof_json        TEXT              -- Verifiable anchor response/proof encoded as JSON.
);

CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY, -- Stable application-generated identifier for the user.
    display_name TEXT NOT NULL,    -- Human-readable name shown in audit and access views.
    role         TEXT NOT NULL,    -- Assigned application role, e.g. examiner or prosecutor.
    created_at   TEXT NOT NULL,    -- ISO 8601 UTC time the user record was created.
    active       INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)) -- Whether access is enabled (1) or disabled (0).
);
