CREATE TABLE IF NOT EXISTS evidence (
                                        evidence_id     TEXT PRIMARY KEY,   -- content hash (sha256 hex) of the sealed file
                                        content_hash    TEXT NOT NULL,      -- same value as evidence_id, kept explicit for clarity
                                        sealed_path     TEXT NOT NULL,      -- path to the read-only working copy under data/sealed/
                                        source          TEXT,               -- where it came from (e.g. "webhook", "manual-upload")
                                        collector       TEXT,               -- who/what collected it
                                        original_name   TEXT,               -- original filename, for display only — never used as a path
                                        captured_at     TEXT,               -- ISO8601 UTC timestamp of capture, if known
                                        sealed_at       TEXT NOT NULL,      -- ISO8601 UTC timestamp of sealing
                                        metadata_json   TEXT                -- free-form metadata as JSON, caller-supplied
);

-- Append-only custody log. No UPDATE or DELETE statement should ever be
-- run against this table, and no application code should expose a
-- function that does so (see Issue #2 / seal/custody_log.py).
CREATE TABLE IF NOT EXISTS custody_log (
                                           entry_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                                           timestamp_utc   TEXT NOT NULL,
                                           actor           TEXT NOT NULL,
                                           role            TEXT NOT NULL,
                                           action          TEXT NOT NULL,      -- e.g. "sealed", "seal_failed", "re_intake"
                                           evidence_id     TEXT,               -- nullable: not every entry concerns one evidence item
                                           artifact_id     TEXT,               -- nullable: reserved for ingest/detect stages (#3.x, #4.x)
                                           details_json    TEXT,               -- structured summary (tool, params, result hash, etc.)
                                           prev_hash       TEXT NOT NULL,      -- hash of the previous entry; genesis uses 64 zero chars
                                           entry_hash      TEXT NOT NULL UNIQUE
);