"""Protect the synthetic demo fixtures from accidental edits."""

import hashlib
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_HASHES = {
    "data/sample/.gitkeep": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "data/sample/bundle_example.json": "db7fc6a0b36ffd33f27c1ba536d64a5c1d1370880aeae46e0d2c8dbcda0810c5",
    "data/sample/cloudtrail_sample.json": "c5d671e9e8e7f43437245872afc4e4dd0f8d5d86579ef6643aa9274821d96c28",
    "data/sample/normalized_event_sample.json": "3462b34fcce6247cc09d20e35ac58978bd683135af62093c9dab8a266095ea5b",
}


def test_synthetic_sample_data_matches_the_reviewed_sha256_manifest():
    actual_paths = {
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in (REPOSITORY_ROOT / "data" / "sample").rglob("*")
        if path.is_file()
    }
    assert actual_paths == set(SAMPLE_HASHES)
    for relative_path, expected_hash in SAMPLE_HASHES.items():
        # Compare with line endings normalised: the manifest holds the LF form, and a Windows
        # checkout (git autocrlf) turns the same files into CRLF. Any other change still fails.
        content = (REPOSITORY_ROOT / relative_path).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(content).hexdigest() == expected_hash, relative_path