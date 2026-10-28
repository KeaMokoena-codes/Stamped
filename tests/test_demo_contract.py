"""Protect the synthetic demo fixtures from accidental edits."""

import hashlib
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_HASHES = {
    "data/sample/.gitkeep": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "data/sample/bundle_example.json": "73bb980585d28e3c64b4243b5f16cb53e5511ba903ad52eb4087951297e21fb6",
    "data/sample/cloudtrail_sample.json": "83884b33d614744606f1e0bc5a476b6514ecbfeb7b8558df36d5d708ffaea1f8",
    "data/sample/normalized_event_sample.json": "028d3e0385add1d0fc275f204e3a03ad8caeb73f5cb2bb2dc17d2303895d0c81",
}


def test_synthetic_sample_data_matches_the_reviewed_sha256_manifest():
    actual_paths = {
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in (REPOSITORY_ROOT / "data" / "sample").rglob("*")
        if path.is_file()
    }
    assert actual_paths == set(SAMPLE_HASHES)
    for relative_path, expected_hash in SAMPLE_HASHES.items():
        content = (REPOSITORY_ROOT / relative_path).read_bytes()
        assert hashlib.sha256(content).hexdigest() == expected_hash, relative_path
