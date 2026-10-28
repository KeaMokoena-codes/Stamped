"""Terminal fallback for the tamper-detection demo (use if the dashboard fails).

    python -m scripts.demo_fallback

Does exactly what the dashboard button does: builds a disposable synthetic case
in a temporary folder, alters one custody entry in that copy only, and runs the
REAL independent verifier (verifier/verify.py) in chain-only mode. The verifier's
own output is printed unmodified. Nothing here is simulated or hard-coded.

Exit code 0 means the demo behaved as expected (verifier FAIL, entry #2 named).
Signatures and external anchors are NOT tested by this demo.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_LINE = "The chain first breaks at entry #2."


def main() -> int:
    print("DEMO ONLY: synthetic case, disposable copy. No real evidence is touched.\n")
    with tempfile.TemporaryDirectory(prefix="stamped-tamper-demo-") as tmp:
        case_dir = Path(tmp) / "demo-case"
        prep = subprocess.run(
            [sys.executable, "-m", "scripts.simulate_tamper", "--case-dir", str(case_dir)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=False,
        )
        if prep.returncode != 0:
            print("Could not prepare the demo case:\n" + prep.stdout + prep.stderr)
            return 2
        print("Step 1: case sealed with 3 custody entries; entry #2 then altered in the copy.\n")
        print("Step 2: running the independent verifier...\n")
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "verifier" / "verify.py"),
             "--case-export", str(case_dir), "--allow-no-anchors"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, check=False,
        )
    print(result.stdout + result.stderr)
    expected = result.returncode == 1 and EXPECTED_LINE in result.stdout
    print("Demo outcome:", "tampering detected at entry #2, as expected."
    if expected else "UNEXPECTED result; do not present this as a success.")
    return 0 if expected else 1


if __name__ == "__main__":
    raise SystemExit(main())