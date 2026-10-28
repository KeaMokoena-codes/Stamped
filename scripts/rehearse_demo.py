"""Clean-environment rehearsal of the tamper-detection demo.

Copies the repository (WITHOUT data/stamped.db, keys/, caches or .idea) into a
fresh temporary folder, then repeats the same steps the dashboard's
"demo: simulate tampering" button runs, and checks every result against what
the pitch expects. Nothing in the real repository is read as state or modified.

    python -m scripts.rehearse_demo              # 3 runs (the Definition of Done)
    python -m scripts.rehearse_demo --runs 5
    python -m scripts.rehearse_demo --with-ui    # also drive the Streamlit page

Exit code 0 only if every run behaved as expected. This does not replace one
live run of `python -m streamlit run run_app.py` on the actual pitch machine.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IGNORE = shutil.ignore_patterns(
    "__pycache__", ".pytest_cache", ".idea", ".git", "keys", "*.db",
    "*.db-journal", "*.pyc", "demo_out",
)
EXPECTED_BROKEN_ENTRY = 2


def _run(cmd, cwd, env, timeout):
    started = time.perf_counter()
    proc = subprocess.run(
        cmd, cwd=cwd, env=env, capture_output=True, text=True,
        timeout=timeout, check=False,
    )
    return proc, time.perf_counter() - started


def _check_report(proc) -> list[str]:
    """Return a list of problems; empty means the run matched the pitch."""
    problems = []
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return [f"verifier output is not JSON ({exc}); stderr={proc.stderr.strip()[:200]!r}"]
    if proc.returncode != 1:
        problems.append(f"verifier exit code {proc.returncode}, expected 1")
    if report.get("overall") != "FAIL":
        problems.append(f"overall={report.get('overall')!r}, expected 'FAIL'")
    if report.get("broken_entry_id") != EXPECTED_BROKEN_ENTRY:
        problems.append(f"broken_entry_id={report.get('broken_entry_id')!r}, expected {EXPECTED_BROKEN_ENTRY}")
    checks = report.get("checks", {})
    if checks.get("chain", {}).get("status") != "FAIL":
        problems.append("chain check did not report FAIL")
    for name in ("signatures", "anchors"):
        if checks.get(name, {}).get("status") != "SKIPPED":
            problems.append(f"{name} check was not SKIPPED (chain-only demo)")
    return problems


def rehearse_once(index: int, timeout_prepare: int, timeout_verify: int) -> dict:
    result = {"run": index, "ok": False, "problems": [], "prepare_s": None, "verify_s": None}
    with tempfile.TemporaryDirectory(prefix="stamped-rehearsal-") as tmp:
        repo = Path(tmp) / "repo"
        shutil.copytree(REPO_ROOT, repo, ignore=IGNORE)
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("STAMPED_")}  # no inherited state
        case_dir = Path(tmp) / "demo-case"
        try:
            prep, result["prepare_s"] = _run(
                [sys.executable, "-m", "scripts.simulate_tamper", "--case-dir", str(case_dir)],
                repo, env, timeout_prepare)
            if prep.returncode != 0:
                result["problems"].append(f"prepare failed: {(prep.stdout + prep.stderr).strip()[:300]}")
                return result
            ver, result["verify_s"] = _run(
                [sys.executable, str(repo / "verifier" / "verify.py"), "--case-export",
                 str(case_dir), "--allow-no-anchors", "--json"],
                repo, env, timeout_verify)
        except subprocess.TimeoutExpired as exc:
            result["problems"].append(f"timed out: {exc}")
            return result
        result["problems"] = _check_report(ver)
        result["ok"] = not result["problems"]
    return result


def rehearse_ui_once(timeout: int) -> list[str]:
    """Click the real dashboard button via Streamlit's test runner (clean DB)."""
    try:
        from streamlit.testing.v1 import AppTest
    except ImportError:
        return ["streamlit is not installed here, so the UI rehearsal could not run (counted as FAIL, not a pass)"]
    with tempfile.TemporaryDirectory(prefix="stamped-rehearsal-ui-") as tmp:
        db = Path(tmp) / "stamped.db"
        sys.path.insert(0, str(REPO_ROOT))
        from schemas.init_db import init_db
        init_db(db)
        os.environ["STAMPED_DB_PATH"] = str(db)
        try:
            from access import connect_database
            from datetime import datetime, timezone
            with connect_database() as conn:
                conn.execute(
                    "INSERT INTO users (user_id, display_name, role, created_at, active) "
                    "VALUES (?, ?, ?, ?, 1)",
                    ("rehearsal-examiner", "Rehearsal", "examiner",
                     datetime.now(timezone.utc).isoformat()))
                conn.commit()

            def page():
                from app.main import verification_page
                verification_page()

            app = AppTest.from_function(page)
            app.session_state["stamped_actor"] = "rehearsal-examiner"
            app.run(timeout=timeout)
            button = next((b for b in app.button if b.label == "demo: simulate tampering"), None)
            if button is None:
                return ["demo button not found on the Verification page"]
            button.click()
            app.run(timeout=timeout)
            problems = []
            if app.exception:
                problems.append(f"page raised: {[e.value for e in app.exception]}")
            if not any("first broken custody entry is #2" in e.value for e in app.error):
                problems.append("expected 'first broken custody entry is #2' message not shown")
            return problems
        finally:
            os.environ.pop("STAMPED_DB_PATH", None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--with-ui", action="store_true", help="also drive the Streamlit page once")
    args = parser.parse_args(argv)

    print(f"Python {sys.version.split()[0]} on {sys.platform}; clean-copy rehearsal x{args.runs}")
    results = [rehearse_once(i, 30, 60) for i in range(1, args.runs + 1)]
    for r in results:
        timing = (f"prepare {r['prepare_s']:.2f}s, verify {r['verify_s']:.2f}s"
                  if r["verify_s"] is not None else "no timing")
        print(f"  run {r['run']}: {'OK  ' if r['ok'] else 'FAIL'} ({timing})")
        for p in r["problems"]:
            print(f"      - {p}")

    ui_problems: list[str] = []
    if args.with_ui:
        started = time.perf_counter()
        ui_problems = rehearse_ui_once(90)
        print(f"  UI run: {'OK' if not ui_problems else 'FAIL'} ({time.perf_counter() - started:.1f}s)")
        for p in ui_problems:
            print(f"      - {p}")

    ok = all(r["ok"] for r in results) and not ui_problems
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())