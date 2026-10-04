#!/usr/bin/env python3
"""
CI guardrail checks for Stamped.

This script is NOT a substitute for the manual crypto review required by
docs/Stamped_Issues.md — it's a cheap automated net that catches the most
obvious, repeatable mistakes before they land on main (since everyone
commits directly to main with no PR gate, this is the only automated
checkpoint the project has).

Checks are intentionally conservative: they skip gracefully if a file
doesn't exist yet (early in the project, most won't), and they distinguish
ERROR (fails the build) from WARNING (prints but doesn't fail), because a
regex-based scan will have false positives and shouldn't block the team
on those.

Run locally with: python scripts/ci_guardrails.py
"""

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
errors = []
warnings = []


def tracked_py_files():
    """Return git-tracked .py files, respecting .gitignore."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "*.py"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout
        return [REPO_ROOT / p for p in out.splitlines() if p]
    except Exception:
        return list(REPO_ROOT.rglob("*.py"))


def read(path):
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


# ---------------------------------------------------------------------
# 1. No committed private key material, anywhere in the tree
# ---------------------------------------------------------------------
def check_no_committed_keys():
    try:
        tracked = subprocess.run(
            ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.splitlines()
    except Exception:
        tracked = []

    key_markers = ("BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY")
    self_path = Path(__file__).resolve()
    for rel in tracked:
        p = REPO_ROOT / rel
        if not p.is_file() or p.resolve() == self_path:
            continue  # don't flag this script's own pattern list as a committed key
        text = read(p)
        if any(marker in text for marker in key_markers):
            errors.append(f"Committed private key material found in {rel} — this must never be on main.")

    suspicious_names = [f for f in tracked if re.search(r"(privkey|private_key|\.pem$|\.key$)", f, re.I)]
    if suspicious_names:
        warnings.append(
            "Files with key-like names are tracked by git: "
            + ", ".join(suspicious_names)
            + " — confirm these are intentional (e.g. public keys) and not secrets."
        )


# ---------------------------------------------------------------------
# 2. seal/signing.py never prints or logs private key material
# ---------------------------------------------------------------------
def check_no_key_printing():
    target = REPO_ROOT / "seal" / "signing.py"
    if not target.exists():
        return
    text = read(target)
    for lineno, line in enumerate(text.splitlines(), start=1):
        if re.search(r"\bprint\s*\(.*(priv|secret)", line, re.I):
            errors.append(f"seal/signing.py:{lineno} — possible private key/secret being printed: {line.strip()!r}")


# ---------------------------------------------------------------------
# 3. custody_log.py must be append-only — no update/delete functions
# ---------------------------------------------------------------------
def check_custody_log_append_only():
    target = REPO_ROOT / "seal" / "custody_log.py"
    if not target.exists():
        return
    text = read(target)
    forbidden = re.findall(r"^\s*def\s+(update_entry|delete_entry|edit_entry|remove_entry)\s*\(", text, re.M)
    if forbidden:
        errors.append(
            f"seal/custody_log.py defines {forbidden} — the custody log must be append-only "
            "per Issue 1.2. No update/delete function should exist anywhere in this file."
        )


# ---------------------------------------------------------------------
# 4. verify_hybrid must require BOTH signatures (and, not or)
# ---------------------------------------------------------------------
def check_hybrid_verify_uses_and():
    target = REPO_ROOT / "seal" / "signing.py"
    if not target.exists():
        return
    text = read(target)
    match = re.search(r"def\s+verify_hybrid\s*\([^)]*\):(.*?)(?=\ndef\s|\Z)", text, re.S)
    if not match:
        return
    body = match.group(1)
    if re.search(r"\bor\b", body) and not re.search(r"\band\b", body):
        errors.append(
            "seal/signing.py: verify_hybrid() appears to combine the classical and post-quantum "
            "checks with 'or' and no 'and' — per Issue 1.3 this MUST require both signatures to "
            "pass. Check this by hand; this is a regex heuristic, not proof."
        )
    elif "and" not in body and "or" not in body:
        warnings.append(
            "seal/signing.py: could not confirm verify_hybrid() combines both signature checks "
            "with 'and' — please confirm manually (regex heuristic only)."
        )


# ---------------------------------------------------------------------
# 5. No bare except:pass hiding failures in seal/ or verifier/
# ---------------------------------------------------------------------
def check_no_silent_exceptions():
    for folder in ("seal", "verifier", "ingest"):
        for path in (REPO_ROOT / folder).rglob("*.py") if (REPO_ROOT / folder).exists() else []:
            text = read(path)
            if re.search(r"except[^:]*:\s*\n\s*pass\b", text):
                warnings.append(
                    f"{path.relative_to(REPO_ROOT)} — found a bare 'except: pass'. Per the guardrails, "
                    "failures in sealing/verification/parsing must be logged, not silently swallowed. "
                    "Confirm this isn't hiding a real error."
                )


# ---------------------------------------------------------------------
# 6. Verifier must not import from the app's own internal modules
# ---------------------------------------------------------------------
def check_verifier_is_independent():
    target = REPO_ROOT / "verifier" / "verify.py"
    if not target.exists():
        return
    text = read(target)
    forbidden_imports = re.findall(r"^\s*(?:from|import)\s+(seal|app|ingest|detect|access)\b", text, re.M)
    if forbidden_imports:
        errors.append(
            f"verifier/verify.py imports from {set(forbidden_imports)} — per Issue 1.5 the verifier "
            "must stay independent of the app's internal modules, otherwise it can share a bug with "
            "the thing it's supposed to be checking."
        )


# ---------------------------------------------------------------------
# 7. No hardcoded "tamper detected" results in the demo UI
# ---------------------------------------------------------------------
def check_tamper_demo_not_faked():
    candidates = list((REPO_ROOT / "app").rglob("*tamper*.py")) if (REPO_ROOT / "app").exists() else []
    for path in candidates:
        text = read(path)
        if re.search(r"tamper(ed)?_?(detected|result)\s*=\s*True\b", text, re.I) and "verify" not in text.lower():
            errors.append(
                f"{path.relative_to(REPO_ROOT)} — looks like it hardcodes a tamper-detected result "
                "rather than calling the real verifier. Per Issue 5.4, this demo MUST call the actual "
                "verifier and display its real output."
            )


# ---------------------------------------------------------------------
# 8. .gitignore covers the obvious secret/data-leak paths
# ---------------------------------------------------------------------
def check_gitignore_coverage():
    gi = REPO_ROOT / ".gitignore"
    if not gi.exists():
        warnings.append("No .gitignore found at repo root.")
        return
    text = read(gi)
    expected = ["*.pem", "*.key", "keys/", "*.db", "__pycache__", ".env"]
    missing = [pat for pat in expected if pat not in text]
    if missing:
        warnings.append(f".gitignore may be missing patterns: {missing} — confirm these are covered somehow.")


def main():
    checks = [
        check_no_committed_keys,
        check_no_key_printing,
        check_custody_log_append_only,
        check_hybrid_verify_uses_and,
        check_no_silent_exceptions,
        check_verifier_is_independent,
        check_tamper_demo_not_faked,
        check_gitignore_coverage,
    ]
    for check in checks:
        check()

    print("=" * 70)
    print("STAMPED CI GUARDRAIL CHECKS")
    print("=" * 70)

    if warnings:
        print(f"\n{len(warnings)} WARNING(S) — printed but non-blocking:\n")
        for w in warnings:
            print(f"  warn:  {w}")

    if errors:
        print(f"\n{len(errors)} ERROR(S) — these fail the build:\n")
        for e in errors:
            print(f"  FAIL:  {e}")
        print("\nThese checks are a heuristic safety net, not a substitute for the")
        print("manual crypto review required before pushing to main. Fix or, if a")
        print("check is a false positive, say so explicitly in the commit message.")
        sys.exit(1)

    print("\nNo blocking issues found. Remember: this script cannot verify")
    print("cryptographic correctness — the manual review step still applies.")
    sys.exit(0)


if __name__ == "__main__":
    main()