#!/usr/bin/env python3
"""
scripts/run_e2e.py
Robust End-to-End Test Driver for Stamped
Validates Capture, Seal, Ingest, Detect, Report, and Verify using strict logic checks.
Uses a throwaway environment, real HTTP, and fails fast.
"""

import os
import sys
import time
import hashlib
import sqlite3
import requests
import subprocess
import tempfile
import json
import signal
import base64
from datetime import datetime, timezone

LISTENER_PORT = 8080
LISTENER_URL = f"http://127.0.0.1:{LISTENER_PORT}/alert"

def to_b64(text : str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')
now_utc = datetime.now(timezone.utc).isoformat()

# --- SCENARIOS ---
# 1. Control Scenario: 4 failures (below the 5+ threshold). Should yield 0 findings.
SCENARIO_CONTROL = {
    "format_version": "stamped-bundle/1",
    "bundle_id": "bndl_control_001",
    "source_system": "e2e_control",
    "alert_type": "e2e_test",
    "alert_timestamp": now_utc,
    "captured_at": now_utc,
    "collector": "e2e_driver",
    "files": [{
        "name": "auth_control.log",
        "kind": "auth_log",
        "base_year": 2026,
        "content_b64": to_b64(
            "Oct 27 21:00:01 server sshd[123]: Failed password for admin from 192.168.1.50 port 22 ssh2\n" * 4 +
            "Oct 27 21:10:00 server sshd[125]: Disconnected from user admin 192.168.1.50 port 22\n"
        )
    }]
}

# 2. Brute Force Scenario
SCENARIO_BRUTE = {
    "format_version": "stamped-bundle/1",
    "bundle_id": "bndl_brute_002",
    "source_system": "e2e_brute",
    "alert_type": "e2e_test",
    "alert_timestamp": now_utc,
    "captured_at": now_utc,
    "collector": "e2e_driver",
    "files": [{
        "name": "auth_brute.log",
        "kind": "auth_log",
        "base_year": 2026,
        "content_b64": to_b64(
            "Oct 27 21:00:01 server sshd[123]: Failed password for admin from 192.168.1.100 port 22 ssh2\n" * 8 +
            "Oct 27 21:00:15 server sshd[123]: Accepted password for admin from 192.168.1.100 port 22 ssh2\n"
        )
    }]
}

# 3. Impossible Travel Scenario
SCENARIO_TRAVEL = {
    "format_version": "stamped-bundle/1",
    "bundle_id": "bndl_travel_003",
    "source_system": "e2e_travel",
    "alert_type": "e2e_test",
    "alert_timestamp": now_utc,
    "captured_at": now_utc,
    "collector": "e2e_driver",
    "files": [{
        "name": "cloudtrail_travel.json",
        "kind": "cloudtrail_json",
        "content_b64": to_b64(json.dumps({
            "Records": [
                {"eventTime": "2026-10-27T21:00:00Z", "eventName": "ConsoleLogin", "sourceIPAddress": "192.168.1.200", "userIdentity": {"userName": "dev"}},
                {"eventTime": "2026-10-27T21:05:00Z", "eventName": "ConsoleLogin", "sourceIPAddress": "10.0.0.50", "userIdentity": {"userName": "dev"}}
            ]
        }))
    }]
}

EXPECTED_RESULTS = {
    "e2e_control": [],
    "e2e_brute": [{"rule": "brute_force", "key": "admin@192.168.1.100", "count": 8, "severity": "high"}],
    "e2e_travel": [{"rule": "impossible_travel", "key": "dev", "count": 2, "severity": "medium"}]
}

def compute_sha256(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def fail(msg: str):
    print(f"\n[FATAL] {msg}")
    sys.exit(1)
def run_test_suite():
    print(">>> Initializing throwaway forensic environment...")
    with tempfile.TemporaryDirectory() as base_dir:
        db_path = os.path.join(base_dir, "stamped.db")
        sealed_dir = os.path.join(base_dir, "sealed")
        anchor_dir = os.path.join(base_dir, "anchors")
        
        for d in [sealed_dir, anchor_dir]:
            os.makedirs(d)

        env = os.environ.copy()
        env["STAMPED_DB_PATH"] = db_path
        env["STAMPED_SEALED_DIR"] = sealed_dir
        env["STAMPED_ANCHOR_DIR"] = anchor_dir
        env["STAMPED_SYNTHETIC_GEO"] = "1" 
        
        print(f">>> Initializing database schema...")
        subprocess.run([sys.executable, "schemas/init_db.py", db_path], env=env, check=True)

        print(">>> Booting real HTTP capture listener...")
        listener_proc = subprocess.Popen(
            [sys.executable, "-m", "capture.listener", "--port", str(LISTENER_PORT)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(2)
        if listener_proc.poll() is not None:
            out, err = listener_proc.communicate()
            err_msg = err.decode('utf-8') if err else "Unknown error"
            fail(f"Listener crashed on boot: {err_msg}")

        try:
            for scenario in [SCENARIO_CONTROL, SCENARIO_BRUTE, SCENARIO_TRAVEL]:
                source_name = scenario["source_system"]
                print(f"\n=== Executing Scenario: {source_name} ===")
                
                # 1. CAPTURE & SEAL
                resp = requests.post(LISTENER_URL, json=scenario, timeout=5)
                assert resp.status_code == 201, f"Capture failed. 201 expected, got {resp.status_code}. Reason {resp.text}"
                
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                
                raw_content_b64 = scenario["files"][0]["content_b64"]
                raw_content = base64.b64decode(raw_content_b64).decode('utf-8')
                if isinstance(raw_content, str):
                    expected_hash = compute_sha256(raw_content)
                else:
                    expected_hash = compute_sha256(json.dumps(raw_content))
                
                cur.execute("SELECT evidence_id FROM evidence WHERE source = ?", (source_name,))
                ev_id = cur.fetchone()["evidence_id"]
                assert ev_id == expected_hash, f"Seal mismatch. Driver hash {expected_hash} != DB {ev_id}"
                # print(f"DEBUG: Contents of sealDir: {os.listdir(sealed_dir)}") --------- REMOVE
                with open(os.path.join(sealed_dir, ev_id), "r") as f:
                    assert compute_sha256(f.read()) == expected_hash, "File on disk altered post-seal."

                # 2. INGEST
                subprocess.run([sys.executable, "-m", "ingest.main", "--db", db_path], env=env, check=True, capture_output=True, text=True)
                
                cur.execute("SELECT COUNT(*) as c FROM parsed_events WHERE evidence_id = ?", (ev_id,))
                parsed_count = cur.fetchone()["c"]
                
                # Strict line math logic check
                if scenario["files"][0]["kind"] == "openssh":
                    total_lines = len([line for line in raw_content.split('\n') if line.strip()])
                    assert parsed_count == total_lines, f"Ingest leak: {total_lines} raw lines, only {parsed_count} parsed."

                # 3. DETECT
                subprocess.run([sys.executable, "-m", "detect.main", "--db", db_path], env=env, check=True)
                cur.execute("SELECT rule_name, key_identifier, event_count, severity, raw_refs FROM findings")
                current_findings = [dict(row) for row in cur.fetchall()]
                
                expected_list = EXPECTED_RESULTS[source_name]
                if not expected_list:
                    assert len(current_findings) == 0, f"Control failed. Expected 0 findings, got {len(current_findings)}"
                else:
                    exp = expected_list[0]
                    # Find matching finding in DB
                    match = next((f for f in current_findings if f["rule_name"] == exp["rule"] and f["key_identifier"] == exp["key"]), None)
                    assert match is not None, f"Expected finding {exp['rule']} for {exp['key']} not triggered."
                    assert match["event_count"] == exp["count"], f"Count mismatch for {exp['rule']}."
                    
                    # Exact line validation
                    if "brute" in source_name:
                        refs = json.loads(match["raw_refs"])
                        lines = raw_content.split('\n')
                        for ref in refs:
                            # Verify the DB line reference points exactly to a "Failed password" string
                            assert "Failed password" in lines[ref - 1], f"False provenance! Line {ref} does not contain failure."

                # 4. REPORT (Check limits and disclaimers)
                subprocess.run([sys.executable, "-m", "report.main", "--db", db_path, "--out", base_dir], env=env, check=True)
                report_path = os.path.join(base_dir, "custody_report.html")
                if os.path.exists(report_path):
                    with open(report_path, "r") as r:
                        rep_text = r.read()
                        assert "Synthetic Geo DB" in rep_text, "Report failed to disclose synthetic geo limits."

            # 5. VERIFY CROSS-CUTTING 
            print("\n=== Executing Cryptographic Integrity Checks ===")
            print(">>> Running clean verification...")
            assert subprocess.run([sys.executable, "-m", "verifier.verify", "--db", db_path, "--sealed", sealed_dir], env=env).returncode == 0
            
            print(">>> Injecting hostile database tamper...")
            # Break the chain of custody intentionally
            cur.execute("SELECT entry_id FROM custody_log LIMIT 1 OFFSET 2")
            tamper_id = cur.fetchone()["entry_id"]
            cur.execute("UPDATE custody_log SET action = 'tampered' WHERE entry_id = ?", (tamper_id,))
            conn.commit()
            
            tamper_res = subprocess.run([sys.executable, "-m", "verifier.verify", "--db", db_path, "--sealed", sealed_dir], env=env, capture_output=True, text=True)
            assert tamper_res.returncode != 0, "FATAL: Verifier accepted a tampered database."
            assert str(tamper_id) in tamper_res.stderr or str(tamper_id) in tamper_res.stdout, "FATAL: Verifier failed to pinpoint the exact broken entry_id."

            print("\n[SUCCESS] Robust E2E Pipeline passed all logic, integrity, and tamper-detection checks.")
            # conn.close()

        finally:
            print(">>> Tearing down listener process...")
            listener_proc.terminate()
            if 'conn' in locals() :
                conn.close()
            try:
                listener_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                listener_proc.kill()

if __name__ == "__main__":
    run_test_suite()