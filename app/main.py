"""Streamlit entry point for the Stamped case workspace."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import streamlit as st

from access import (
    AccessError,
    Action,
    DatabaseError,
    Pseudonymizer,
    Resource,
    Role,
    can,
    connect_database,
    export_custody_log,
    export_findings,
    export_timeline_from_db,
    get_custody_log,
    get_evidence,
    get_findings,
    get_timeline_from_db,
    resolve_role,
)

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PSEUDONYM_KEY = REPOSITORY_ROOT / "keys" / "pseudonym.key"
PSEUDONYM_KEY_ENV_VAR = "STAMPED_PSEUDONYM_KEY"


def _load_pseudonymizer() -> Pseudonymizer | None:
    key_path = Path(os.environ.get(PSEUDONYM_KEY_ENV_VAR, DEFAULT_PSEUDONYM_KEY)).expanduser()
    if not key_path.is_file():
        return None
    return Pseudonymizer.from_key_file(key_path)


def _identity() -> tuple[str, Role] | None:
    actor = st.session_state.get("stamped_actor")
    if not actor:
        return None
    try:
        with connect_database() as connection:
            role = resolve_role(connection, actor)
    except (AccessError, DatabaseError) as exc:
        st.sidebar.error(f"Could not resolve this login: {exc}")
        st.session_state.pop("stamped_actor", None)
        return None
    return actor, role


def _login_sidebar() -> tuple[str, Role] | None:
    with st.sidebar.form("demo_login"):
        user_id = st.text_input("Registered user ID", key="stamped_login_user_id")
        submitted = st.form_submit_button("Sign in / switch user")

    if submitted:
        user_id = user_id.strip()
        if not user_id:
            st.sidebar.error("Enter a registered user ID.")
            st.session_state.pop("stamped_actor", None)
        else:
            try:
                with connect_database() as connection:
                    resolve_role(connection, user_id)
            except (AccessError, DatabaseError) as exc:
                st.sidebar.error(f"Sign-in failed: {exc}")
                st.session_state.pop("stamped_actor", None)
            else:
                st.session_state["stamped_actor"] = user_id

    identity = _identity()
    if identity is None:
        return None

    actor, role = identity
    st.sidebar.caption(f"Signed in: {actor} ({role.value})")
    if st.sidebar.button("Sign out", key="stamped_sign_out"):
        st.session_state.pop("stamped_actor", None)
        st.rerun()
    return identity


def _page_identity() -> tuple[str, Role] | None:
    identity = _identity()
    if identity is None:
        st.info("Sign in with a registered user ID to open a case view.")
    return identity


def _load_error(exc: Exception) -> None:
    st.error(f"Could not load this view: {exc}")


def case_overview() -> None:
    st.header("Case overview")
    identity = _page_identity()
    if identity is None:
        return
    actor, role = identity

    try:
        pseudonymizer = _load_pseudonymizer()
        with connect_database() as connection:
            evidence = get_evidence(connection, role, actor, pseudonymizer=pseudonymizer)
            findings = get_findings(connection, role, actor, pseudonymizer=pseudonymizer)
    except (AccessError, DatabaseError, OSError, ValueError) as exc:
        _load_error(exc)
        return

    evidence_metric, findings_metric = st.columns(2)
    evidence_metric.metric("Evidence items", len(evidence))
    findings_metric.metric("Findings", len(findings))
    st.subheader("Evidence")
    if evidence:
        st.dataframe(evidence, width="stretch")
    else:
        st.info("No evidence items are recorded in the shared database yet.")
    st.subheader("Findings")
    if findings:
        st.dataframe(findings, width="stretch")
    else:
        st.info("No findings are recorded in the shared database yet.")


def timeline_page() -> None:
    st.header("Timeline")
    st.caption("Events from recorded auth-log and CloudTrail parser artifacts, merged with persisted findings.")
    identity = _page_identity()
    if identity is None:
        return
    actor, role = identity

    try:
        pseudonymizer = _load_pseudonymizer()
        with connect_database() as connection:
            entries = get_timeline_from_db(
                connection, role, actor, pseudonymizer=pseudonymizer
            )
    except (AccessError, DatabaseError, OSError, ValueError) as exc:
        _load_error(exc)
        return

    if entries:
        st.caption(f"{len(entries)} chronological timeline entries")
        for entry in entries:
            is_finding = entry.get("entry_type") == "finding"
            marker = "🚩 Finding" if is_finding else "• Event"
            summary = entry.get("summary", "Timeline entry")
            label = f"{marker} · {entry.get('timestamp_utc', 'Unknown time')} · {summary}"
            with st.expander(label):
                if is_finding:
                    severity = str(entry.get("severity", "medium")).lower()
                    message = f"{severity.title()} severity finding"
                    if severity in {"critical", "high"}:
                        st.error(message)
                    else:
                        st.warning(message)
                else:
                    st.caption(
                        f"{entry.get('service', 'unknown')} · "
                        f"{entry.get('event_type', 'event')} · "
                        f"{entry.get('outcome', 'unknown')}"
                    )
                st.markdown("**Provenance**")
                st.json(entry.get("provenance", {}))
                st.markdown("**Details**")
                st.json(entry.get("details", {}))
    else:
        st.info("No parser artifacts or findings are recorded in the shared database yet.")


def findings_page() -> None:
    st.header("Findings")
    identity = _page_identity()
    if identity is None:
        return
    actor, role = identity

    try:
        pseudonymizer = _load_pseudonymizer()
        with connect_database() as connection:
            findings = get_findings(connection, role, actor, pseudonymizer=pseudonymizer)
    except (AccessError, DatabaseError, OSError, ValueError) as exc:
        _load_error(exc)
        return

    if findings:
        st.dataframe(findings, width="stretch")
    else:
        st.info("No findings are recorded in the shared database yet.")


def custody_history_page() -> None:
    st.header("Custody history")
    identity = _page_identity()
    if identity is None:
        return
    actor, role = identity

    try:
        pseudonymizer = _load_pseudonymizer()
        with connect_database() as connection:
            entries = get_custody_log(connection, role, actor, pseudonymizer=pseudonymizer)
    except (AccessError, DatabaseError, OSError, ValueError) as exc:
        _load_error(exc)
        return

    if entries:
        st.dataframe(entries, width="stretch")
    else:
        st.info("The shared custody log is empty.")


def verification_page() -> None:
    st.header("Verification")
    if _page_identity() is None:
        return

    st.info(
        "The demo below runs the independent verifier against a disposable, synthetic case. "
        "It does not use or modify the live case database."
    )
    with st.container(border=True):
        st.subheader("Demo only: isolated tamper-detection demo")
        st.warning(
            "This separate demo creates a fresh case with synthetic records, tampers only "
            "with its disposable copy, and checks the hash chain. No real evidence or "
            "custody log is changed. Signatures and external anchors are not tested."
        )
        if st.button(
            "demo: simulate tampering",
            key="stamped_simulate_tampering",
            type="primary",
        ):
            repository_root = Path(__file__).resolve().parent.parent
            verifier_path = repository_root / "verifier" / "verify.py"
            with tempfile.TemporaryDirectory(prefix="stamped-tamper-demo-") as temp_dir:
                case_dir = Path(temp_dir) / "demo-case"
                try:
                    preparation = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "scripts.simulate_tamper",
                            "--case-dir",
                            str(case_dir),
                        ],
                        cwd=repository_root,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    if preparation.returncode != 0:
                        st.error("Could not prepare the isolated demo case.")
                        st.code(preparation.stdout + preparation.stderr, language="text")
                        return

                    result = subprocess.run(
                        [
                            sys.executable,
                            str(verifier_path),
                            "--case-export",
                            str(case_dir),
                            "--allow-no-anchors",
                            "--json",
                        ],
                        cwd=repository_root,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    st.error(f"The demo command could not complete: {exc}")
                    return

            st.markdown("### Actual verifier output")
            verifier_output = result.stdout + result.stderr
            st.code(verifier_output, language="json")
            try:
                report = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                st.error(
                    "The verifier did not return its expected JSON report "
                    f"(exit code {result.returncode}): {exc}"
                )
                return

            expected_exit_code = {"PASS": 0, "FAIL": 1, "ERROR": 2}.get(
                report.get("overall")
            )
            if result.returncode != expected_exit_code:
                st.error(
                    "The verifier exit code does not match its reported result "
                    f"(exit code {result.returncode}, result {report.get('overall')!r})."
                )
                return

            chain_check = report.get("checks", {}).get("chain", {})
            broken_entry_id = report.get("broken_entry_id")
            if (
                report.get("overall") == "FAIL"
                and chain_check.get("status") == "FAIL"
                and isinstance(broken_entry_id, int)
            ):
                st.error(
                    "The verifier detected the tampering. "
                    f"The first broken custody entry is #{broken_entry_id}."
                )
            elif report.get("overall") == "PASS":
                st.warning(
                    "The verifier reported PASS; this demo did not produce the expected "
                    "tamper detection."
                )
            else:
                st.error(
                    "The verifier did not confirm the expected hash-chain tampering. "
                    f"Reported result: {report.get('overall', 'unknown')}."
                )


def reports_page() -> None:
    st.header("Reports")
    identity = _page_identity()
    if identity is None:
        return
    actor, role = identity
    exports = {
        "Findings": (Resource.FINDINGS, export_findings),
        "Timeline": (Resource.TIMELINE, export_timeline_from_db),
        "Custody history": (Resource.CUSTODY_LOG, export_custody_log),
    }
    available = {
        name: (resource, exporter)
        for name, (resource, exporter) in exports.items()
        if can(role, resource, Action.EXPORT)
    }
    if not available:
        st.info("This role does not have permission to export reports.")
        return

    report_name = st.selectbox("Report", list(available), key="stamped_report_type")
    if st.button("Prepare report", key="stamped_prepare_report"):
        resource, exporter = available[report_name]
        try:
            pseudonymizer = _load_pseudonymizer()
            with connect_database() as connection:
                result = exporter(
                    connection, role, actor, pseudonymizer=pseudonymizer
                )
        except (AccessError, DatabaseError, OSError, ValueError) as exc:
            _load_error(exc)
            return

        st.success(f"Prepared {result.row_count} rows; SHA-256: {result.sha256}")
        st.download_button(
            "Download JSON report",
            data=result.content,
            file_name=f"stamped-{result.dataset}.json",
            mime="application/json",
        )
    
    
    # ... (Kea's existing JSON exports code) ...

    st.divider()
    st.subheader("Formal Custody Report (PDF/HTML)")
    st.caption("Generates a complete chain-of-custody document for the current database state.")
    
    if st.button("Generate Full Case Report", type="primary"):
        from report.export_report import generate_full_report
        
        with st.spinner("Compiling live case data..."):
            try:
                pseudonymizer = _load_pseudonymizer()
                # Use role.value if role is an Enum, otherwise use role directly
                role_str = role.value if hasattr(role, 'value') else str(role)
                html_data, pdf_data, case_id = generate_full_report(role_str, actor, pseudonymizer)
                
                st.success(f"Report generated successfully: `{case_id}`")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.download_button(
                        label="Download HTML Report",
                        data=html_data,
                        file_name=f"{case_id}_Custody_Report.html",
                        mime="text/html"
                    )
                with col2:
                    if pdf_data:
                        st.download_button(
                            label="Download PDF Report",
                            data=pdf_data,
                            file_name=f"{case_id}_Custody_Report.pdf",
                            mime="application/pdf"
                        )
                    else:
                        st.warning("PDF export unavailable (WeasyPrint missing). Download HTML instead.")
                        
            except Exception as exc:
                st.error(f"Failed to generate report: {exc}")   


def main() -> None:
    st.set_page_config(page_title="Stamped", layout="wide")
    st.title("Stamped")
    st.caption("Court-ready digital evidence that stays trustworthy for 30 years.")
    st.sidebar.header("Demo login")
    st.sidebar.caption(
        "Enter a user ID already registered in the shared database. "
        "The role is resolved from that database; this demo login is not password authentication."
    )

    if _login_sidebar() is None:
        st.info(
            "Initialize the shared database with `python schemas/init_db.py` and add an active "
            "user before signing in. No sample case data is generated by the app."
        )
        return

    pages = [
        st.Page(case_overview, title="Case overview", default=True),
        st.Page(timeline_page, title="Timeline"),
        st.Page(findings_page, title="Findings"),
        st.Page(custody_history_page, title="Custody history"),
        st.Page(verification_page, title="Verification"),
        st.Page(reports_page, title="Reports"),
    ]
    st.navigation(pages, position="sidebar").run()


if __name__ == "__main__":
    main()
