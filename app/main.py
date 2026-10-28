"""Streamlit entry point for the Stamped case workspace."""

import json
import logging
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
from app.plain_language import (
    CUSTODY_COLUMNS,
    EVIDENCE_COLUMNS,
    FINDINGS_COLUMNS,
    GLOSSARY,
    demo_expectation,
    friendly_error,
    plain_rows,
    role_label,
    signin_error,
    summarise_verification,
)
from app.theme import inject_theme, show_verdict

LOGGER = logging.getLogger("stamped.app")

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
        _sidebar_problem(exc)
        st.session_state.pop("stamped_actor", None)
        return None
    return actor, role


def _sidebar_problem(exc: Exception) -> None:
    """Sign-in trouble in plain words. The raw exception goes to the server log, not the screen."""
    LOGGER.warning("Sign-in problem (%s): %s", type(exc).__name__, exc)
    friendly = signin_error(exc)
    st.sidebar.error(f"{friendly.what_happened} {friendly.what_to_do}")


def _login_sidebar() -> tuple[str, Role] | None:
    with st.sidebar.form("demo_login"):
        user_id = st.text_input("Your user ID", key="stamped_login_user_id")
        submitted = st.form_submit_button("Sign in (or switch user)")

    if submitted:
        user_id = user_id.strip()
        if not user_id:
            st.sidebar.error("Please type your user ID, then press Sign in.")
            st.session_state.pop("stamped_actor", None)
        else:
            try:
                with connect_database() as connection:
                    resolve_role(connection, user_id)
            except (AccessError, DatabaseError) as exc:
                _sidebar_problem(exc)
                st.session_state.pop("stamped_actor", None)
            else:
                st.session_state["stamped_actor"] = user_id

    identity = _identity()
    if identity is None:
        return None

    actor, role = identity
    st.sidebar.caption(f"Signed in: {actor} ({role_label(role)})")
    if st.sidebar.button("Sign out", key="stamped_sign_out"):
        st.session_state.pop("stamped_actor", None)
        st.rerun()
    return identity


def _page_identity() -> tuple[str, Role] | None:
    identity = _identity()
    if identity is None:
        st.info("Please sign in using the panel on the left to see this page.")
    return identity


def _load_error(exc: Exception, headline: str = "This page could not be shown.") -> None:
    """What happened and what to do. The raw exception goes to the server log, never the screen."""
    LOGGER.warning("Dashboard error (%s): %s", type(exc).__name__, exc, exc_info=exc)
    friendly = friendly_error(exc)
    st.error(f"{headline} {friendly.what_happened}\n\n**What to do:** {friendly.what_to_do}")
    st.caption(
        f"Reference for your administrator: {friendly.reference}. "
        "The full technical record is in the server log."
    )


def _show_records(
        title: str,
        rows: list[dict],
        empty_message: str,
        columns: tuple[tuple[str, str], ...] | None = None,
) -> None:
    """Plain table first; the complete stored record stays one click away.

    Both tables are built from the same rows the access layer returned for this role,
    so nothing is added, and nothing a role may not see can appear.
    """
    st.subheader(title)
    if not rows:
        st.info(empty_message)
        return
    plain = plain_rows(rows, columns) if columns else None
    if plain is None:
        st.dataframe(rows, width="stretch")
        return
    st.dataframe(plain, width="stretch")
    with st.expander("Technical details: the full record"):
        st.caption(
            "Every stored field, including fingerprints, identifiers and raw data, "
            "exactly as recorded."
        )
        st.dataframe(rows, width="stretch")


def case_overview() -> None:
    st.header("Case overview")
    st.caption("A summary of the evidence and findings your role is allowed to see.")
    identity = _page_identity()
    if identity is None:
        return
    actor, role = identity

    try:
        pseudonymizer = _load_pseudonymizer()
        with connect_database() as connection:
            evidence = get_evidence(connection, role, actor, pseudonymizer=pseudonymizer)
            findings = get_findings(connection, role, actor, pseudonymizer=pseudonymizer)
            custody = (
                get_custody_log(connection, role, actor, pseudonymizer=pseudonymizer)
                if role is Role.PROSECUTOR
                else []
            )
    except (AccessError, DatabaseError, OSError, ValueError) as exc:
        _load_error(exc)
        return

    if role is Role.EXAMINER:
        st.subheader("Forensic analysis workspace")
        st.caption("The complete evidence record and the findings drawn from it.")
        evidence_metric, findings_metric = st.columns(2)
        evidence_metric.metric("Evidence items", len(evidence))
        findings_metric.metric("Findings", len(findings))
        _show_records(
            "Evidence register",
            evidence,
            "No evidence items are recorded in the shared database yet.",
            EVIDENCE_COLUMNS,
        )
        _show_records(
            "Analysis findings", findings, "No findings are recorded yet.", FINDINGS_COLUMNS
        )
    elif role is Role.INVESTIGATING_OFFICER:
        st.subheader("Investigation workspace")
        st.caption(
            "Start with the most serious leads. In this role you can see the real account "
            "names and IP addresses."
        )
        high_priority = sum(
            str(finding.get("severity", "")).lower() in {"critical", "high"}
            for finding in findings
        )
        leads_metric, evidence_metric = st.columns(2)
        leads_metric.metric("Investigation leads", len(findings))
        evidence_metric.metric("High-priority leads", high_priority)
        severities = sorted(
            {str(finding.get("severity", "unknown")).lower() for finding in findings}
        )
        selected_severity = st.selectbox(
            "Filter leads by severity",
            ["All"] + severities,
            key="stamped_investigation_severity",
            )
        visible_findings = (
            findings
            if selected_severity == "All"
            else [
                finding
                for finding in findings
                if str(finding.get("severity", "unknown")).lower() == selected_severity
            ]
        )
        _show_records(
            "Investigative leads",
            visible_findings,
            "No findings are recorded yet.",
            FINDINGS_COLUMNS,
        )
        _show_records(
            "Evidence available to investigate",
            evidence,
            "No evidence items are recorded in the shared database yet.",
            EVIDENCE_COLUMNS,
        )
    else:
        st.subheader("Prosecution case brief")
        st.caption(
            "In this view, names, accounts and IP addresses are replaced with codes. Review "
            "the findings, the list of evidence and who has handled it."
        )
        serious_findings = sum(
            str(finding.get("severity", "")).lower() in {"critical", "high"}
            for finding in findings
        )
        findings_metric, serious_metric, custody_metric = st.columns(3)
        findings_metric.metric("Case findings", len(findings))
        serious_metric.metric("High-priority findings", serious_findings)
        custody_metric.metric("Custody entries", len(custody))
        _show_records(
            "Findings for review", findings, "No findings are recorded yet.", FINDINGS_COLUMNS
        )
        _show_records(
            "Evidence schedule",
            evidence,
            "No evidence items are recorded in the shared database yet.",
            EVIDENCE_COLUMNS,
        )
        _show_records(
            "Chain of custody",
            custody,
            "The shared custody log is empty.",
            CUSTODY_COLUMNS,
        )


def timeline_page() -> None:
    st.header("Timeline")
    st.caption(
        "What happened, in time order. Entries marked Finding are suspicious activity the "
        "system flagged; open any entry to see where it came from."
    )
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
        st.caption(f"{len(entries)} entries, oldest first")
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
                        st.error(f"{message}: review this first.")
                    else:
                        st.warning(message)
                else:
                    st.caption(
                        f"{entry.get('service', 'unknown')} · "
                        f"{entry.get('event_type', 'event')} · "
                        f"{entry.get('outcome', 'unknown')}"
                    )
                st.markdown("**Where this record came from**")
                st.json(entry.get("provenance", {}))
                st.markdown("**Technical details**")
                st.json(entry.get("details", {}))
    else:
        st.info("There is nothing on the timeline yet: no events or findings have been recorded.")


def findings_page() -> None:
    st.header("Findings")
    st.caption(
        "Suspicious activity the system flagged, and how serious it is. "
        "Critical and High findings need attention first."
    )
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

    _show_records(
        "Flagged activity",
        findings,
        "No findings are recorded in the shared database yet.",
        FINDINGS_COLUMNS,
    )


def custody_history_page() -> None:
    st.header("Custody history")
    st.caption(
        "Who handled the evidence, what they did and when. Opening evidence, findings or the "
        "timeline is recorded here too."
    )
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

    _show_records(
        "Record of handling",
        entries,
        "The shared custody log is empty.",
        CUSTODY_COLUMNS,
    )


def verification_page() -> None:
    st.header("Verification: has anything been altered?")
    st.caption(
        "Checks that a case record has not been changed since it was sealed, and tells you "
        "in plain words whether you can rely on it."
    )
    if _page_identity() is None:
        return

    st.info(
        "The demo below runs the independent verifier on a made-up practice case. "
        "It does not use or change the live case database."
    )
    with st.container(border=True):
        st.subheader("Demo only: see tampering get caught")
        st.warning(
            "This demo builds a practice case with made-up records, then deliberately alters "
            "one record in a disposable copy to show the check catching it. No real evidence "
            "or custody record is touched. Only the chain of custody entries is checked; "
            "signatures and signed checkpoints are not."
        )
        if st.button(
                "Run tamper-detection demo",
                key="stamped_simulate_tampering",
                type="primary",
        ):
            repository_root = Path(__file__).resolve().parent.parent
            verifier_path = repository_root / "verifier" / "verify.py"
            with st.spinner("Running the check..."):
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
                            LOGGER.warning(
                                "Demo case preparation failed: %s",
                                preparation.stdout + preparation.stderr,
                                )
                            st.error(
                                "The practice case could not be set up on this computer, so "
                                "no check was run. Nothing was changed.\n\n"
                                "**What to do:** ask your administrator to check the "
                                "Stamped installation."
                            )
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
                        LOGGER.warning("Demo command could not complete: %s", exc)
                        st.error(
                            "The check did not finish, so nothing has been confirmed. "
                            "Nothing was changed.\n\n"
                            "**What to do:** try again. If it keeps happening, ask your "
                            "administrator."
                        )
                        return

            verifier_output = result.stdout + result.stderr
            report = _read_report(result)
            show_verdict(summarise_verification(report))
            if report is not None:
                caught, note = demo_expectation(report)
                if caught:
                    st.caption(note)
                else:
                    st.warning(note)
            with st.expander("Technical details: the verifier's full report"):
                st.caption(
                    "Exactly what the verifier printed. Share this with a technical "
                    "colleague if you need a second opinion."
                )
                st.code(verifier_output, language="json")


def _read_report(result: subprocess.CompletedProcess) -> dict | None:
    """The verifier's JSON report, or None if it cannot be trusted.

    None is shown to the reader as UNKNOWN (never as a pass). The reason goes to the log.
    """
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        LOGGER.warning(
            "Verifier did not return JSON (exit code %s): %s", result.returncode, exc
        )
        return None
    if not isinstance(report, dict):
        LOGGER.warning("Verifier JSON was not an object (exit code %s)", result.returncode)
        return None
    expected_exit_code = {"PASS": 0, "FAIL": 1, "ERROR": 2}.get(report.get("overall"))
    if result.returncode != expected_exit_code:
        LOGGER.warning(
            "Verifier exit code %s does not match its reported result %r",
            result.returncode,
            report.get("overall"),
        )
        return None
    return report


def reports_page() -> None:
    st.header("Reports")
    st.caption(
        "Download a copy of what you are allowed to see, to keep or hand to someone else."
    )
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
        st.info("Your role is not allowed to download reports.")
        return

    report_name = st.selectbox("Which report?", list(available), key="stamped_report_type")
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

        st.success(
            f"Prepared {result.row_count} rows. Fingerprint (SHA-256): {result.sha256}. "
            "Anyone can use this fingerprint to confirm the downloaded file was not changed."
        )
        st.download_button(
            "Download report (JSON file)",
            data=result.content,
            file_name=f"stamped-{result.dataset}.json",
            mime="application/json",
        )

    st.divider()
    st.subheader("Formal custody report (PDF or web page)")
    st.caption(
        "A complete chain-of-custody document for the case as it stands now, "
        "suitable for filing."
    )

    case_id_input = st.text_input("Case reference (for example CASE-001):", value="CASE-")

    if st.button("Create the formal report", type="primary") and case_id_input:
        from report.export_report import generate_full_report

        with st.spinner("Putting the report together..."):
            try:
                pseudonymizer = _load_pseudonymizer()
                role_str = role.value if hasattr(role, 'value') else str(role)
                html_data, pdf_data = generate_full_report(case_id_input, role_str, actor, pseudonymizer)

                st.success(f"The report for `{case_id_input}` is ready to download.")

                col1, col2 = st.columns(2)
                with col1:
                    st.download_button(
                        label="Download report (web page)",
                        data=html_data,
                        file_name=f"{case_id_input}_Custody_Report.html",
                        mime="text/html"
                    )
                with col2:
                    if pdf_data:
                        st.download_button(
                            label="Download report (PDF)",
                            data=pdf_data,
                            file_name=f"{case_id_input}_Custody_Report.pdf",
                            mime="application/pdf"
                        )
                    else:
                        st.warning(
                            "The PDF version is not available on this computer. The web page "
                            "version contains the same information. Ask your administrator "
                            "to enable PDF export."
                        )

            except Exception as exc:  # noqa: BLE001 - shown to the reader in plain words
                _load_error(exc, headline="The report could not be created.")

def main() -> None:
    st.set_page_config(page_title="Stamped", page_icon="\U0001F50F", layout="wide")
    inject_theme()
    st.title("Stamped")
    st.caption("Court-ready digital evidence that stays trustworthy for 30 years.")
    st.sidebar.header("Sign in")
    st.sidebar.caption(
        "Enter the user ID you were given. This is a demonstration sign-in: it checks your "
        "ID but does not use a password. Your role decides what you can see."
    )

    identity = _login_sidebar()
    with st.sidebar.expander("What do these terms mean?"):
        for term, meaning in GLOSSARY:
            st.markdown(f"**{term}**  \n{meaning}")
    if identity is None:
        st.info(
            "Welcome. Sign in with your user ID in the panel on the left to open your case. "
            "If you do not have a user ID, ask your administrator."
        )
        with st.expander("First-time setup (for administrators)"):
            st.markdown(
                "Initialize the shared database with `python schemas/init_db.py` and add an "
                "active user before signing in. No sample case data is generated by the app."
            )
        return
    _, role = identity

    workspace_names = {
        Role.EXAMINER: "Forensic analysis workspace",
        Role.INVESTIGATING_OFFICER: "Investigation workspace",
        Role.PROSECUTOR: "Prosecution case brief",
    }
    st.sidebar.subheader(workspace_names[role])
    pages = [
        st.Page(case_overview, title="Case overview", default=True),
        st.Page(timeline_page, title="Timeline"),
        st.Page(findings_page, title="Findings"),
        st.Page(custody_history_page, title="Custody history"),
        st.Page(verification_page, title="Verification"),
        st.Page(reports_page, title="Reports"),
    ]
    navigation = st.navigation(pages, position="sidebar")
    previous_role = st.session_state.get("stamped_navigation_role")
    st.session_state["stamped_navigation_role"] = role.value
    if previous_role is not None and previous_role != role.value:
        st.switch_page(pages[0])
    navigation.run()


if __name__ == "__main__":
    main()