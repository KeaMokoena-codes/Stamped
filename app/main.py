"""Streamlit entry point for the Stamped case workspace."""

import os
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

    st.metric("Accessible custody entries", len(entries))
    st.info(
        "Verification is not reported by this app skeleton. Use the independent verifier "
        "with an exported case package to check the hash chain, signatures, and anchors."
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
