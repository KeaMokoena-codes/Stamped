"""
Custody report export.

    python -m report.export_report --db data/stamped.db --out reports --case-id CASE-001

The dashboard calls ``generate_full_report`` directly; the command line above is
the same code path for scripts and the end-to-end run (scripts/run_e2e.py).

The "Internal Database Check" line is a real recomputation of the custody hash
chain at export time. It is still an internal check only: it cannot prove the
database was not rewritten wholesale, which is what the independent verifier
and external anchors are for (the report's disclaimer says so).
"""
import argparse
import datetime
import re
import sys
from io import BytesIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # lets `python report/export_report.py` work as well as `-m`
    sys.path.insert(0, str(REPO_ROOT))

from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: E402

from access import (AccessError, DatabaseError, connect_database, get_custody_log,  # noqa: E402
                    get_directory, get_evidence, get_findings)
from app.plain_language import EMPTY_DIRECTORY, Directory  # noqa: E402
from seal.custody_log import recompute_and_verify_chain  # noqa: E402

try:
    from xhtml2pdf import pisa
    XHTML2PDF_AVAILABLE = True
except ImportError:
    XHTML2PDF_AVAILABLE = False

CASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)


def validate_case_id(case_id: str) -> str:
    """Reject unsafe case references before report rendering or filename creation."""
    if not isinstance(case_id, str) or not CASE_ID_RE.fullmatch(case_id):
        raise ValueError("Case reference must start with a letter or digit and contain only letters, digits, '_' or '-'.")
    return case_id


def _deny_pdf_resource(uri: str, _relative_to: str | None = None):
    """PDF reports are self-contained; never let content trigger file or network reads."""
    raise ValueError("PDF resource loading is disabled.")


def _internal_chain_check(conn) -> str:
    """Recompute the custody hash chain and say what happened. Never reports a pass it did not earn."""
    try:
        ok, bad_entry = recompute_and_verify_chain(conn)
        entries = conn.execute("SELECT COUNT(*) FROM custody_log").fetchone()[0]
    except Exception as exc:  # noqa: BLE001 - reported in the document, never swallowed
        return f"ERROR - the custody chain could not be checked ({type(exc).__name__})"
    if entries == 0:
        return "NOT CHECKED - the custody log is empty, so there is nothing to verify"
    if ok:
        return f"PASS - hash chain recomputed over {entries} custody entries (internal check only)"
    return f"FAIL - the custody hash chain breaks at entry #{bad_entry}"


def generate_full_report(case_id: str, role: str, actor: str, pseudonymizer=None, db_path=None):
    """Fetches live data from the DB, renders the Jinja2 HTML, and generates a PDF.

    ``db_path`` is optional; without it the configured shared database is used
    (STAMPED_DB_PATH, else data/stamped.db)."""

    case_id = validate_case_id(case_id)
    with connect_database(db_path) as conn:
        # Names are for reading only (a user's display name, an evidence file name, a finding title). They come
        # from the same role-restricted views as the data below and are never stored, hashed or exported as
        # data; if they cannot be looked up the report simply shows the stored identifiers.
        try:
            directory = Directory.from_rows(get_directory(conn, role, actor, pseudonymizer=pseudonymizer))
        except AccessError:
            raise
        except Exception:  # noqa: BLE001 - a missing name must never stop the report; ids are shown instead
            directory = EMPTY_DIRECTORY

        evidence = get_evidence(conn, role, actor, pseudonymizer=pseudonymizer)
        findings = get_findings(conn, role, actor, pseudonymizer=pseudonymizer)
        # These views append access records. Check the chain after them, then read the custody
        # snapshot last; its own access record is appended after the snapshot is returned.
        verification_status = _internal_chain_check(conn)
        custody_logs = get_custody_log(conn, role, actor, pseudonymizer=pseudonymizer)

        last_anchor_date = "No anchor recorded"
        row = conn.execute(
            "SELECT timestamp_utc FROM custody_log WHERE action = 'anchored' "
            "ORDER BY entry_id DESC LIMIT 1"
        ).fetchone()
        if row:
            last_anchor_date = row[0]

    template_dir = Path(__file__).resolve().parent / "templates"
    # Autoescape ON: finding titles and custody details contain text taken from
    # attacker-controlled logs (account names, IPs). They must never render as markup.
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html"]))
    template = env.get_template("custody_report.html")

    export_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html_out = template.render(
        case_id=case_id,
        export_date=export_date,
        actor=actor,
        role=role,
        directory=directory,
        evidence=evidence,
        findings=findings,
        custody_logs=custody_logs,
        verification_status=verification_status,
        last_anchor_date=last_anchor_date,
    )

    pdf_out = None
    if XHTML2PDF_AVAILABLE:
        result = BytesIO()
        pisa_status = pisa.CreatePDF(
            BytesIO(html_out.encode("utf-8")), dest=result, link_callback=_deny_pdf_resource
        )
        if not pisa_status.err:
            pdf_out = result.getvalue()

    return html_out, pdf_out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Export the custody report (HTML, and PDF when xhtml2pdf is installed).")
    parser.add_argument("--db", required=True, type=Path, help="path to the Stamped SQLite database")
    parser.add_argument("--out", required=True, type=Path, help="output folder (created if missing)")
    parser.add_argument("--case-id", default="CASE-UNSPECIFIED")
    parser.add_argument("--role", default="examiner", help="role the report is generated for (default: examiner)")
    parser.add_argument("--actor", default="report-cli", help="actor recorded in the custody log for this export")
    args = parser.parse_args(argv)

    try:
        html_out, pdf_out = generate_full_report(args.case_id, args.role, args.actor, db_path=args.db)
    except (DatabaseError, AccessError, ValueError) as exc:
        print(f"ERROR: could not generate the report: {exc}", file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    html_path = args.out / "custody_report.html"
    html_path.write_text(html_out, encoding="utf-8")
    print(f"wrote {html_path}")
    if pdf_out:
        pdf_path = args.out / "custody_report.pdf"
        pdf_path.write_bytes(pdf_out)
        print(f"wrote {pdf_path}")
    else:
        print("PDF not written (xhtml2pdf is not installed, or conversion failed).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())