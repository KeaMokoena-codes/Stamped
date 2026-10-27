import datetime
import uuid
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from access import connect_database, get_custody_log, get_evidence, get_findings

# Graceful fallback in case WeasyPrint fails to install on Windows
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except Exception:  # Catch OSError, ImportError, or any other loading issue
    WEASYPRINT_AVAILABLE = False
    
def generate_full_report(role: str, actor: str, pseudonymizer=None):
    """Fetches live data from the DB, renders the Jinja2 HTML, and optionally generates a PDF."""
    
    # 1. Fetch live case data respecting RBAC
    with connect_database() as conn:
        custody_logs = get_custody_log(conn, role, actor, pseudonymizer=pseudonymizer)
        evidence = get_evidence(conn, role, actor, pseudonymizer=pseudonymizer)
        findings = get_findings(conn, role, actor, pseudonymizer=pseudonymizer)

    # 2. Setup Jinja2 Environment
    template_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("custody_report.html")

    # 3. Generate dynamic Case ID & render HTML
    case_id = f"CASE-{datetime.datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    export_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

    html_out = template.render(
        case_id=case_id,
        export_date=export_date,
        actor=actor,
        role=role,
        evidence=evidence,
        findings=findings,
        custody_logs=custody_logs
    )

    # 4. Generate PDF if available
    pdf_out = None
    if WEASYPRINT_AVAILABLE:
        pdf_out = HTML(string=html_out).write_pdf()

    return html_out, pdf_out, case_id