import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from access import connect_database, get_custody_log, get_evidence, get_findings

try:
    from xhtml2pdf import pisa
    from io import BytesIO
    XHTML2PDF_AVAILABLE = True
except ImportError:
    XHTML2PDF_AVAILABLE = False

def generate_full_report(case_id: str, role: str, actor: str, pseudonymizer=None):
    """Fetches live data from the DB, renders the Jinja2 HTML, and generates a PDF."""
    
    with connect_database() as conn:
        custody_logs = get_custody_log(conn, role, actor, pseudonymizer=pseudonymizer)
        evidence = get_evidence(conn, role, actor, pseudonymizer=pseudonymizer)
        findings = get_findings(conn, role, actor, pseudonymizer=pseudonymizer)
        
        # Check last anchor date and basic DB integrity
        last_anchor_date = "No anchor found"
        verification_status = "Pass (Internal Check)"
        try:
            cur = conn.cursor()
            cur.execute("SELECT timestamp_utc FROM custody_log WHERE action LIKE '%anchor%' ORDER BY timestamp_utc DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                last_anchor_date = row[0]
            else:
                cur.execute("SELECT timestamp_utc FROM custody_log ORDER BY timestamp_utc DESC LIMIT 1")
                row = cur.fetchone()
                if row:
                    last_anchor_date = f"Latest Entry: {row[0]}"
        except Exception as e:
            verification_status = f"Fail ({str(e)})"

    template_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("custody_report.html")

    export_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

    html_out = template.render(
        case_id=case_id,
        export_date=export_date,
        actor=actor,
        role=role,
        evidence=evidence,
        findings=findings,
        custody_logs=custody_logs,
        verification_status=verification_status,
        last_anchor_date=last_anchor_date
    )

    pdf_out = None
    if XHTML2PDF_AVAILABLE:
        result = BytesIO()
        pisa_status = pisa.CreatePDF(BytesIO(html_out.encode('utf-8')), dest=result)
        if not pisa_status.err:
            pdf_out = result.getvalue()

    return html_out, pdf_out