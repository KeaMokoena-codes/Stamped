"""See docs/access-control.md.

The UI must read case data ONLY through the functions exported here."""
from access.data import (AccessLogError, ExportResult, authorize, export_custody_log, export_findings,
                         export_timeline, get_custody_log, get_evidence, get_findings, get_timeline,
                         resolve_role)
from access.masking import Pseudonymizer, PseudonymizerRequired
from access.roles import (AccessDenied, AccessError, Action, Resource, Role, UnknownRoleError, can,
                          parse_role, require)

__all__ = [
    "AccessDenied", "AccessError", "AccessLogError", "Action", "ExportResult", "Pseudonymizer",
    "PseudonymizerRequired", "Resource", "Role", "UnknownRoleError", "authorize", "can",
    "export_custody_log", "export_findings", "export_timeline", "get_custody_log", "get_evidence",
    "get_findings", "get_timeline", "parse_role", "require", "resolve_role",
]