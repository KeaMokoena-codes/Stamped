"""
Capture listener: a local stand-in for a real alerting pipeline.

It exposes one endpoint, ``POST /alert``. A caller posts an evidence bundle
(format: docs/bundle-format.md). The listener validates the whole bundle,
stages each file, and calls ``seal_evidence()`` once per file. It does not talk
to any external service. It binds to loopback by default without authentication;
non-loopback operation requires an HMAC secret and the production WSGI server.

Run it (from the repository root, after ``python schemas/init_db.py``):

    python -m capture.listener --staging-root data/sample
    python scripts/send_example_alert.py

or trigger it by hand (use curl.exe, not curl, in Windows PowerShell):

    curl.exe -X POST http://127.0.0.1:5000/alert -H "Content-Type: application/json" --data-binary "@data/sample/bundle_example.json"

Design rules that matter for safety:
  * Everything is validated, and every declared hash checked, BEFORE the first
    file is sealed, so a bad bundle seals nothing.
  * Input is rejected, never "cleaned up". A file name with a path separator is
    an error, not something to strip.
  * Payload text is never used to build a path. A file's ``name`` must be a
    plain single name; ``path`` entries are only honoured when a staging root
    is configured and must resolve inside it.
  * Error responses never include stack traces or server paths. Request bodies
    are never logged (they may contain evidence).
  * A non-loopback listener requires STAMPED_CAPTURE_HMAC_SECRET, and only runs
    under Gunicorn. Signed requests include a timestamp and one-use nonce.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import tempfile
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # lets `python capture/listener.py` work as well as `-m`
    sys.path.insert(0, str(REPO_ROOT))

from flask import Flask, jsonify, request  # noqa: E402
from werkzeug.exceptions import HTTPException  # noqa: E402

from access.database import DatabaseError, connect_database  # noqa: E402
from capture.auth import valid_request_signature  # noqa: E402
from seal.intake import DEFAULT_SEALED_DIR, IntakeError, seal_evidence  # noqa: E402

log = logging.getLogger("stamped.capture")

FORMAT_VERSION = "stamped-bundle/1"

# What the listener writes into the custody log as the acting party. The role
# string is still to be confirmed with Ash (same open question as the TODO in
# detect/findings.py); change these two constants, nothing else depends on them.
ACTOR = "capture-listener"
ROLE = "collector"

KINDS = frozenset({"auth_log", "cloudtrail_json"})
TOP_REQUIRED = ("format_version", "bundle_id", "source_system", "alert_type",
                "alert_timestamp", "captured_at", "collector", "files")
TOP_OPTIONAL = ("alert_id",)
FILE_ALLOWED = frozenset({"name", "kind", "path", "content_b64", "sha256", "base_year"})
ID_FIELDS = ("bundle_id", "source_system", "alert_type", "collector", "alert_id")

MAX_ID_LEN = 256
MAX_NAME_LEN = 128
MAX_PATH_LEN = 1024
MAX_ERRORS_REPORTED = 20
MIN_BASE_YEAR, MAX_BASE_YEAR = 1970, 2100

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_NAME_FORBIDDEN = set('/\\:<>"|?*')
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


@dataclass(frozen=True)
class Settings:
    db_path: Path | None = None            # None -> STAMPED_DB_PATH or data/stamped.db
    sealed_dir: Path = DEFAULT_SEALED_DIR
    staging_root: Path | None = None       # None -> `path` entries are rejected
    max_body_bytes: int = 16 * 1024 * 1024
    max_files: int = 10
    max_file_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    auth_secret: bytes | None = None
    max_requests_per_minute: int = 60
    max_replay_cache_entries: int = 10_000


class BundleError(Exception):
    """The bundle is not acceptable. ``errors`` are safe to show to the sender."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors[:MAX_ERRORS_REPORTED]


@dataclass(frozen=True)
class StagedFile:
    name: str
    kind: str
    data: bytes
    sha256: str
    base_year: int | None


@dataclass(frozen=True)
class ValidBundle:
    fields: dict
    files: list[StagedFile]


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def _no_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key {key[:40]!r}")
        obj[key] = value
    return obj


def _reject_constant(name):
    raise ValueError(f"{name} is not valid JSON")


def parse_json(raw: bytes):
    """Strict JSON: valid UTF-8, no NaN/Infinity, no duplicate keys."""
    try:
        return json.loads(raw.decode("utf-8"),
                          object_pairs_hook=_no_duplicate_keys,
                          parse_constant=_reject_constant)
    except UnicodeDecodeError:
        raise BundleError(["body is not valid UTF-8"]) from None
    except (ValueError, RecursionError) as exc:  # JSONDecodeError is a ValueError
        raise BundleError([f"body is not valid JSON: {str(exc)[:120]}"]) from None


def _has_control_chars(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def _parse_utc(value, label: str, errors: list[str]) -> str | None:
    if type(value) is not str:
        errors.append(f"{label}: must be a string")
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        errors.append(f"{label}: not an ISO 8601 timestamp")
        return None
    if moment.tzinfo is None or moment.utcoffset() != timedelta(0):
        errors.append(f"{label}: must be UTC with an explicit offset (Z or +00:00)")
        return None
    return moment.astimezone(timezone.utc).isoformat()


def _check_id(value, label: str, errors: list[str]) -> str | None:
    if type(value) is not str or not value.strip():
        errors.append(f"{label}: must be a non-empty string")
    elif len(value) > MAX_ID_LEN:
        errors.append(f"{label}: longer than {MAX_ID_LEN} characters")
    elif _has_control_chars(value):
        errors.append(f"{label}: contains control characters")
    else:
        return value
    return None


def _check_name(value, label: str, errors: list[str]) -> str | None:
    """A file name must be a plain single name. Rejected, never repaired."""
    if type(value) is not str or not value:
        errors.append(f"{label}: must be a non-empty string")
    elif len(value) > MAX_NAME_LEN:
        errors.append(f"{label}: longer than {MAX_NAME_LEN} characters")
    elif _has_control_chars(value) or any(c in _NAME_FORBIDDEN for c in value):
        errors.append(f"{label}: must not contain path separators, control characters or any of : < > \" | ? *")
    elif value in (".", "..") or value != value.rstrip(" ."):
        errors.append(f"{label}: must not be '.' or '..' or end with a space or dot")
    elif value.split(".")[0].upper() in _WINDOWS_DEVICE_NAMES:
        errors.append(f"{label}: is a reserved device name")
    else:
        return value
    return None


def _read_path_entry(rel: str, label: str, settings: Settings, errors: list[str]) -> bytes | None:
    """Read a file by ``path``, only from inside the configured staging root."""
    if settings.staging_root is None:
        errors.append(f"{label}: 'path' entries are disabled on this listener (no staging root configured); send content_b64")
        return None
    if not rel or len(rel) > MAX_PATH_LEN or "\x00" in rel:
        errors.append(f"{label}: invalid path")
        return None
    # Absolute in EITHER OS flavour (drive letters, UNC, leading slash) or any '..' part: reject.
    parts = set(PurePosixPath(rel).parts) | set(PureWindowsPath(rel).parts)
    if (PurePosixPath(rel).is_absolute() or PureWindowsPath(rel).anchor
            or rel.startswith(("/", "\\")) or ".." in parts):
        errors.append(f"{label}: path must be relative to the staging root and contain no '..'")
        return None
    root = settings.staging_root.resolve()
    try:
        candidate = (root / rel).resolve(strict=True)
    except (OSError, RuntimeError):
        errors.append(f"{label}: file not found under the staging root")
        return None
    if not candidate.is_relative_to(root) or not candidate.is_file():
        errors.append(f"{label}: path does not resolve to a file inside the staging root")
        return None
    try:
        with open(candidate, "rb") as handle:
            data = handle.read(settings.max_file_bytes + 1)
    except OSError:
        errors.append(f"{label}: file could not be read")
        return None
    return data


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_bundle(obj, settings: Settings) -> ValidBundle:
    """Validate a parsed payload. Raises BundleError listing every problem found
    (up to a cap). Reads/decodes file bytes and checks declared hashes, but
    writes nothing and seals nothing."""
    errors: list[str] = []
    if type(obj) is not dict:
        raise BundleError(["top level must be a JSON object"])

    allowed = set(TOP_REQUIRED) | set(TOP_OPTIONAL)
    for key in sorted(set(obj) - allowed):
        errors.append(f"unknown field {key[:60]!r}")
    for key in TOP_REQUIRED:
        if key not in obj:
            errors.append(f"missing required field {key!r}")

    if "format_version" in obj and obj["format_version"] != FORMAT_VERSION:
        errors.append(f"format_version: must be {FORMAT_VERSION!r}")

    fields: dict = {}
    for key in ID_FIELDS:
        if key in obj:
            value = _check_id(obj[key], key, errors)
            if value is not None:
                fields[key] = value
    for key in ("alert_timestamp", "captured_at"):
        if key in obj:
            value = _parse_utc(obj[key], key, errors)
            if value is not None:
                fields[key] = value

    files_value = obj.get("files")
    staged: list[StagedFile] = []
    if "files" in obj:
        if type(files_value) is not list:
            errors.append("files: must be a list")
        elif not files_value:
            errors.append("files: must contain at least one file")
        elif len(files_value) > settings.max_files:
            errors.append(f"files: more than the {settings.max_files} files allowed per bundle")
        else:
            total = 0
            for index, entry in enumerate(files_value):
                staged_file = _validate_file(entry, f"files[{index}]", settings, errors)
                if staged_file is not None:
                    total += len(staged_file.data)
                    staged.append(staged_file)
            if total > settings.max_total_bytes:
                errors.append(f"files: combined size is over the {settings.max_total_bytes} byte limit")

    if errors:
        raise BundleError(errors)
    return ValidBundle(fields=fields, files=staged)


def _validate_file(entry, label: str, settings: Settings, errors: list[str]) -> StagedFile | None:
    start = len(errors)
    if type(entry) is not dict:
        errors.append(f"{label}: must be an object")
        return None
    for key in sorted(set(entry) - FILE_ALLOWED):
        errors.append(f"{label}: unknown field {key[:60]!r}")

    name = _check_name(entry.get("name"), f"{label}.name", errors) if "name" in entry else None
    if "name" not in entry:
        errors.append(f"{label}: missing required field 'name'")

    kind = entry.get("kind")
    if "kind" not in entry:
        errors.append(f"{label}: missing required field 'kind'")
    elif type(kind) is not str or kind not in KINDS:
        errors.append(f"{label}.kind: must be one of {sorted(KINDS)}")
        kind = None

    base_year = None
    if "base_year" in entry:
        value = entry["base_year"]
        if type(value) is not int or not MIN_BASE_YEAR <= value <= MAX_BASE_YEAR:
            errors.append(f"{label}.base_year: must be an integer between {MIN_BASE_YEAR} and {MAX_BASE_YEAR}")
        elif kind != "auth_log":
            errors.append(f"{label}.base_year: only allowed when kind is 'auth_log'")
        else:
            base_year = value

    declared = None
    if "sha256" in entry:
        if type(entry["sha256"]) is not str or not _SHA256_RE.fullmatch(entry["sha256"]):
            errors.append(f"{label}.sha256: must be 64 lowercase hex characters")
        else:
            declared = entry["sha256"]

    has_path, has_inline = "path" in entry, "content_b64" in entry
    if has_path == has_inline:
        errors.append(f"{label}: provide exactly one of 'path' or 'content_b64'")
        return None

    data = None
    if has_inline:
        text = entry["content_b64"]
        if type(text) is not str:
            errors.append(f"{label}.content_b64: must be a string")
        elif len(text) // 4 * 3 > settings.max_file_bytes + 3:
            errors.append(f"{label}.content_b64: file is over the {settings.max_file_bytes} byte limit")
        else:
            try:
                data = base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError):
                errors.append(f"{label}.content_b64: not valid base64")
    else:
        if type(entry["path"]) is not str:
            errors.append(f"{label}.path: must be a string")
        else:
            data = _read_path_entry(entry["path"], f"{label}.path", settings, errors)

    if data is not None and len(data) > settings.max_file_bytes:
        errors.append(f"{label}: file is over the {settings.max_file_bytes} byte limit")
        data = None

    if len(errors) > start or name is None or kind is None or data is None:
        return None
    digest = hashlib.sha256(data).hexdigest()
    if declared is not None and digest != declared:
        errors.append(f"{label}.sha256: does not match the file's content")
        return None
    return StagedFile(name=name, kind=kind, data=data, sha256=digest, base_year=base_year)


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------
def _metadata_for(bundle: ValidBundle, item: StagedFile) -> dict:
    """The dict handed to seal_evidence(); see docs/bundle-format.md section 4."""
    f = bundle.fields
    metadata = {
        "source": f["source_system"],
        "collector": f["collector"],
        "captured_at": f["captured_at"],
        "bundle_id": f["bundle_id"],
        "alert_type": f["alert_type"],
        "alert_timestamp": f["alert_timestamp"],
        "kind": item.kind,
        "declared_name": item.name,
    }
    if "alert_id" in f:
        metadata["alert_id"] = f["alert_id"]
    if item.base_year is not None:
        metadata["base_year"] = item.base_year
    return metadata


def seal_bundle(bundle: ValidBundle, settings: Settings) -> list[dict]:
    """Stage each file under its validated name and seal it. Returns one result
    per file: sealed, re_intake or failed. One failing file never stops the
    others (seal_evidence commits per call, so a bundle is not atomic)."""
    results: list[dict] = []
    with connect_database(settings.db_path) as conn, \
            tempfile.TemporaryDirectory(prefix="stamped-capture-") as work:
        work_dir = Path(work).resolve()
        for index, item in enumerate(bundle.files):
            result = {"name": item.name, "kind": item.kind, "status": "failed", "evidence_id": None}
            results.append(result)
            try:
                folder = work_dir / str(index)
                folder.mkdir()
                staged = folder / item.name
                if staged.resolve().parent != folder.resolve():  # belt and braces
                    raise IntakeError("staged file would fall outside its folder")
                staged.write_bytes(item.data)
                evidence_id = seal_evidence(
                    conn, staged, metadata=_metadata_for(bundle, item),
                    actor=ACTOR, role=ROLE, sealed_dir=settings.sealed_dir,
                )
                action = conn.execute(
                    "SELECT action FROM custody_log WHERE evidence_id = ? "
                    "ORDER BY entry_id DESC LIMIT 1", (evidence_id,)
                ).fetchone()
                result["evidence_id"] = evidence_id
                result["status"] = "re_intake" if action and action[0] == "re_intake" else "sealed"
            except Exception as exc:  # noqa: BLE001 - reported per file, never swallowed
                # IntakeError is the expected case; anything else (disk, SQLite) is
                # also reported against this file so earlier files' results survive.
                # Details go to the server log only; they may contain server paths.
                log.error("sealing %r failed: %s: %s", item.name, type(exc).__name__, exc)
    return results


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def create_app(settings: Settings | None = None, *, host: str = "127.0.0.1") -> Flask:
    settings = settings or Settings()
    if not _is_loopback_host(host) and not settings.auth_secret:
        raise ValueError("Non-loopback capture listeners require STAMPED_CAPTURE_HMAC_SECRET.")
    if settings.auth_secret is not None and len(settings.auth_secret) < 32:
        raise ValueError("STAMPED_CAPTURE_HMAC_SECRET must contain at least 32 bytes.")
    if settings.max_requests_per_minute < 1:
        raise ValueError("max_requests_per_minute must be positive.")
    if settings.max_replay_cache_entries < 1:
        raise ValueError("max_replay_cache_entries must be positive.")

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes
    app.config["STAMPED_SETTINGS"] = settings
    rejection_counts = {"rate_limited": 0, "authentication": 0}
    request_times: OrderedDict[str, deque[float]] = OrderedDict()
    seen_nonces: OrderedDict[str, float] = OrderedDict()
    state_lock = threading.Lock()
    app.extensions["stamped_listener_rejections"] = rejection_counts

    def reject(reason: str, status: int, code: str):
        with state_lock:
            rejection_counts[reason] += 1
        log.warning("capture request rejected: %s", code)
        return error(status, code)

    def error(status: int, code: str, details: list[str] | None = None):
        body: dict[str, str | list[str]] = {"error": code}
        if details:
            body["details"] = details
        return jsonify(body), status

    @app.post("/alert")
    def alert():
        now = time.monotonic()
        source = request.remote_addr or "unknown"
        with state_lock:
            attempts = request_times.pop(source, deque())
            while attempts and now - attempts[0] >= 60:
                attempts.popleft()
            limited = len(attempts) >= settings.max_requests_per_minute
            if not limited:
                attempts.append(now)
            request_times[source] = attempts
            while len(request_times) > 4096:
                request_times.popitem(last=False)
        if limited:
            return reject("rate_limited", 429, "rate_limited")

        raw = request.get_data(cache=False)  # raises 413 past MAX_CONTENT_LENGTH

        if settings.auth_secret is not None:
            timestamp = request.headers.get("X-Stamped-Timestamp")
            nonce = request.headers.get("X-Stamped-Nonce")
            signature = request.headers.get("X-Stamped-Signature")
            if not valid_request_signature(
                settings.auth_secret, timestamp, nonce, signature, raw
            ):
                return reject("authentication", 401, "unauthorized")
            if nonce is None:
                return reject("authentication", 401, "unauthorized")
            with state_lock:
                replayed = nonce in seen_nonces
                if not replayed:
                    seen_nonces[nonce] = time.monotonic()
                    while len(seen_nonces) > settings.max_replay_cache_entries:
                        seen_nonces.popitem(last=False)
            if replayed:
                return reject("authentication", 401, "replayed_request")

        if request.mimetype != "application/json":
            return error(415, "unsupported_media_type", ["Content-Type must be application/json"])
        try:
            bundle = validate_bundle(parse_json(raw), settings)
        except BundleError as exc:
            return error(400, "invalid_bundle", exc.errors)

        try:
            results = seal_bundle(bundle, settings)
        except DatabaseError as exc:
            log.error("evidence database unavailable: %s", exc)
            return error(503, "evidence_database_unavailable")

        ok = [r for r in results if r["status"] != "failed"]
        body = {"bundle_id": bundle.fields["bundle_id"], "files": results}
        if len(ok) == len(results):
            body["status"] = "sealed"
            return jsonify(body), 201
        if ok:
            body["status"] = "partial"
            return jsonify(body), 207
        body["status"] = "failed"
        return jsonify(body), 500

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        codes = {404: "not_found", 405: "method_not_allowed", 413: "payload_too_large"}
        status = exc.code or 500
        details = [f"limit is {settings.max_body_bytes} bytes"] if status == 413 else None
        return error(status, codes.get(status, "http_error"), details)

    @app.errorhandler(Exception)
    def unexpected(exc: Exception):
        log.exception("unhandled error in capture listener")  # traceback to the server log only
        return error(500, "internal_error")

    return app


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Loopback demo listener or HMAC-authenticated non-loopback capture listener.")
    parser.add_argument("--host", default="127.0.0.1", help="default: 127.0.0.1 (loopback only)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--db", type=Path, default=None, help="default: STAMPED_DB_PATH or data/stamped.db")
    parser.add_argument("--sealed-dir", type=Path, default=DEFAULT_SEALED_DIR)
    parser.add_argument("--staging-root", type=Path, default=None,
                        help="folder `path` entries are read from; omit to accept inline content only")
    return parser.parse_args(argv)


def create_app_from_env() -> Flask:
    host = os.environ.get("STAMPED_CAPTURE_HOST", "127.0.0.1")
    secret = os.environ.get("STAMPED_CAPTURE_HMAC_SECRET")
    return create_app(
        Settings(
            db_path=Path(os.environ["STAMPED_CAPTURE_DB_PATH"])
            if os.environ.get("STAMPED_CAPTURE_DB_PATH") else None,
            sealed_dir=Path(os.environ.get("STAMPED_CAPTURE_SEALED_DIR", DEFAULT_SEALED_DIR)),
            staging_root=Path(os.environ["STAMPED_CAPTURE_STAGING_ROOT"])
            if os.environ.get("STAMPED_CAPTURE_STAGING_ROOT") else None,
            auth_secret=secret.encode("utf-8") if secret else None,
        ),
        host=host,
    )


def main(argv=None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.staging_root is not None and not args.staging_root.is_dir():
        print(f"--staging-root {args.staging_root} is not a directory", file=sys.stderr)
        return 2
    secret = os.environ.get("STAMPED_CAPTURE_HMAC_SECRET")
    settings = Settings(
        db_path=args.db,
        sealed_dir=args.sealed_dir,
        staging_root=args.staging_root,
        auth_secret=secret.encode("utf-8") if secret else None,
    )
    try:
        app = create_app(settings, host=args.host)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        with connect_database(settings.db_path):
            pass
    except DatabaseError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    if _is_loopback_host(args.host):
        app.run(host=args.host, port=args.port, threaded=True)
    else:
        if sys.platform == "win32":
            print("Non-loopback capture listeners require a supported Unix host and Gunicorn.", file=sys.stderr)
            return 2
        try:
            from gunicorn.app.wsgiapp import run as gunicorn_run
        except ImportError:
            print("Gunicorn is required for a non-loopback capture listener.", file=sys.stderr)
            return 2
        os.environ["STAMPED_CAPTURE_HOST"] = args.host
        if args.db is not None:
            os.environ["STAMPED_CAPTURE_DB_PATH"] = str(args.db)
        os.environ["STAMPED_CAPTURE_SEALED_DIR"] = str(args.sealed_dir)
        if args.staging_root is not None:
            os.environ["STAMPED_CAPTURE_STAGING_ROOT"] = str(args.staging_root)
        sys.argv = [
            "gunicorn",
            "--bind",
            f"{args.host}:{args.port}",
            "capture.listener:create_app_from_env()",
        ]
        gunicorn_run()
    return 0


if __name__ == "__main__":
    sys.exit(main())