"""HMAC request authentication helpers for non-loopback capture deployments."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time

NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z", re.ASCII)
SIGNATURE_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


def request_signature(secret: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    message = timestamp.encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n" + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def signed_headers(secret: bytes, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    signature = request_signature(secret, timestamp, nonce, body)
    return {
        "X-Stamped-Timestamp": timestamp,
        "X-Stamped-Nonce": nonce,
        "X-Stamped-Signature": signature,
    }


def valid_request_signature(
    secret: bytes,
    timestamp: str | None,
    nonce: str | None,
    signature: str | None,
    body: bytes,
    *,
    now: float | None = None,
) -> bool:
    if (
        not isinstance(timestamp, str)
        or not timestamp.isascii()
        or not timestamp.isdecimal()
        or len(timestamp) > 12
        or not isinstance(nonce, str)
        or not NONCE_RE.fullmatch(nonce)
        or not isinstance(signature, str)
        or not SIGNATURE_RE.fullmatch(signature)
    ):
        return False
    current_time = time.time() if now is None else now
    if abs(current_time - int(timestamp)) > 300:
        return False
    expected = request_signature(secret, timestamp, nonce, body)
    return hmac.compare_digest(expected, signature)
