"""
PSEUDONYMS
  A pseudonym is HMAC-SHA256(secret key, kind + value), shortened: 'acct-3fa91c2d7b',
  'ip-9c01e47a22'. The same account (or address) always gets the same token, so a
  prosecutor can still follow "acct-3fa9... failed 12 logins, then acct-3fa9... moved
  500 MB". Without the key the token cannot be reversed or checked against a guessed
  value. The key is REQUIRED: there is deliberately no fallback to an unkeyed hash,
  because there are only about four billion IPv4 addresses and an unkeyed hash of
  one can be reversed by trying them all.

  Pseudonymised is not anonymous. Anyone holding the key (the examiner) can re-link
  tokens to people. That is the point: the data stays usable inside the case, and a
  restricted role does not receive the identifiers.

PROJECTION (default deny)
  project_records() rebuilds each record from the policy. For a role other than the
  examiner it copies ONLY fields the policy lists, so anything unexpected (a new
  column, a new key inside details_json, a nested object) is dropped rather than shown.

FREE TEXT (titles, descriptions, summaries)
  Rules write sentences such as "Impossible travel for account bob ... from 1.2.3.4".
  For a pseudonymising role: (1) every identifier found in the structured fields of
  the same result is replaced by its token; (2) afterwards ANY IP address left in the
  text is replaced as well. If an identifier is too short or common to replace safely
  inside a sentence (for example an account called "1" or "for") the whole sentence is
  withheld instead of being garbled or leaked. Over-masking is the safe failure.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import os
import re
from pathlib import Path

from access.roles import DATASETS, AccessError, H, ListOf, P, Role, Rule, Vis

PREFIX = {"account": "acct", "ip": "ip", "ident": "id"}
WITHHELD_TEXT = ("[text withheld for this role: it contains an identifier that cannot be masked safely "
                 "inside a sentence; see the structured fields]")
_AMBIGUOUS_WORDS = frozenset({
    "for", "the", "and", "from", "with", "after", "before", "account", "user", "login", "logins", "failed",
    "success", "failure", "high", "medium", "low", "info", "rule", "events", "event", "unknown", "none",
    "null", "true", "false", "data", "large", "access", "travel", "impossible", "followed", "baseline",
})
_DROP = object()


class PseudonymizerRequired(AccessError):
    """A role that gets pseudonyms was asked for data, but no secret key was supplied."""


class Pseudonymizer:
    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise ValueError("The pseudonym key must be at least 16 bytes of secret random data.")
        self._key = bytes(key)

    @staticmethod
    def generate_key_file(path) -> Path:
        """Create a new random key file readable only by the owner. Refuses to overwrite."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(os.urandom(32))
        return path

    @classmethod
    def from_key_file(cls, path) -> "Pseudonymizer":
        return cls(Path(path).read_bytes())

    def token(self, kind: str, value) -> str:
        text = str(value)
        if kind == "ip":
            try:
                text = str(ipaddress.ip_address(text.strip()))      # 1.2.3.4 and ::ffff:1.2.3.4 style spellings agree
            except ValueError:
                pass
        prefix = PREFIX.get(kind, "id")
        digest = hmac.new(self._key, f"{prefix}\x00{text}".encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{prefix}-{digest[:10]}"


class ProjectionContext:
    """State for ONE result set: the role, the key, and every identifier seen so far."""

    def __init__(self, role: Role, pseudonymizer: Pseudonymizer | None):
        self.role = role
        self.pz = pseudonymizer
        self.registry: dict[str, str] = {}
        self.pending: list[tuple[object, object, str]] = []

    def pseudonym(self, kind: str, value) -> str:
        if self.pz is None:
            raise PseudonymizerRequired(
                f"Role '{self.role.value}' receives pseudonyms; pass a Pseudonymizer (see access/masking.py).")
        raw = str(value)
        token = self.pz.token(kind, raw)
        self.registry[raw] = token
        return token

    def finish(self) -> None:
        """Scrub free text last, when every identifier in the whole result is known."""
        for container, key, text in self.pending:
            container[key] = scrub_text(text, self)
        self.pending.clear()


def _is_ambiguous(raw: str) -> bool:
    return len(raw) < 3 or raw.isdigit() or raw.lower() in _AMBIGUOUS_WORDS


_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")


def scrub_text(text, ctx: ProjectionContext) -> str:
    text = text if isinstance(text, str) else str(text)
    if ctx.registry:
        ordered = sorted(ctx.registry, key=len, reverse=True)
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(r) for r in ordered) + r")(?![A-Za-z0-9_]|\.[A-Za-z0-9])")
        if any(_is_ambiguous(m.group(0)) for m in pattern.finditer(text)):
            return WITHHELD_TEXT
        text = pattern.sub(lambda m: ctx.registry[m.group(0)], text)

    def ip_sub(match):
        try:
            ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)                      # not an address (e.g. a clock time such as 12:30:45)
        return ctx.pseudonym("ip", match.group(0))

    return _IPV6.sub(ip_sub, _IPV4.sub(ip_sub, text))


def _store(container, key, result, ctx: ProjectionContext) -> None:
    if isinstance(result, _PendingText):
        container[key] = None
        ctx.pending.append((container, key, result.text))
    else:
        container[key] = result


class _PendingText:
    def __init__(self, text):
        self.text = text


_SCALARS = (str, int, float, bool, type(None))


def _project_leaf(value, rule: Rule, ctx: ProjectionContext, parent: dict):
    vis = rule.vis(ctx.role)
    if vis is H:
        return _DROP
    if isinstance(value, (dict, list)):
        # A leaf rule describes ONE value. A nested value turning up where a plain value was
        # expected is not shown to a restricted role unless the rule says nesting is fine.
        return copy.deepcopy(value) if (ctx.role is Role.EXAMINER or (rule.container_ok and vis is Vis.FULL)) else _DROP
    if vis is Vis.FULL or value is None:
        return value
    kind = rule.kind
    if kind == "by_grouped_by":
        kind = {"account": "account", "source_ip": "ip"}.get((parent or {}).get("grouped_by"), "ident")
    if kind == "text":
        return _PendingText(value)
    return ctx.pseudonym(kind or "ident", value)


def _project(value, spec, ctx: ProjectionContext, parent: dict | None):
    if isinstance(spec, Rule):
        return _project_leaf(value, spec, ctx, parent)
    if isinstance(spec, ListOf):
        if not isinstance(value, list):
            return _DROP
        inner = spec.resolve()
        out: list = []
        for item in value:
            result = _project(item, inner, ctx, None)
            if result is _DROP:
                continue
            out.append(None)
            _store(out, len(out) - 1, result, ctx)
        return out
    if isinstance(spec, dict):
        if not isinstance(value, dict):
            return _DROP
        out_obj: dict = {}
        for key, inner_value in value.items():
            if key in spec:
                result = _project(inner_value, spec[key], ctx, value)
            elif ctx.role is Role.EXAMINER:
                result = copy.deepcopy(inner_value)       # the examiner sees everything, including unknown keys
            else:
                continue                                  # DEFAULT DENY for every other role
            if result is not _DROP:
                _store(out_obj, key, result, ctx)
        return out_obj
    raise TypeError(f"bad policy spec: {type(spec).__name__}")


def project_records(records, spec, role: Role, pseudonymizer: Pseudonymizer | None = None) -> list[dict]:
    """Rebuild every record from the policy. `spec` is a dict, or a function record -> dict (the timeline
    needs a different details spec per entry type). Free text is scrubbed once, at the end, with the
    identifiers from the WHOLE result in hand."""
    ctx = ProjectionContext(role, pseudonymizer)
    if pseudonymizer is None and role_pseudonymizes(role):
        raise PseudonymizerRequired(
            f"Role '{role.value}' receives pseudonyms; pass a Pseudonymizer (see access/masking.py).")
    out = []
    for record in records:
        record_spec = spec(record) if callable(spec) else spec
        projected = _project(record, record_spec, ctx, None)
        if projected is not _DROP:
            out.append(projected)
    ctx.finish()
    return out


def role_pseudonymizes(role: Role) -> bool:
    """True if any field in any dataset is pseudonymised for this role (i.e. a key is required)."""
    return any(r.vis(role) is P for ds in DATASETS.values() for r in _rules(ds))


def _rules(spec, _seen=frozenset()):
    if isinstance(spec, Rule):
        yield spec
    elif isinstance(spec, ListOf):
        yield from _rules(spec.resolve(), _seen)
    elif isinstance(spec, dict) and id(spec) not in _seen:
        for inner in spec.values():
            yield from _rules(inner, _seen | {id(spec)})