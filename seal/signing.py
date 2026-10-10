import base64
import json
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import oqs  # real liboqs binding; ImportError/RuntimeError here is intentional

MLDSA_ALGORITHM = "ML-DSA-65"
DEFAULT_KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"

_ED25519_PRIV_FILE = "ed25519_private.bin"
_MLDSA_PRIV_FILE = "mldsa65_private.bin"
_ED25519_PUB_FILE = "ed25519_public.bin"
_MLDSA_PUB_FILE = "mldsa65_public.bin"
_PUB_MANIFEST = "public_keys.json"


class KeyManagementError(Exception):
    """Raised for key-file problems. Messages never contain key material."""


# ---------------------------------------------------------------------------
# Key generation / storage
# ---------------------------------------------------------------------------
def generate_keypairs() -> dict:
    """
    Generate a fresh Ed25519 keypair and a fresh ML-DSA-65 keypair.

    Returns raw bytes:
      {"ed25519_private", "ed25519_public", "mldsa_private", "mldsa_public"}
    Ed25519 keys are the 32-byte raw encodings. ML-DSA keys are liboqs' raw
    encodings.
    """
    ed_priv = Ed25519PrivateKey.generate()
    ed_priv_raw = ed_priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    ed_pub_raw = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    with oqs.Signature(MLDSA_ALGORITHM) as signer:
        mldsa_pub = signer.generate_keypair()
        mldsa_priv = signer.export_secret_key()

    return {
        "ed25519_private": ed_priv_raw,
        "ed25519_public": ed_pub_raw,
        "mldsa_private": mldsa_priv,
        "mldsa_public": mldsa_pub,
    }


def _write_private(path: Path, data: bytes) -> None:
    # Create with 0600 from the start so the key is never briefly world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def create_case_keys(case_id: str, keys_dir: Path = DEFAULT_KEYS_DIR) -> Path:
    """
    Generate and store a keypair set for a case. Refuses to overwrite
    existing keys (overwriting a signing key would orphan every signature
    made with the old one). Returns the case key directory.
    """
    _validate_case_id(case_id)
    case_dir = Path(keys_dir) / case_id
    if (case_dir / _ED25519_PRIV_FILE).exists() or (case_dir / _MLDSA_PRIV_FILE).exists():
        raise KeyManagementError(f"Keys already exist for case '{case_id}'; refusing to overwrite.")

    case_dir.mkdir(parents=True, exist_ok=True)
    case_dir.chmod(0o700)  # owner-only; a failure here should surface, not be swallowed

    keys = generate_keypairs()
    _write_private(case_dir / _ED25519_PRIV_FILE, keys["ed25519_private"])
    _write_private(case_dir / _MLDSA_PRIV_FILE, keys["mldsa_private"])
    export_public_keys(case_id, keys["ed25519_public"], keys["mldsa_public"], keys_dir)
    return case_dir


def export_public_keys(
        case_id: str,
        ed25519_public: bytes,
        mldsa_public: bytes,
        keys_dir: Path = DEFAULT_KEYS_DIR,
) -> Path:
    """
    Write public keys plus a small JSON manifest to keys/<case_id>/public/.
    Everything in this folder is safe to share; the independent verifier
    needs only this folder, not the application.
    """
    _validate_case_id(case_id)
    pub_dir = Path(keys_dir) / case_id / "public"
    pub_dir.mkdir(parents=True, exist_ok=True)
    (pub_dir / _ED25519_PUB_FILE).write_bytes(ed25519_public)
    (pub_dir / _MLDSA_PUB_FILE).write_bytes(mldsa_public)
    manifest = {
        "case_id": case_id,
        "ed25519": {"file": _ED25519_PUB_FILE, "encoding": "raw-32-bytes"},
        "ml_dsa": {"algorithm": MLDSA_ALGORITHM, "file": _MLDSA_PUB_FILE},
        "public_key_b64": {
            "ed25519": base64.b64encode(ed25519_public).decode("ascii"),
            "ml_dsa": base64.b64encode(mldsa_public).decode("ascii"),
        },
        "rule": "A record is valid only if BOTH signatures verify.",
    }
    (pub_dir / _PUB_MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return pub_dir


def load_private_keys(case_id: str, keys_dir: Path = DEFAULT_KEYS_DIR) -> tuple[bytes, bytes]:
    """Return (ed25519_private, mldsa_private) raw bytes for a case."""
    _validate_case_id(case_id)
    case_dir = Path(keys_dir) / case_id
    try:
        return (
            (case_dir / _ED25519_PRIV_FILE).read_bytes(),
            (case_dir / _MLDSA_PRIV_FILE).read_bytes(),
        )
    except OSError as e:
        # Report which case, never the contents.
        raise KeyManagementError(f"Cannot read private keys for case '{case_id}': {type(e).__name__}") from e


def load_public_keys(public_dir: Path) -> tuple[bytes, bytes]:
    """Return (ed25519_public, mldsa_public) from an exported public/ folder."""
    public_dir = Path(public_dir)
    try:
        return (
            (public_dir / _ED25519_PUB_FILE).read_bytes(),
            (public_dir / _MLDSA_PUB_FILE).read_bytes(),
        )
    except OSError as e:
        raise KeyManagementError(f"Cannot read public keys from '{public_dir}': {type(e).__name__}") from e


def _validate_case_id(case_id: str) -> None:
    # case_id becomes a directory name: block path traversal and odd characters.
    if not case_id or not all(c.isalnum() or c in "-_" for c in case_id):
        raise KeyManagementError("case_id must be non-empty and contain only letters, digits, '-' or '_'.")


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------
def sign_hybrid(
        data: bytes, ed25519_privkey: bytes, mldsa_privkey: bytes
) -> tuple[bytes, bytes]:
    """
    Sign `data` with both algorithms. Returns (sig_classical, sig_pq).
    `data` must be bytes: the caller chooses the canonical message; this
    function signs exactly those bytes and nothing else.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("sign_hybrid requires bytes; serialise canonically first.")
    data = bytes(data)

    sig_classical = Ed25519PrivateKey.from_private_bytes(ed25519_privkey).sign(data)

    with oqs.Signature(MLDSA_ALGORITHM, secret_key=mldsa_privkey) as signer:
        sig_pq = signer.sign(data)

    return sig_classical, sig_pq


def _verify_ed25519(data: bytes, sig: bytes, pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _verify_mldsa(data: bytes, sig: bytes, pub: bytes) -> bool:
    try:
        with oqs.Signature(MLDSA_ALGORITHM) as verifier:
            return bool(verifier.verify(data, sig, pub))
    except Exception:  # malformed sig/key must mean "invalid", never a crash
        return False


def verify_hybrid(
        data: bytes,
        sig_classical: bytes,
        sig_pq: bytes,
        ed25519_pubkey: bytes,
        mldsa_pubkey: bytes,
) -> bool:
    """
    True ONLY if BOTH signatures verify over `data`. Returns False (never
    raises, never returns None) if either is invalid, missing, malformed,
    or made with a different key.
    """
    if not isinstance(data, (bytes, bytearray)):
        return False
    data = bytes(data)

    # Both checks always run (no short-circuit) so timing/behaviour does not
    # reveal which half failed, and `and` — not `or` — combines them.
    classical_ok = _verify_ed25519(data, sig_classical, ed25519_pubkey)
    pq_ok = _verify_mldsa(data, sig_pq, mldsa_pubkey)
    return classical_ok and pq_ok