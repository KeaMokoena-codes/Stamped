import json
import stat
import sys

import pytest

try:
    from seal import signing
except Exception as exc:  # ImportError, or liboqs' RuntimeError on a failed native build
    pytest.skip(f"liboqs unavailable, ML-DSA not tested here: {type(exc).__name__}", allow_module_level=True)

MESSAGE = b"entry_hash:9f2c...canonical-bytes-of-a-custody-checkpoint"


@pytest.fixture(scope="module")
def keys():
    return signing.generate_keypairs()


@pytest.fixture
def signed(keys):
    sig_c, sig_pq = signing.sign_hybrid(MESSAGE, keys["ed25519_private"], keys["mldsa_private"])
    return sig_c, sig_pq


def _verify(keys, data, sig_c, sig_pq):
    return signing.verify_hybrid(data, sig_c, sig_pq, keys["ed25519_public"], keys["mldsa_public"])


# --- happy path -------------------------------------------------------------
def test_valid_hybrid_signature_verifies(keys, signed):
    assert _verify(keys, MESSAGE, *signed) is True


def test_signatures_are_real_and_correctly_sized(signed):
    sig_c, sig_pq = signed
    assert len(sig_c) == 64          # Ed25519 signatures are always 64 bytes
    assert len(sig_pq) > 3000        # ML-DSA-65 signatures are ~3.3 KB; a stub would be tiny


# --- DoD: tampering with signed data causes BOTH checks to fail --------------
def test_tampered_data_fails_both_individual_checks(keys, signed):
    sig_c, sig_pq = signed
    tampered = MESSAGE + b"x"
    assert signing._verify_ed25519(tampered, sig_c, keys["ed25519_public"]) is False
    assert signing._verify_mldsa(tampered, sig_pq, keys["mldsa_public"]) is False
    assert _verify(keys, tampered, sig_c, sig_pq) is False


def test_single_flipped_bit_in_data_is_rejected(keys, signed):
    flipped = bytearray(MESSAGE)
    flipped[0] ^= 0x01
    assert _verify(keys, bytes(flipped), *signed) is False


# --- DoD: partial forgery (only ONE valid signature) is rejected -------------
def test_valid_classical_but_forged_pq_is_rejected(keys, signed):
    sig_c, sig_pq = signed
    forged_pq = bytes(len(sig_pq))  # all zeros: right length, not a real signature
    assert signing._verify_ed25519(MESSAGE, sig_c, keys["ed25519_public"]) is True  # half is genuinely valid
    assert _verify(keys, MESSAGE, sig_c, forged_pq) is False


def test_valid_pq_but_forged_classical_is_rejected(keys, signed):
    sig_c, sig_pq = signed
    forged_c = bytes(64)
    assert signing._verify_mldsa(MESSAGE, sig_pq, keys["mldsa_public"]) is True  # half is genuinely valid
    assert _verify(keys, MESSAGE, forged_c, sig_pq) is False


def test_signatures_from_a_different_keypair_are_rejected(keys):
    other = signing.generate_keypairs()
    sig_c, sig_pq = signing.sign_hybrid(MESSAGE, other["ed25519_private"], other["mldsa_private"])
    assert _verify(keys, MESSAGE, sig_c, sig_pq) is False


def test_classical_from_other_key_with_pq_from_right_key_is_rejected(keys, signed):
    other = signing.generate_keypairs()
    other_c, _ = signing.sign_hybrid(MESSAGE, other["ed25519_private"], other["mldsa_private"])
    _, good_pq = signed
    assert _verify(keys, MESSAGE, other_c, good_pq) is False


# --- DoD: returns False, never raises, never None ----------------------------
@pytest.mark.parametrize("bad_sig", [b"", b"short", None, 12345])
def test_malformed_signatures_return_false_not_exception(keys, signed, bad_sig):
    sig_c, sig_pq = signed
    for result in (_verify(keys, MESSAGE, bad_sig, sig_pq), _verify(keys, MESSAGE, sig_c, bad_sig)):
        assert result is False


@pytest.mark.parametrize("bad_pub", [b"", b"short", None])
def test_malformed_public_keys_return_false_not_exception(keys, signed, bad_pub):
    sig_c, sig_pq = signed
    assert signing.verify_hybrid(MESSAGE, sig_c, sig_pq, bad_pub, keys["mldsa_public"]) is False
    assert signing.verify_hybrid(MESSAGE, sig_c, sig_pq, keys["ed25519_public"], bad_pub) is False


def test_non_bytes_message_returns_false_for_verify_and_raises_for_sign(keys, signed):
    assert _verify(keys, "a string, not bytes", *signed) is False
    with pytest.raises(TypeError):
        signing.sign_hybrid("a string", keys["ed25519_private"], keys["mldsa_private"])


def test_signing_is_over_exact_bytes_not_a_string_repr(keys):
    sig_c, sig_pq = signing.sign_hybrid(MESSAGE, keys["ed25519_private"], keys["mldsa_private"])
    assert _verify(keys, str(MESSAGE).encode(), sig_c, sig_pq) is False  # str(bytes) != the bytes


# --- DoD: key storage / export ------------------------------------------------
def test_create_case_keys_writes_private_keys_owner_only(tmp_path):
    case_dir = signing.create_case_keys("case_001", keys_dir=tmp_path)
    for name in ("ed25519_private.bin", "mldsa65_private.bin"):
        mode = stat.S_IMODE((case_dir / name).stat().st_mode)
        if sys.platform != "win32":
            assert mode == 0o600


def test_create_case_keys_refuses_to_overwrite_existing_keys(tmp_path):
    signing.create_case_keys("case_001", keys_dir=tmp_path)
    with pytest.raises(signing.KeyManagementError):
        signing.create_case_keys("case_001", keys_dir=tmp_path)


@pytest.mark.parametrize("bad_id", ["", "../escape", "a/b", "a b", "case;rm"])
def test_case_id_cannot_traverse_paths(tmp_path, bad_id):
    with pytest.raises(signing.KeyManagementError):
        signing.create_case_keys(bad_id, keys_dir=tmp_path)


def test_public_keys_export_contains_no_private_material(tmp_path):
    case_dir = signing.create_case_keys("case_002", keys_dir=tmp_path)
    ed_priv, mldsa_priv = signing.load_private_keys("case_002", keys_dir=tmp_path)
    for f in (case_dir / "public").iterdir():
        blob = f.read_bytes()
        assert ed_priv not in blob
        assert mldsa_priv not in blob


def test_independent_verifier_flow_needs_only_the_public_folder(tmp_path):
    case_dir = signing.create_case_keys("case_003", keys_dir=tmp_path)
    ed_priv, mldsa_priv = signing.load_private_keys("case_003", keys_dir=tmp_path)
    sig_c, sig_pq = signing.sign_hybrid(MESSAGE, ed_priv, mldsa_priv)

    # Simulate a third party: they have ONLY the public/ folder.
    ed_pub, mldsa_pub = signing.load_public_keys(case_dir / "public")
    assert signing.verify_hybrid(MESSAGE, sig_c, sig_pq, ed_pub, mldsa_pub) is True
    manifest = json.loads((case_dir / "public" / "public_keys.json").read_text())
    assert manifest["ml_dsa"]["algorithm"] == "ML-DSA-65"


def test_key_errors_never_leak_key_material(tmp_path):
    with pytest.raises(signing.KeyManagementError) as exc:
        signing.load_private_keys("missing_case", keys_dir=tmp_path)
    assert "missing_case" in str(exc.value)