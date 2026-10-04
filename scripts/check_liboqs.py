"""Run a real ML-DSA-65 sign/verify smoke test against liboqs."""

import oqs


ALGORITHM = "ML-DSA-65"
MESSAGE = b"Stamped liboqs installation smoke test"


def main() -> None:
    enabled = oqs.get_enabled_sig_mechanisms()
    if ALGORITHM not in enabled:
        raise RuntimeError(
            f"{ALGORITHM} is not enabled in this liboqs build. "
            f"Enabled signature algorithms: {', '.join(enabled)}"
        )

    with oqs.Signature(ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(MESSAGE)

        if not signer.verify(MESSAGE, signature, public_key):
            raise RuntimeError("ML-DSA-65 rejected the original signed message")
        if signer.verify(MESSAGE + b" (tampered)", signature, public_key):
            raise RuntimeError("ML-DSA-65 accepted a tampered message")

    print(
        f"PASS: {ALGORITHM} key generation, signing, valid verification, "
        "and tampered-message rejection"
    )
    print(f"liboqs version: {oqs.oqs_version()}")
    print(f"Signature size: {len(signature)} bytes")


if __name__ == "__main__":
    main()
