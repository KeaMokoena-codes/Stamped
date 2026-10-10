## Decision: one keypair set per case

Each case gets its own Ed25519 keypair **and** its own ML-DSA-65 keypair,
generated once when the case is created (`signing.create_case_keys(case_id)`).

Why per case rather than per team:

- **Blast radius.** If one case's private keys are ever exposed, only that
  case's signatures are in question, not every case the team has ever sealed.
- **Handover.** A case can be exported to a prosecutor or court with its public
  keys and nothing that touches any other case.
- **Cost.** Key generation takes milliseconds, so there is no reason to share.

Trade-off: more key sets to back up. For the hackathon this is fine; a
production deployment would put private keys in an HSM or KMS.

## Where keys live

```
keys/<case_id>/
├── ed25519_private.bin      PRIVATE  (file mode 0600)
├── mldsa65_private.bin      PRIVATE  (file mode 0600)
└── public/                  SAFE TO SHARE
    ├── ed25519_public.bin
    ├── mldsa65_public.bin
    └── public_keys.json     manifest: algorithm names, base64 copies
```

- `keys/` is in `.gitignore` (including `**/keys/`). Never commit it.
- The `keys/<case_id>/` directory is created `0700`; private files are created
  `0600` from the first write, so they are never briefly world-readable.
- `create_case_keys` refuses to overwrite existing keys: replacing a signing key
  would orphan every signature made with the old one.
- `case_id` may contain only letters, digits, `-` and `_` (it becomes a folder
  name, so path traversal is blocked).

## How the independent verifier gets the public keys

The verifier must run **without the application**. It needs only the
`public/` folder:

1. Copy `keys/<case_id>/public/` into the exported case package. (`keys/` is
   gitignored, so this is a deliberate copy, not a git operation.)
2. The verifier reads `ed25519_public.bin` and `mldsa65_public.bin`, and checks
   `public_keys.json` for the algorithm names.
3. A record is valid only if **both** signatures verify over the same bytes.

## What gets signed

`sign_hybrid` signs exactly the bytes it is given and never re-encodes them.
Callers must pass the canonical pre-signature bytes: for custody log entries
and checkpoints, the `entry_hash` (see `docs/custody-log-format.md`). Never
sign a structure that already contains the signature (circular).

## Known limitations (state these honestly in the pitch)

- Private keys are stored as raw files protected by filesystem permissions
  only. They are **not** passphrase-encrypted. Anyone with read access to the
  machine as that user can use them.
- Signing is not yet wired into the custody log. Issue #1.4 (anchoring) is
  where checkpoints get signed.
- A hybrid signature protects integrity records against a future break of one
  algorithm family. It does not make evidence admissible and does not protect
  seized encrypted data.
- Rotating or revoking a case key is not implemented.