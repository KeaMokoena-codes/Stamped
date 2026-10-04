# Crypto setup and liboqs test status

Stamped pins `liboqs-python==0.16.0.1` in `requirements.txt`. This binding
uses liboqs 0.16.0 by default. If it cannot find a native liboqs library,
the binding attempts to clone and build liboqs on first import. That build
requires Git, CMake, and a working C compiler/toolchain; installing the
Python binding alone does not prove ML-DSA is usable.

## Install and test

From the repository root, in the project's Python environment:

```bash
python -m pip install -r requirements.txt
python scripts/check_liboqs.py
```

The smoke test uses ML-DSA-65 to generate a keypair, sign a message, verify
the original message, and assert that verification rejects a modified
message. A passing install must print `PASS`. Import/build errors or a
nonzero exit are failures; do not substitute mock or simulated signatures.

On first import without a native library, liboqs-python fetches the
corresponding liboqs release from GitHub and builds it locally. Ensure Git,
CMake, and a platform C/C++ compiler are installed and available on `PATH`.
On Windows, install the Visual Studio C++ build tools as well as CMake. A
failed CMake configure/build or missing toolchain is an environment/build
failure, not a successful crypto test.

## Test record

Record the OS/version, Python version, binding version, and smoke-test
result for each team machine here. The project requirement is at least three
successful team-machine round-trips; a CI runner or repeated test on one
machine does not count as multiple team machines.

| Machine/member | OS | Python | liboqs-python | Result |
|---|---|---|---|---|
| Local Windows machine | Windows 11 Home Single Language, version 10.0.26200 (build 26200) | 3.13.4 | 0.16.0.1 present | **Failed**: Python binding present, but no native liboqs library was found; auto-build stopped because `cmake` was not available on `PATH`. ML-DSA keygen/sign/verify was not reached. |
| Team machine 2 | Not reported | Not reported | Not reported | Pending |
| Team machine 3 | Not reported | Not reported | Not reported | Pending |
| Team machine 4 | Not reported | Not reported | Not reported | Pending |
| Team machine 5 | Not reported | Not reported | Not reported | Pending |

The local failure occurred before CMake configuration or compilation and is
not a four-hour build attempt. It does not, by itself, establish that liboqs
is unusable on the team's supported machines.

## Time-box and fallback

For any machine where the native build fails, time-box troubleshooting to
four hours. The team should record the start time and stop debugging that
machine when the limit is reached. If the binding still cannot be built,
the team must explicitly decide and record whether to use a pure-Python
ML-DSA implementation (for example, a reviewed and version-pinned
`dilithium-py`) or another supported environment. Do not add a fallback
dependency or change the crypto implementation until that decision is made.

No fallback has been selected or tested in this record. The three-machine
success threshold and team fallback decision remain pending; do not treat
the issue as complete until those results and the decision are recorded.
