# Stamped

**Court-ready digital evidence that stays trustworthy for 30 years.**

Built by **A3TK** for HackSecure 2026 — Digital Forensics Track.

---

## What this is

Stamped is an evidence-integrity platform for digital forensics investigators. It seals evidence at the moment of capture, records every action in a tamper-evident custody log, links every analysis result back to the sealed source, and protects those integrity records with hybrid classical and post-quantum signatures — verifiable independently, without trusting our software.

Most digital evidence needs to stay trustworthy for 10 to 30 years, through investigation, trial, appeal, and cold-case review. Many small forensic units still track custody in spreadsheets, and integrity proofs built on today's signature schemes (RSA/ECDSA) were never designed to outlast the cryptography behind them. Stamped is built so the proof of integrity doesn't expire.

For the full problem statement, market analysis, legal alignment, and business case, see [`docs/Project_Document.docx`](docs/Project_Document.docx).

## How it works

Evidence moves through five stages, each one owned by a team member, with every stage writing to a shared, hash-chained custody log:

```
[1 CAPTURE] -> [2 SEAL] -> [3 INGEST + TIMELINE] -> [4 DETECT] -> [5 REPORT]
 Amir          Ash          Abdi                     Alex          Kea
```

Three rules hold across the whole system:

1. **Nothing enters analysis unsealed.** Evidence is hashed and signed before any parser touches it.
2. **Nothing leaves analysis without provenance.** Every derived artifact records its source hash, the tool and version that produced it, and its own hash.
3. **Nothing happens without a log entry.** Every action is appended to a hash-chained custody log.

## Project structure

```
stamped/
├── capture/        # Webhook listener, evidence bundle assembly (Amir)
├── seal/           # Hashing, custody log, hybrid signing, anchoring (Ash)
├── ingest/         # Log parsers, normalization, timeline (Abdi)
├── detect/         # Detection rules and provenance-linked findings (Alex)
├── access/         # Role-based access enforcement (Ash)
├── report/         # Report templates and export (Kea)
├── app/            # Streamlit dashboard (Kea)
├── verifier/        # Standalone independent verifier (Ash)
├── schemas/        # Shared database schema and normalized event schema
├── data/
│   ├── sample/      # Dummy datasets and fixtures
│   └── public_samples/  # Public datasets used for validation
├── tests/
├── docs/            # Project document, crypto setup notes, validation notes
└── README.md
```

## Setup

### Requirements

- Python 3.10+
- Linux (campus workstations) recommended
- Git

### Install

```bash
git clone <repo-url>
cd stamped
pip install -r requirements.txt
```

### Crypto library setup

Stamped uses hybrid signing: Ed25519 (classical) plus ML-DSA (post-quantum, via Open Quantum Safe's `liboqs-python`).

```bash
pip install liboqs-python
```

If this fails to build on your machine, see [`docs/crypto-setup.md`](docs/crypto-setup.md) for the agreed fallback (pure-Python ML-DSA implementation). Don't spend more than a few hours debugging the build before switching — this is flagged as the project's top technical risk.

### Initialize the database

```bash
python schemas/init_db.py
```

This creates a fresh SQLite database from `schemas/schema.sql`. The schema is frozen and agreed by the whole team — do not modify it without a team review (see `CONTRIBUTING.md`).

### Run the app

```bash
streamlit run app/main.py
```

### Run the independent verifier

The verifier is standalone and has no dependency on the running app — it's meant to be run by anyone (a judge, a defence expert) who wants to check a case independently.

```bash
python verifier/verify.py --case-export <path-to-exported-case>
```

## Core demo

The centerpiece of the project: an evidence item sealed in 2026, challenged on appeal in 2041.

1. An alert triggers the webhook, which captures and seals a bundle of evidence.
2. The bundle is parsed into a timeline of events, with detections flagged along the way.
3. Different roles (examiner, investigating officer, prosecutor) see different views of the same case.
4. A record is tampered with. The verifier runs and identifies exactly which entry broke the chain.
5. The custody report exports with hashes, custody history, and algorithm status.

## What Stamped protects against — and what it doesn't

| Protects against | Does not protect against |
|---|---|
| Undetected modification of evidence after sealing | Evidence already altered before it reached the platform |
| Editing or deleting custody log entries | A determined insider who controls the database, keys, and every anchor at once |
| Disputes about who handled evidence and when | Poor acquisition practice (e.g. a bad device image) |
| A future weakening of classical signatures | Decryption of seized encrypted data |
| Unreproducible analysis findings | Legal questions of admissibility, which courts decide |

Stamped **supports** chain-of-custody practice aligned with ISO/IEC 27037 and **supports** POPIA safeguards through role-based access and audit logging. It does not guarantee admissibility, and it does not make an organisation POPIA compliant on its own.

## Team (A3TK)

| Member | Owns |
|---|---|
| **Ash** | Trust layer — hashing, custody log, hybrid signing, anchoring, verifier, role enforcement |
| **Amir** | Capture — webhook listener, evidence bundle assembly |
| **Abdi** | Ingestion — log parsers, timeline, incident narrative, project management |
| **Alex** | Detection — normalized schema, rules, provenance-linked findings |
| **Kea** | Frontend — Streamlit dashboard, role views, report export |

## Contributing (team only)

Everyone commits directly to `main` — no feature branches, no PRs. That's fine for a team this size on this timeline, but it means the usual review safety net doesn't exist, so these rules replace it:

- `git pull` before starting any session, commit small and often, and never leave `main` in a state where it doesn't run
- Flag in the team channel *before* touching `schemas/schema.sql` — every module depends on it, and a bad change pushed straight to `main` breaks everyone's local copy immediately
- Crypto code (anything in `seal/` touching hashing or signing) gets a manual line-by-line read by someone other than the author *before* it's pushed to `main` — schedule this as a deliberate step, since there's no PR to force it
- No AI-generated mock/simulated results in the verifier or the tamper-detection demo path — see `docs/Stamped_Issues.md` cross-cutting guardrails

## Status

Built for HackSecure 2026. Submission deadline: **27 October 2026**. Feature freeze: 22 October 2026.

## License

TBD by team.
