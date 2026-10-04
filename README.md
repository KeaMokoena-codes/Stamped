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
python -m pip install -r requirements.txt
python scripts/check_liboqs.py
```

The smoke test verifies a real ML-DSA-65 signature and confirms that a modified message is rejected. See [`docs/crypto-setup.md`](docs/crypto-setup.md) for prerequisites, tested-machine results, and the team's time-boxed fallback status. Do not replace a failed install with a mock or simulated signature implementation.

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

Everyone commits directly to `main` — no feature branches or PRs. Since there is no review gate, use this protocol for every work session and commit:

1. Run `git pull` before starting a session.
2. Make small, focused commits as work is completed; don't save everything for one end-of-day commit.
3. Run the full test suite locally (`pytest -v --tb=short`) before every commit.
4. Never leave `main` in a state where the project does not run. If a change breaks it, fix or revert that change before starting other work.
5. Before editing a shared or high-impact file, post a short heads-up in the GitHub issue thread for the task (use issue #1 for repository-wide coordination). Name the file and say you are starting, for example: "I'm touching `schemas/schema.sql` now" or "I'm touching `seal/signing.py` now." Post again when finished so the next person knows it is free. This 10-second message is the team's overlap check in place of a PR review.

Crypto code (anything in `seal/` touching hashing or signing) should also get a manual line-by-line read by someone other than the author before it is pushed to `main`. No AI-generated mock/simulated results in the verifier or the tamper-detection demo path — see `docs/Stamped_Issues.md` cross-cutting guardrails.

## Status

Built for HackSecure 2026. Submission deadline: **27 October 2026**. Feature freeze: 22 October 2026.

## License

TBD by team.
