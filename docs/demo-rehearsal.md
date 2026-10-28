# Tamper-detection demo: rehearsal plan, fallback and timing

Purpose: catch fragility before judging day. "It worked once on my machine" does not count.
A rehearsal only counts when it is run from a clean environment (no `data/stamped.db`,
no `keys/`, no caches, no previously running app).

## What the demo actually does

The Verification page button `demo: simulate tampering` runs two subprocesses from the repo root:

1. `python -m scripts.simulate_tamper --case-dir <tmp>/demo-case` builds a synthetic 3-entry custody log, alters entry #2's actor, and writes placeholder public keys.
2. `python verifier/verify.py --case-export <tmp>/demo-case --allow-no-anchors --json` verifies it.

Expected on screen: red message **"first broken custody entry is #2"**, JSON with `"overall": "FAIL"`,
`"broken_entry_id": 2`, and two `"SKIPPED"` checks (signatures, anchors). The live database is never touched.

This demo is **chain-only**. It does not show signatures or anchors. Say so out loud in the pitch.

## Rehearsal procedure (do this on the pitch machine)

Automated part (3 clean-copy runs, timed):

```bash
python -m scripts.rehearse_demo --runs 3 --with-ui
```

Exit code 0 and `RESULT: PASS` required. `--with-ui` needs Streamlit installed and drives the real page.

Manual part (once per rehearsal, from a fresh clone or a fresh `venv`):

```bash
git clone <repo-url> && cd <repo>
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python schemas/init_db.py
python -m scripts.create_user --user-id examiner1 --display-name "Demo Examiner" --role examiner
python -m streamlit run run_app.py
```

Then in the browser: sign in as `examiner1` -> Verification -> click the button. Time it with a stopwatch from sign-in to the red message.

## Known fragility points (checked in code)

- Run scripts with `-m` from the repo root. `python scripts/simulate_tamper.py` fails with `ModuleNotFoundError: No module named 'schemas'`. The button already uses `-m`; a presenter typing commands by hand may not.
- A fresh clone has no `data/stamped.db` (gitignored). Without `init_db` and `create_user`, sign-in fails. Do these before going on stage.
- `liboqs-python` is not needed for this demo (chain-only), but is needed for `scripts/check_liboqs.py` and any signing demo. Do not claim PQ signatures were verified in this demo.
- The README mentions WeasyPrint for PDF reports; `requirements.txt` pins `xhtml2pdf`. Reports are outside this demo, but check before showing them.

## Extra cases checked against the real verifier (chain-only mode)

Run on disposable copies in Claude's sandbox. The custody log has append-only triggers, so
changes below were made after dropping them, as an insider with database access would.

| Case | Exit code | Result |
|---|---|---|
| Standard demo (entry #2 altered) | 1 | FAIL, broken entry #2 |
| Untampered control | 0 | PASS (chain-only) |
| Entry #1 altered / entry #3 (last) altered | 1 | FAIL, #1 / #3 |
| Middle entry deleted | 1 | FAIL, blames #3 (the entry after the gap) |
| Last entry deleted | 0 | **PASS: chain alone cannot see this; anchors catch it** |
| Database missing / public key folder missing / corrupt database | 2 | ERROR, never PASS |

Prepare an answer for "what if I delete the newest entry?": the hash chain cannot detect it
by itself, and that is exactly what the external signed anchors are for (see `docs/anchoring.md`).
The on-stage demo does not show anchors, so do not claim it does.

## Fallback plan (backup only, never the primary plan)

1. **Primary:** live click in the dashboard.
2. **Backup A (terminal):** one command in a prepared terminal tab, opened in the repo root with the venv active: `python -m scripts.demo_fallback`. It runs the same real verifier on a disposable case and prints its output unmodified; exit code 0 means entry #2 was detected. Takes well under a second.
3. **Backup B (recording):** a screen capture of a successful live run, saved locally (not only in the cloud) and tested to play offline. Record it after the final clean rehearsal, from the same machine and resolution.
4. Decide beforehand who switches to the fallback and after how many seconds of a stuck screen (suggested: 10 s).

### Recording the backup video (Backup B)

Record only after the final clean rehearsal passes, on the pitch machine and at the pitch resolution.

- [ ] Fresh start: new browser window, no other tabs, notifications off, app started from a clean clone.
- [ ] Capture the whole flow: sign-in as `examiner1` -> Verification -> click the button -> red message and verifier output visible long enough to read (hold 3 s).
- [ ] Capture the Backup A terminal run as a second clip.
- [ ] Record it as a genuine live run. Do not edit, splice or fake any frame (the project forbids simulated results in the demo path).
- [ ] Save a copy on the pitch laptop and a copy on a USB drive; play it with the Wi-Fi off to confirm it works offline.
- [ ] Name the files with the date and commit hash of the recorded version.

## Timing

| Measurement | Value | Where measured |
|---|---|---|
| Button logic only (prepare + verify), 3 clean-copy runs | about 0.13 to 0.20 s total | Claude's Linux sandbox, Python 3.12, no Streamlit |
| Click-to-result in the real dashboard | TO MEASURE | pitch machine |
| Whole demo segment including narration | TO MEASURE | pitch machine |

The sandbox figures show the verifier is not the bottleneck. They say nothing about Streamlit start-up, page loads or browser speed on the pitch machine.

## Rehearsal log (fill in on the pitch machine; leave blank until actually done)

| # | Date | Machine / OS / Python | Clean env? | Result | Click-to-result (s) | Notes |
|---|---|---|---|---|---|---|
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |

Definition of Done status:

- [ ] 3 successful runs from a clean environment on the pitch machine
- [ ] Backup recording exists and plays offline
- [ ] Demo segment time documented and fits the pitch budget
