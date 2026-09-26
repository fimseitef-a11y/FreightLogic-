# GPT → Claude: operator-approved Field Certification Runner + final M6 replay

Date: 2026-09-17
Current main at handoff: `ee07297045d76bf1288c895159718c5ab9646b82`
Tracking issue: **#226**

## Operator approval

The operator explicitly approved building a guided physical-iPhone certification runner so A1–A12 can be completed efficiently on the final post-v24.5 candidate instead of as twelve disconnected manual investigations.

This does **not** waive the physical-device requirement. Headless/browser/emulator evidence may pre-validate logic but may never close a physical A-row by itself.

## Implementation authority

Current repo authority makes Claude the sole runtime writer for v24.5; `tests/` and certification docs are Claude-owned and `app.js` is SHARED/serialized. GPT is reviewer/verifier. Please implement #226 in the owning lane rather than asking GPT to create a parallel runtime branch.

## Runner contract

Build a resumable certification session inside the existing app/diagnostics/More architecture. Before A1, freeze candidate/environment evidence: app origin/version, DB version, active SW URL/scope/cache generation, Worker `/health` version, candidate SHA when exposed, Safari vs installed-PWA launch mode, timestamps, and operator-confirmed iPhone/iOS when the platform cannot report them reliably.

Each A1–A12 row is exactly one of `NOT_RUN | RUNNING | PASS | FAIL | BLOCKED`. Persist non-sensitive automated observations, required manual actions, operator attestation, timestamps, environment fingerprint, and failure/block reason. A generation change invalidates the session.

Never store/export bearer/admin tokens, PIN/PIN hash, passphrases, invite/claim codes, private raw M6 freight rows, or unrelated device data. Export only a privacy-safe certification summary.

Use synthetic records wherever the existing checklist permits. Do not duplicate canonical evaluator, routing, persistence, onboarding or security logic.

### Manual-only checkpoints that must remain real-device evidence

- A1 normal installed-PWA update/launch identity and no data loss/loop.
- A4 Airplane Mode close/reopen/offline/reconnect observation.
- A6 real GPS movement + background/locked >=10 minutes; do not require interaction while driving.
- A7 revoke Location permission in iOS Settings mid-trip.
- A8 two real Safari tabs stale-edit conflict.
- A11 iOS 27+ SVG/select/scroll/persistent-storage/backup-paused visual behavior.
- A12 Mail/iMessage invite delivery and the Safari → Home Screen storage-partition result.

The runner can automate/check the deterministic portions of A2/A3/A5/A9/A10 and the machine-observable portions of the rows above, but not manufacture a physical PASS.

## TDD / controls

Write failing regressions first. Minimum negative controls:

1. wrong runtime generation cannot start/continue;
2. automation alone cannot close physical row;
3. A6 cannot PASS without >=10-minute checkpoint + real-device attestation;
4. A11 cannot PASS without iOS 27+ attestation + all manual checkpoints;
5. A12 cannot PASS without explicit Safari→Home Screen storage-partition answer;
6. stored/exported evidence contains no secrets;
7. candidate generation change invalidates in-progress session;
8. FAIL/BLOCKED cannot be overwritten by generic green automated state.

Each new assertion needs the repo-standard effective negative control.

## M6 — important correction

The five-file authentic bundle is **located**, not missing. Private Library location:

`/Freight history/M6 Bundle/FreightLogic_Recovered_History_2026-09-13.zip`

It contains all five adapter-expected CSVs and 216 source rows. Keep all raw rows off the public repository.

Historical authentic run at `07d7e4a` produced:

- 149 imported records;
- identical re-import: 149 existing / 0 new;
- 5 reused order numbers kept separate where facts conflict;
- 2 dry runs preserved and excluded;
- deadhead known on only 8/149; UNKNOWN never coerced to zero;
- winning-RPM calibration correctly unavailable.

The file-specific `scripts/m6-import.mjs` has changed by only one added/one removed line since that raw run (the documented output-filename comment correction), but `importHistoricalOpportunities()` later gained evidence-first and no-op safety changes. Therefore final strict M6 PASS still requires replaying the private raw ZIP against the final candidate.

Current exact-main controlled suite rerun proves the M6 contract itself is green despite unrelated #224:

- `integration/m6-historical-import.spec.mjs` 15/15;
- `integration/batch-b-m6-reconciliation.spec.mjs` 14/14;
- `integration/blockers-exact-candidate.spec.mjs` 12/12;
- `integration/batch-a-release-integrity.spec.mjs` 21/21;
- `integration/m4-load-lifecycle.spec.mjs` 30/30.

## Final certification sequence

1. Resolve #224 so exact-head full suite is first-attempt green.
2. Land v24.5 + Field Certification Runner under normal generation/lock discipline.
3. Deploy final candidate; live parity + production SW green.
4. Run A1–A12 once on operator's actual iPhone through the runner.
5. Mount/private-access the M6 ZIP and run `verify-history-bundle.mjs`, `m6-import.mjs`, current import pathway twice, and reconciliation checks against the same candidate.
6. Record only non-sensitive M6 counts/verdicts publicly.
7. Supersede certification state with exact candidate SHA + A1–A12/M6 evidence.

Do not mark #226 or the release certified from emulation/headless-only evidence.
