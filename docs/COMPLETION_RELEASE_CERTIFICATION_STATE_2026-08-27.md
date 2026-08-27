# FreightLogic Completion Release — Certification State

Date: 2026-08-27
Runtime source baseline reviewed: `3fba27a16cebf22a20a54191101b17cc27feac6e` (later merges through the current governance head are docs-only unless separately noted)
Status: **HOLD — NOT CERTIFIED FOR COMPLETION RELEASE**

This is a certification-state record, **not a second roadmap**. Milestone order and scope remain governed by `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`.

## What is already implemented

The repository contains substantial implementation for:

- Gate 0 operator-truth / evidence-provenance governance;
- Milestone 1 doctrine and money-integrity repairs;
- Milestone 2 expense/fuel optimistic concurrency;
- Milestone 3 Confidence + Evidence helpers/UI integration;
- Milestone 4 load lifecycle schema/state/UI/analytics foundation;
- Milestone 5A normalized-opportunity helper and helper-level local intake machinery;
- Milestone 6 historical-import and calibration machinery.

**Important M5B distinction:** current source does not contain a production caller that wires the driver-facing manual/email-compatible intake through `intakeOpportunity()`. The helper exists and tests call it directly through `window.__FL_TESTS`; that is not the same as implementing the required production M5B path.

Passing CI on milestone PRs proves the tested assertions passed. It does **not** by itself certify the completion release, because current-source review has identified uncovered real-path defects below.

## Current release-blocking source defects

### 1. IndexedDB v14 lifecycle indexes

The catch-all DB upgrade path creates `loadLifecycle` before the v14 block that creates its indexes. Consequently the `updatedAt`, `orderNo`, and `broker` indexes are not guaranteed to exist after the intended upgrade path. Certification requires a migration repair plus assertions against the actual resulting `indexNames` on fresh and v13→v14 paths.

### 2. Cloud delta-sync lifecycle initialization

`cloudPushBackup()` checks `lc.length` in its empty-delta guard before `lc` is declared. A valid delta-sync path can therefore fail before upload/no-op completion. Certification requires a real empty-delta regression, not helper-only coverage.

### 3. Lifecycle / durable-evidence export integrity

Local JSON export includes `loadLifecycle`, but the current checksum helpers hash only trips/expenses/fuel and settings. Lifecycle mutations therefore are not protected by the export's integrity checksum. Any newly durable normalized evidence must also participate in the protected export-integrity contract.

### 4. Reused-identifier lifecycle ambiguity and timestamp loss

The lifecycle linker still auto-links a unique normalized broker+order match without enforcing compatibility of supplied route/time facts, and lifecycle stage chips/editor lookup are keyed by order number alone. Reused identifiers can therefore link, display, or edit the wrong lifecycle.

`pickupAt` / `deliveryAt` are passed through a date-only `YYYY-MM-DD` validator, so clock-time evidence needed to disambiguate same-ID shipments cannot survive lifecycle normalization/persistence. Ambiguity must fail safe rather than pick a record.

### 5. Lifecycle background-link concurrency

`linkLifecycle()` reads a matched base row and then calls `upsertLifecycle()` without deriving `expectedRevision` from the revision it read. The normal intake/background caller therefore can bypass the compare-and-abort boundary and overwrite a newer lifecycle mutation with a stale merged object. Real-path race coverage is required.

### 6. Worker canonical-absence compatibility

The source remains Worker v12. `/evaluate` requires a truthy verdict/grade, finite True RPM, and a bid range, which is incompatible with the canonical client's legitimate incomplete/`UNAVAILABLE` state. Worker review must preserve client-owned absence instead of coercing or rejecting it.

### 7. Confidence/evidence real-path wiring

The post-M3 review remains open for explicit fuel write-point provenance, NWS successful-zero versus no-observation/failure semantics, persisted evaluation-history evidence snapshots, real lane/broker evidence wiring, and actual vehicle-fit measurement state. Confidence remains descriptive-only; repairing evidence wiring must not change decision authority.

The current M3 suite mostly tests helpers with hand-built inputs and does not certify these real evaluator / Worker-handler paths.

### 8. Normalized opportunity evidence is not durable and the M5B production path is absent

`normalizeOpportunity()` produces money, mileage, semantic and provenance fields, but `intakeOpportunity()` persists only a lifecycle projection. Historical import similarly normalizes evidence and then persists lifecycle identity/state without durable amount/mileage semantics or source provenance. Semantic evidence needed for later explanation/calibration can disappear after reload.

Additional exact-source issues:

- a `DISPLAYED_TOTAL_MILES` value can currently occupy the field named `loadedMi`, creating a contradictory shape where a non-loaded-mile fact sits in the canonical loaded-mile slot;
- `operatorConfirmedAt` can default to `Date.now()` when a historical confirmation time is actually unknown, fabricating provenance;
- `sourceTimestamp` uses numeric-only normalization and can discard a valid ISO source timestamp;
- canonical price/mileage vocabulary is narrower than `EVIDENCE_PROVENANCE.md`.

Production call-path review found `intakeOpportunity(` only at its definition in `app.js`, and no call in `voice-load.js`, `admin-driver-ui.js`, `midwest-stack-authority.js`, or `index.html`. Current M5 tests invoke the helper directly via `window.__FL_TESTS`.

Milestone 5A is therefore helper-implemented but durability-incomplete. Milestone 5B is **not production-implemented** until a real manual/email-compatible surface calls normalize → durable evidence persistence → conservative lifecycle link.

The merged implementation contract is `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`.

### 9. Historical adapter reconciliation and import identity

The one-time historical adapter staged in draft PR #108 requires reconciliation before merge. The valid local lifecycle-import fix should be preserved, but adapter identity, correction precedence, per-field provenance, dry-run preservation, and unknown-status handling must be repaired first.

The proposed replacement fingerprint solves the 120-character truncation problem but uses only a 32-bit DJB2 hash plus raw length; a same-length collision has been demonstrated. Dedup identity needs a bounded collision-resistant deterministic digest.

Raw operator financial/history source files remain outside the repository unless the operator explicitly authorizes repository storage.

### 10. M6 recency provenance

`calibrateWinningRange()` currently gives an observation with no `observedAt` full recency weight. `calibrateFromLifecycle()` falls back from evidence observation time to lifecycle `updatedAt`, which for historical imports can be the import/mutation time rather than when the load/market fact was observed.

Unknown observation age must not become maximally fresh, and importing or correcting an old record today must not refresh its market-observation age. Calibration must read durable source observation provenance or keep age unknown under a conservative deterministic policy.

### 11. Release-generation parity

`app.js` still advertises v24.0.1 while the source contains later milestone functionality, and Worker source remains v12. Final app/PWA/cache-buster/service-worker/manifest/Worker version markers must be selected and aligned only after the corrective runtime is stable.

## Test-suite certification gaps

Green CI currently misses several real-path defects. Exact test-gap packets are on `agent-coordination` for M3, M4, and M5. Key examples:

- M4-01 checks store existence but not required lifecycle indexes.
- M4-04 currently asserts broker+order alone is strong linking evidence and must be corrected to require compatible route/time evidence.
- M4-13 is sequential and does not reproduce stale background-link concurrency.
- M4-15's title says export/import but the body uses `dumpStore()` + `mergeRestoreData()` rather than the real local import path.
- M5-12/M5-13 call `intakeOpportunity()` directly through the test exposure and read transient return values rather than proving durable evidence after reload.
- M3 tests primarily exercise confidence helpers and do not drive the real evaluator evidence assembly / history / Worker boundary.

Existing valid authority regressions must remain green, but a test that encodes an unsafe assumption must be corrected to the governing contract rather than preserved merely because it is old.

## Certification gates still required

Before a named completion release can be frozen:

1. Close every current-source defect above with real-path regressions.
2. Keep existing Level X+ authority and money-integrity tests green.
3. Implement the real M5B production manual/email-compatible intake path.
4. Prove normalized evidence remains semantically traceable after reload; missing deadhead remains unknown and cannot become zero.
5. Prove full backup + delta + restore parity with all current durable stores/evidence.
6. Prove local export/import parity and integrity checking with all protected durable data.
7. Repair/re-run the M6 real import off-repo and confirm non-sensitive aggregate outcomes without committing raw financial source files.
8. Run the full automated suite and lane checks on the exact candidate SHA.
9. Complete physical iPhone Safari/offline/GPS representative field checks.
10. Verify the live Cloudflare Pages/Worker generation, `/health`, auth-denial behavior, and non-sensitive `/evaluate` + `/extract` smoke tests.
11. Record an executable rollback point.
12. Only then mark the completion release certified/frozen.

## Current integration disposition

- `main` contains Milestone 6 machinery, but **no release certification is implied**.
- Draft PR #108 preserves valid post-real-data work while remaining blocked for reconciliation.
- M5B production intake remains open; helper-level tests do not satisfy that requirement.
- Vision intake and provider adapters remain governed by the roadmap's explicit non-blocking/defer rules; they do not take precedence over the correctness gates above.

The controlling rule remains: **EVIDENCE → TEST → CHALLENGE → RECONCILE → CERTIFY → ADOPT**.
