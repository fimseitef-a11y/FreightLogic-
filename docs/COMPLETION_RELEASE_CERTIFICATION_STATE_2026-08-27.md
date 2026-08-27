# FreightLogic Completion Release — Certification State

Date: 2026-08-27
Source baseline reviewed: `3fba27a16cebf22a20a54191101b17cc27feac6e`
Status: **HOLD — NOT CERTIFIED FOR COMPLETION RELEASE**

This is a certification-state record, **not a second roadmap**. Milestone order and scope remain governed by `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`.

## What is already implemented

The repository now contains substantial implementation for:

- Gate 0 operator-truth / evidence-provenance governance;
- Milestone 1 doctrine and money-integrity repairs;
- Milestone 2 expense/fuel optimistic concurrency;
- Milestone 3 Confidence + Evidence helpers/UI integration;
- Milestone 4 load lifecycle schema/state/UI/analytics foundation;
- Milestone 5A/5B normalized opportunity helpers and provider-independent intake foundation;
- Milestone 6 historical-import and calibration machinery.

Passing CI on those milestone PRs proves the tested assertions passed. It does **not** by itself certify the completion release, because current-source review has identified uncovered real-path defects below.

## Current release-blocking source defects

### 1. IndexedDB v14 lifecycle indexes

The catch-all DB upgrade path creates `loadLifecycle` before the v14 block that creates its indexes. Consequently the `updatedAt`, `orderNo`, and `broker` indexes are not guaranteed to exist after the intended upgrade path. Certification requires a migration repair plus an assertion against the actual resulting `indexNames`.

### 2. Cloud delta-sync lifecycle initialization

`cloudPushBackup()` checks `lc.length` in its empty-delta guard before `lc` is declared. A valid delta-sync path can therefore fail before upload/no-op completion. Certification requires a real empty-delta regression, not helper-only coverage.

### 3. Lifecycle export-integrity coverage

Local JSON export includes `loadLifecycle`, but the current legacy/full checksum helpers hash only trips/expenses/fuel and settings. Lifecycle mutations therefore are not protected by the export's integrity checksum. A backward-compatible integrity version must cover current material exported stores.

### 4. Reused-identifier lifecycle ambiguity

The lifecycle linker still auto-links a unique normalized broker+order match without enforcing compatibility of supplied route/time facts, and lifecycle stage chips are indexed by order number alone. Reused identifiers can therefore link or display the wrong lifecycle. Ambiguity must fail safe rather than pick a record.

### 5. Worker canonical-absence compatibility

The deployed source remains Worker v12. `/evaluate` requires a truthy verdict/grade, finite True RPM, and a bid range, which is incompatible with the canonical client's legitimate incomplete/`UNAVAILABLE` state. Worker review must preserve client-owned absence instead of coercing or rejecting it.

### 6. Confidence/evidence real-path wiring

The post-M3 review remains open for explicit fuel write-point provenance, NWS successful-zero versus no-observation/failure semantics, persisted evaluation-history evidence snapshots, real lane/broker evidence wiring, and actual vehicle-fit measurement state. Confidence remains descriptive-only; repairing evidence wiring must not change decision authority.

### 7. Normalized opportunity evidence is not durable

`normalizeOpportunity()` produces money, mileage, semantic and provenance fields, but `intakeOpportunity()` persists only a lifecycle projection. Historical import similarly normalizes evidence and then persists lifecycle identity/state without durable amount/mileage semantics or source provenance. Semantic evidence needed for later explanation/calibration can disappear after reload.

Milestone 5A/5B and Milestone 6 are therefore **not certification-complete** until a bounded durable evidence representation is linked to lifecycle identity and included in backup/delta/restore/export/import compatibility.

### 8. Historical adapter reconciliation

The one-time historical adapter currently staged in draft PR #108 requires reconciliation before merge. The valid bounded-fingerprint and local lifecycle-import fixes on that branch should be preserved, but adapter identity, correction precedence, per-field provenance, dry-run preservation, and unknown-status handling must be repaired first.

Raw operator financial/history source files remain outside the repository unless the operator explicitly authorizes repository storage.

### 9. Release-generation parity

`app.js` still advertises v24.0.1 while the source contains later milestone functionality, and Worker source remains v12. Final app/PWA/cache-buster/service-worker/manifest/Worker version markers must be selected and aligned only after the corrective runtime is stable.

## Certification gates still required

Before a named completion release can be frozen:

1. Close every current-source defect above with real-path regressions.
2. Keep existing Level X+ authority and money-integrity tests green.
3. Prove full backup + delta + restore parity with all current durable stores.
4. Prove local export/import parity and integrity checking with current durable stores.
5. Prove historical evidence remains semantically traceable after reload; missing deadhead remains unknown and cannot become zero.
6. Run the full automated suite and lane checks on the exact candidate SHA.
7. Complete physical iPhone Safari/offline/GPS representative field checks.
8. Verify the live Cloudflare Pages/Worker generation, `/health`, auth-denial behavior, and non-sensitive `/evaluate` + `/extract` smoke tests.
9. Record an executable rollback point.
10. Only then mark the completion release certified/frozen.

## Current integration disposition

- `main` contains Milestone 6 machinery, but **no release certification is implied**.
- Draft PR #108 preserves two valid post-real-data fixes while remaining blocked for reconciliation.
- Vision intake and provider adapters remain governed by the roadmap's explicit non-blocking/defer rules; they do not take precedence over the correctness gates above.

The controlling rule remains: **EVIDENCE → TEST → CHALLENGE → RECONCILE → CERTIFY → ADOPT**.