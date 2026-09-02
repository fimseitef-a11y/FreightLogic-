# Backup Contract

Started in Phase 1 of v23.9 "Trust & Recovery" and maintained as the single normative list of what `cloudPushBackup()` uploads and what `cloudPullBackup()` → `mergeRestoreData()` must restore.

## Rule

**Every persisted store or settings field uploaded by `cloudPushBackup()` must be restorable by `mergeRestoreData()`.** Credentials are the only documented exception. Any release that adds a durable store/field must update this document, push/export coverage, merge/restore coverage, integrity coverage when protected, and regression tests in the same release.

A restore must preserve newer local protected history. For revisioned records, import/restore is reconciliation, not blind overwrite. Scalar values and their provenance must travel together.

## Credentials exception

Cloud backup and `exportJSON()` exclude these secret settings:

- `fmcsaApiKey`
- `eiaApiKey`

No backup/import path may re-introduce them from an export payload.

## Store-level contract — v24.0.2 / DB v15

| Store | Full backup | Delta backup | Restored | Contract |
|---|---:|---:|---:|---|
| `trips` | Yes | Yes | Yes | Existing trip merge rules; no secret material. |
| `expenses` | Yes | Yes | Yes | Includes `insuranceBucket` where present. |
| `fuel` | Yes | Yes | Yes | Preserve persisted fuel records. |
| `laneHistory` | Yes | Yes | Yes | Preserve history without manufacturing newer evidence. |
| `weeklyReports` | Yes | Yes | Yes | Existing report identity/merge rules. |
| `reloadOutcomes` | Yes | Yes | Yes | Existing outcome identity/merge rules. |
| `bidHistory` | Yes | Yes | Yes | Preserve historical bid evidence. |
| `documents` | Yes | Yes | Yes | Metadata/document records under existing contract. |
| `gpsLogs` | Yes | Yes | Yes | Deduplicate on `tripTrackingId` + `timestamp`; incoming numeric ID is not trusted as a write key. |
| `settings` | Yes | Yes | Yes | Secret keys filtered; merge remains conservative/additive unless a setting has an explicit newer contract. |
| `receipts` | Yes | Yes | Yes | File-list union by receipt file `id`; metadata pointer only. |
| `loadLifecycle` | Yes | Yes | Yes | Protected revisioned lifecycle state; see below. |
| `normalizedEvidence` | Yes | Yes | Yes | Protected durable normalized opportunity evidence; see below. |
| `receiptBlobs` (Cache API) | No | No | No | Out of scope; receipt metadata round-trips, blob bytes do not. |
| `auditLog` | No | No | No | Intentionally local-only. |

## `loadLifecycle` contract

`loadLifecycle` is lifecycle state/linking, not the normalized market-evidence store.

| Property | Value |
|---|---|
| keyPath | `lifecycleId` — stable internal identity, independent of broker/order number |
| Required indexes | `updatedAt`, `orderNo`, `broker` |
| Full backup | yes |
| Delta backup | yes; changed records selected by persisted update state |
| Restore/import | yes |
| Protected checksum | yes (`checksumProtected`) |
| Merge | by stable lifecycle identity; reconcile `revision`/`updatedAt`; `sourceRefs` unioned and de-duplicated |

External order numbers are candidate linking signals only. Reused identifiers must never collapse unrelated shipments. Ambiguous links fail unresolved rather than guessing.

For competing lifecycle copies, an older delta/import must not roll a newer confirmed state backward. `createdAt` keeps the earliest defensible creation time; revision/newer scalar state wins according to runtime reconciliation; `sourceRefs` are unioned because each copy can carry a legitimate partial reference set.

A legacy payload with no `loadLifecycle` key is valid legacy input and is not corruption.

## `normalizedEvidence` contract — v24.0.2 / DB v15

`normalizedEvidence` is the durable evidence layer introduced by the release-integrity correction. It preserves normalized opportunity facts, semantics, source references, confirmation state, and per-field provenance independently of lifecycle linkage.

| Property | Value |
|---|---|
| keyPath | `evidenceId` |
| Required indexes | `recordedAt`, `lifecycleId`, `fingerprint`, `observedAt` |
| Full backup | yes |
| Delta backup | yes |
| Restore/import | yes |
| Protected checksum | yes (`checksumProtected`) |
| Identity | bounded SHA-256 evidence fingerprint / stable evidence ID contract |
| No-op re-import | must preserve the existing evidence row, revision, and `recordedAt` |
| Lifecycle link | may remain unresolved; evidence durability does not depend on successful linking |
| Provenance | field-specific and preserved with the scalar it qualifies |

### Evidence-first durability

Both source-normalization paths must persist the normalized observation **before** lifecycle linkage is attempted:

1. manual/production `intakeOpportunity()`;
2. historical reconciliation/import.

A lifecycle row must never stand as the only durable trace of an observation whose normalized evidence failed to persist.

### Semantic preservation

Backup/import must preserve the evidence vocabulary rather than reinterpret values:

- `SHIPPER_BOOKABLE_PRICE`, `OPERATOR_BID`, `BOARD_TARGET_RATE`, `POSTED_RATE`, and `MARKET_BENCHMARK` remain evidence and do not become canonical carrier revenue;
- only proven carrier-payout/settled semantics or explicit field-specific operator revenue confirmation may populate canonical revenue;
- `DISPLAYED_TOTAL_MILES` must not occupy canonical loaded-mile fields;
- unknown material facts remain null/UNKNOWN, not zero;
- typed/manual values keep truthful field-specific provenance and are not upgraded wholesale to `PRIMARY_DOCUMENT` or `OPERATOR_CORRECTION`;
- source timestamps retain available precision; an unknown confirmation timestamp stays unknown unless a live action explicitly stamps it.

### Restore reconciliation

Cloud restore and local JSON import must use the same protected-record principle:

- compare stable identity/revision before replacing a protected record;
- never overwrite newer protected local history with a stale incoming record;
- keep scalar/provenance pairs from the same winning side;
- do not synthesize provenance for absent fields;
- repeated exact evidence imports are idempotent.

A pre-v15 payload with no `normalizedEvidence` key is valid legacy input and is not corruption.

## Protected export integrity

v24.0.2 retains the legacy `checksumFull` compatibility path for older exports and adds/uses `checksumProtected` for current protected data. Current-generation integrity coverage includes at least:

- `loadLifecycle`;
- `normalizedEvidence`;
- the existing core export data included by the implementation.

A lifecycle-only or normalized-evidence-only mutation of a current export must be detectable. Legacy exports lacking the newer protected sections remain eligible for the documented compatibility path; absence must not be silently interpreted as current complete coverage.

## Delta restore coverage

`cloudPushBackup()` can write deltas when the base full backup is recent and the change set is small. `cloudPullBackup()` must read the base snapshot and retained deltas, applying deltas in chronological order.

Coverage has two non-silent failure states:

- **Confirmed gap** — Worker lifetime `totalCreated` is greater than retained delta count, proving eviction/expiry occurred.
- **Unverifiable** — delta retrieval, decrypt, or parse failed, so full coverage cannot be proven.

Either state must surface a visible partial-restore warning rather than a false success.

The zero-change delta path is also part of the contract: it must not reference uninitialized store variables or throw a hidden retry-only exception.

## Settings fields carried by this contract

The settings store is generic; current durable keys include, among others:

| Key | Shape / purpose |
|---|---|
| `vehicleProfiles` | per-vehicle tax-method election profiles |
| `activeVehicleId` | current vehicle profile reference |
| `insuranceSplitMigrationDone` | one-time insurance migration marker |
| `insuranceMigrationBackupKeys` | retained migration snapshot index |
| `insuranceMigrationBackup_<timestamp>` | pre-mutation insurance category snapshots |
| `vanProfile` | configurable cargo dimensions/payload used by fit checks |

These keys are covered through the settings-store backup/restore path; no separate store is required. Secret exclusions above still apply.

## Expense field carried by this contract

`expenses.insuranceBucket` (`A | B | C | undefined`) travels with its parent expense record and is therefore covered by the `expenses` store contract.

## Verification

The release suite must continue to exercise the real shared paths, not helper-only substitutes. For v24.0.2 that includes:

- full backup → delta(s) → wipe → restore;
- settings, receipts metadata, gpsLogs, lifecycle, and normalized-evidence preservation;
- confirmed delta-gap warning behavior;
- zero-change delta push;
- stale lifecycle/evidence downgrade protection;
- `sourceRefs` de-duplicated union;
- scalar/provenance pairing on cloud restore;
- local JSON protected-record revision reconciliation;
- exact no-op evidence re-import;
- lifecycle/evidence protected-checksum mutation detection;
- legacy payload compatibility with absent lifecycle/evidence sections.

Relevant regression coverage includes `tests/integration/backup-restore-parity.spec.mjs`, the v24.0.2 release-integrity/blocker specs, and the M7 automated certification preflight. A green repository suite proves code-side behavior only; final completion certification still requires live Cloudflare and physical-device gates recorded against the exact release SHA.
