# Backup Contract

Started in Phase 1 of v23.9 "Trust & Recovery" and maintained as the single normative list of what `cloudPushBackup()` uploads and what `cloudPullBackup()` → `mergeRestoreData()` must restore.

Current application contract: **FreightLogic v24.0.13 / IndexedDB v16 / Worker v18**.

## Rule

**Every persisted store or settings field uploaded by `cloudPushBackup()` must be restorable by `mergeRestoreData()`.** Credentials are the only documented exception. Any release that adds a durable store/field must update this document, push/export coverage, merge/restore coverage, integrity coverage when protected, and regression tests in the same release.

A restore must preserve newer local protected history. For revisioned records, import/restore is reconciliation, not blind overwrite. Scalar values and their provenance must travel together.

## Credentials exception

Cloud backup and `exportJSON()` exclude these secret settings:

- `fmcsaApiKey`
- `eiaApiKey`

No backup/import path may re-introduce them from an export payload.

Worker v18 also tightens the legacy driver-token contract. A legacy v7 plaintext token is migration input only, never durable output: admin listing proactively scrubs any reachable raw token, lazy driver authentication rewrites the matching user record to the hashed-token form, and revoke removes any residual plaintext field before persisting the disabled user. New tokens must never be written back in plaintext.

## Store-level contract — current through v24.0.13 / DB v16

| Store | Full backup | Delta backup | Restored | Contract |
|---|---:|---:|---:|---|
| `tripRecords` (logical backup key `trips`) | Yes | Yes | Yes | Canonical DB16 trip store. `id` is stable internal identity; `orderNo` is a non-unique lookup/index signal and must never be a write key. |
| `trips` (legacy DB15 store) | Migration source only | No new canonical writes | Migrated into `tripRecords` | Retained as the DB15 source during upgrade. Its historical `orderNo` keyPath is not authoritative after DB16. |
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

## DB16 stable-trip identity and migration contract

DB16 fixes a data-loss class in which an external broker/order number could act as the IndexedDB primary key. External identifiers are not guaranteed unique: they can be blank, reused, malformed, or repeated by different sources. Therefore they are evidence for lookup/reconciliation, not identity.

The canonical v24.0.13 trip rules are:

- `tripRecords` uses keyPath `id`, a stable internal trip identity independent of `orderNo`;
- the `orderNo` index is non-unique and may return multiple records;
- creating or importing a trip with a duplicate external order number must not overwrite another shipment;
- blank or missing external order numbers are valid as unknown evidence and must not collapse unrelated records;
- CRUD, restore, merge, and delete operations target the stable internal `id`;
- lookup by `orderNo` is explicitly one-to-many and must be reconciled rather than treated as proof of identity.

### Upgrade from DB15

During the DB15 → DB16 upgrade, each legacy `trips` row is copied into `tripRecords` with a stable internal `id`. Migration must be additive/fail-safe: an existing historical trip may not be discarded merely because its order number is blank or collides with another row. The legacy DB15 store remains the migration source, while post-upgrade runtime access to logical `trips` routes to the canonical DB16 store.

The backup/export payload keeps the logical key `trips` so cloud/local interchange does not require a gratuitous wire-format rename. On v24.0.13/DB16, that logical key represents canonical `tripRecords` data and restore/import must persist by stable `id`.

### Payment-state preservation during migration and restore

`paymentStatusKnown` is part of the truthfulness contract:

- `paymentStatusKnown === true` means the paid/unpaid boolean is backed by explicit state;
- `paymentStatusKnown !== true` means payment status is UNKNOWN;
- missing legacy `isPaid` evidence must remain UNKNOWN, not silently become unpaid;
- receivables/unpaid totals may include only explicit known-unpaid records;
- CSV/export may serialize UNKNOWN distinctly (or leave the paid value blank where the format requires) but must not emit a fabricated `false`.

Restore/import/sanitize paths must preserve this distinction so an old or incomplete payload cannot manufacture debt/receivables.

### Downgrade and rollback warning

DB16 introduces a new canonical store. A runtime rollback to DB15 cannot be assumed to understand trips created or changed only in `tripRecords` after the upgrade. Therefore:

1. before any downgrade from v24.0.13/DB16, create and verify a current-generation export/cloud backup;
2. do not treat the retained legacy DB15 `trips` store as a complete rollback snapshot after DB16 has been used;
3. if rollback is required, preserve the DB16 database/export until forward recovery is proven;
4. a rollback procedure must never delete the DB16 database merely to make an older runtime open successfully.

This is a recovery constraint, not an optional cleanup detail.

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

## `normalizedEvidence` contract — introduced in v24.0.x and retained through v24.0.13 / DB v16

`normalizedEvidence` is the durable evidence layer introduced by the v24.0.2 release-integrity correction. It preserves normalized opportunity facts, semantics, source references, confirmation state, and per-field provenance independently of lifecycle linkage.

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

v24.0.2 introduced/retained the legacy `checksumFull` compatibility path and the current `checksumProtected` coverage. v24.0.13 keeps that contract unchanged. Current-generation integrity coverage includes at least:

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
| `planningAvgMph` | optional operator-set pickup-planning average speed; valid runtime range 5–85 mph. There is deliberately no default. Missing/cleared means the gate and any time-derived Profit/Hour estimate are inapplicable. Restore/import must never invent or clamp a missing value. |

These keys are covered through the settings-store backup/restore path; no separate store is required. `planningAvgMph` is explicitly admitted by the local JSON import allow-list, so export/import may preserve a real operator-set value while an absent value stays absent. Secret exclusions above still apply.

## Expense field carried by this contract

`expenses.insuranceBucket` (`A | B | C | undefined`) travels with its parent expense record and is therefore covered by the `expenses` store contract.

## Verification

The release suite must continue to exercise the real shared paths, not helper-only substitutes. For the current v24.0.13 / DB v16 candidate that includes:

- DB15 → DB16 trip migration with duplicate and blank external order numbers preserved as distinct records;
- stable-id create/edit/delete/restore behavior after migration;
- UNKNOWN payment status preserved through sanitize, import/restore, receivables logic, and export;
- full backup → delta(s) → wipe → restore;
- settings, receipts metadata, gpsLogs, lifecycle, normalized-evidence, and canonical trips preservation;
- preservation of explicit durable settings such as `planningAvgMph` without manufacturing missing settings;
- confirmed delta-gap warning behavior;
- zero-change delta push;
- stale lifecycle/evidence downgrade protection;
- `sourceRefs` de-duplicated union;
- scalar/provenance pairing on cloud restore;
- local JSON protected-record revision reconciliation;
- exact no-op evidence re-import;
- lifecycle/evidence protected-checksum mutation detection;
- Worker v18 legacy plaintext-token cleanup without exposing raw tokens through admin listing;
- legacy payload compatibility with absent lifecycle/evidence sections.

Relevant regression coverage includes `tests/integration/full-repair-regressions.spec.mjs`, `tests/integration/backup-restore-parity.spec.mjs`, `tests/unit/worker-token-rotation.spec.mjs`, the v24.0.x release-integrity/blocker specs, pickup-feasibility/UNKNOWN-setting coverage, and the M7 automated certification preflight. A green repository suite proves code-side behavior only; final completion certification still requires live Cloudflare and physical-device gates recorded against the exact release SHA.
