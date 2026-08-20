# Backup Contract

Started in Phase 1 of v23.9 "Trust & Recovery" (Amendment 2) and completed in Phase 4
(X-01/X-07). This document is the single list of what `cloudPushBackup()` uploads and
what a restore (`cloudPullBackup()` → `mergeRestoreData()`) is required to bring back.

## Rule

**Every store or settings field `cloudPushBackup()` uploads must be restorable by
`mergeRestoreData()`.** Credentials are the only documented exception (see below). If a
phase adds a new persisted field, it must be added to this document, included in the
push payload, handled by the merge/restore path, and covered by the Phase 4 restore
E2E test (`tests/integration/backup-restore-parity.spec.mjs`) in the same commit that
introduces the field — not deferred to a later cleanup pass.

## Credentials exception

`cloudPushBackup()`'s `settings` dump is a full-store dump — it does not allowlist
fields the way `exportJSON()` does. Two keys are secrets, not user data, and must never
round-trip through cloud backup at all:

- `fmcsaApiKey`
- `eiaApiKey`

**Status as of Phase 1: this exception is not yet enforced on the push side.**
`cloudPushBackup()` currently uploads the raw `dumpStore('settings')` result verbatim,
which includes these two keys if set — unlike `exportJSON()`, which already strips them
(`app.js:1374`, the fix target of X-05 in Phase 3). Fixing `cloudPushBackup()` to strip
the same two keys before upload is in scope for Phase 4 alongside the rest of the
restore-path work, tracked here so it isn't lost. Until that lands, treat cloud backup
as carrying these two keys the same way a pre-Phase-3 JSON export did.

## Store-level contract

| Store | Pushed by `cloudPushBackup()`? | Restored by `mergeRestoreData()`? |
|---|---|---|
| `trips` | Yes | Yes |
| `expenses` | Yes | Yes |
| `fuel` | Yes | Yes |
| `laneHistory` | Yes | Yes |
| `weeklyReports` | Yes | Yes |
| `reloadOutcomes` | Yes | Yes |
| `bidHistory` | Yes | Yes |
| `documents` | Yes | Yes |
| `gpsLogs` | Yes | **No — X-07, fixed Phase 4** |
| `settings` | Yes (whole store, unfiltered) | **No — X-07, fixed Phase 4** |
| `receipts` | Yes | **No — X-07, fixed Phase 4** |
| `receiptBlobs` (Cache API, not IDB) | No | No — out of scope; receipts metadata round-trips, blob bytes do not |
| `auditLog` | No | No — intentionally local-only, not part of the backup contract |

## Settings fields added in Phase 1 (X-02/X-03)

All of the following live in the existing `settings` store (keyPath `key`) — no new IDB
object store, no `DB_VERSION` bump. They are pushed today (full-store dump) but **not
yet restorable** until Phase 4 fixes `mergeRestoreData()` to cover `settings` at all.

| Key | Shape | Purpose |
|---|---|---|
| `vehicleProfiles` | `Array<{ id, label, vehicleTaxMethod, firstYearElection, createdAt }>` | Per-vehicle tax-method election (X-03). `vehicleTaxMethod` ∈ `UNSET \| STANDARD_MILEAGE \| ACTUAL_EXPENSE`; `firstYearElection` ∈ `UNKNOWN \| ACTUAL_EXPENSE \| STANDARD_MILEAGE`. |
| `activeVehicleId` | string | Points at the currently-active entry in `vehicleProfiles`. |
| `insuranceSplitMigrationDone` | boolean | Set once the one-time insurance-category migration has run; skips the boot-time re-scan. |
| `insuranceMigrationBackupKeys` | `string[]` | Index of retained pre-migration snapshot keys (see next row) — lets a future revert tool find them without a full settings scan. |
| `insuranceMigrationBackup_<timestamp>` | `Array<{ id, category, insuranceBucket }>` | One retained snapshot per migration run, written **before** mutating (Amendment 3). Consumed by `revertInsuranceCategorySplit(key)`. Never auto-deleted — small (one row per affected expense, three fields each). |

## Expense record field added in Phase 1 (X-03)

| Field | Store | Shape | Purpose |
|---|---|---|---|
| `insuranceBucket` | `expenses` | `'A' \| 'B' \| 'C' \| undefined` | Explicit auto (A, vehicle-operating) vs. cargo/liability/occ-acc (B, always deductible) vs. unresolved (C, excluded + flagged) split for insurance-category expenses. `undefined` for any non-insurance expense. See `classifyExpenseTaxBucket()` in `app.js`. |

This field travels with its parent `expenses` record, so it is already covered by the
existing `expenses` push/restore path (both Yes above) — no separate contract entry
needed beyond documenting its shape here.

## Fields to be added in Phase 7

Updated in the same commit each Phase 7 sub-phase lands, per Amendment 2. Placeholder
until then:

- **7A** (concept tags: OPERATIONAL vs. TAX) — pending inventory approval (Amendment 5)
  before implementation; fields TBD.
- **7D** (van dimensional/payload profile) — pending Phase 7 implementation; fields TBD.

## Verification

`tests/integration/backup-restore-parity.spec.mjs` (added in Phase 4) must assert, at
minimum: a full backup → wipe local data → restore round-trip preserves every store
in the "Yes/Yes" rows above, **and**, once Phase 7 lands, the Phase 1 fields
(`vehicleProfiles`, `activeVehicleId`, `insuranceBucket` on expense records) and every
Phase 7 field added to this document. Phase 7 must not be marked closed until that
assertion is green.
