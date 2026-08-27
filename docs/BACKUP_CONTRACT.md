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

`cloudPushBackup()`'s `settings` dump does not allowlist fields the way `exportJSON()`
does — it filters out exactly two secret keys, the same two `exportJSON()` strips
(`app.js:1374`, X-05):

- `fmcsaApiKey`
- `eiaApiKey`

**Fixed in Phase 4.** `cloudPushBackup()` previously uploaded the raw
`dumpStore('settings')` result verbatim, including these two keys if set. It now
filters them the same way `exportJSON()`'s `exportableSettings` does (Phase 3, X-05) —
one pattern, two call sites, both correct.

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
| `gpsLogs` | Yes | **Yes — X-07, fixed Phase 4** (dedup on `tripTrackingId`+`timestamp`; incoming numeric `id` never used as a write key — see `mergeRestoreData()`) |
| `settings` | Yes (secrets filtered — see above) | **Yes — X-07, fixed Phase 4** (add-only: a key already present locally is never overwritten, since settings carry no revision timestamp to compare against — see `mergeRestoreData()`) |
| `receipts` | Yes | **Yes — X-07, fixed Phase 4** (file-list union by file `id`; blob bytes still not part of this contract, only the metadata pointer) |
| `receiptBlobs` (Cache API, not IDB) | No | No — out of scope; receipts metadata round-trips, blob bytes do not |
| `auditLog` | No | No — intentionally local-only, not part of the backup contract |

## `loadLifecycle` (v24.2, DB v14)

**Required runtime contract.** PR #105 introduced `loadLifecycle` on `main`, but post-merge source review reopened M4 certification because the live delta path, real JSON import path, lifecycle checksum coverage, and other lifecycle-integrity paths still require a corrective hotfix. The table below is the behavior the runtime must satisfy; presence of the store on `main` is not by itself evidence that the contract is certified.

| Property | Value |
|---|---|
| keyPath | `lifecycleId` (stable, generated, independent of broker order numbers) |
| Pushed in full backup | yes |
| Pushed in delta | yes — changed rows selected by `updatedAt > lastSynced` |
| Restored | yes |
| Merge strategy | **by `lifecycleId`, resolved on `revision` then `updatedAt`; `sourceRefs` merged as a de-duplicated union** |

Why the union rather than last-writer-wins: a full backup and a later delta can
each carry a *partial* `sourceRefs` list for the same load. Taking the winner's
list wholesale would silently drop links that only exist in the loser — so the
reference arrays are unioned even though the scalar state fields are not.

`createdAt` takes the earliest of the two; `revision` takes the highest. An
older delta therefore cannot roll a newer confirmed state backwards.

A payload with no `loadLifecycle` key at all is valid legacy input (any backup
written before v24.2) and must never be treated as corruption.

Required verification on the corrected M4 head includes lifecycle export/import idempotence through the real user-facing import path, full+delta source-reference union, stale-delta downgrade protection, lifecycle-only integrity-check coverage, and pre-v24.2 payload compatibility. The dedicated M4 lifecycle spec may cover those cases, but `tests/integration/backup-restore-parity.spec.mjs` must also continue to prove the shared backup/restore path remains intact.

## X-01: delta sync is now actually read back

`cloudPushBackup()` writes a delta (`POST /backup/delta`) whenever the base full backup
is recent and the changed-record count is small; `cloudPullBackup()` previously only
ever fetched the last full snapshot (`GET /backup`) and never read deltas back — every
delta synced after the last full backup was silently unreachable on restore. Fixed:
`cloudPullBackup()` now also calls `GET /backup/delta` (new in Worker v11), applies
every currently-retained delta **in chronological order** on top of the base snapshot
via `mergeRestoreData()`, and distinguishes two non-silent outcomes when full coverage
can't be proven:

- **Confirmed gap** — the Worker's delta pointer tracks a lifetime `totalCreated`
  counter alongside the currently-retained `keys`; when `totalCreated > retainedCount`,
  some deltas were evicted (the 20-key cap or the 7-day TTL) and coverage is provably
  incomplete.
- **Unverifiable** — the `/backup/delta` request itself failed, or a delta payload
  couldn't be decrypted/parsed; coverage cannot be proven either way.

Both surface a visible `⚠️ Partial restore — …` toast (never a silent "Cloud backup
restored!") — see `cloudPullBackup()`/`cloudFetchDeltas()` in `app.js`.

## Settings fields added in Phase 1 (X-02/X-03)

All of the following live in the existing `settings` store (keyPath `key`) — no new IDB
object store, no `DB_VERSION` bump. As of Phase 4 they are both pushed and restorable
(add-only merge — see the store-level contract above).

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

## Fields added in Phase 7

Updated in the same commit each Phase 7 sub-phase lands, per Amendment 2.

### 7D — van profile (`settings['vanProfile']`)

| Key | Shape | Purpose |
|---|---|---|
| `vanProfile` | `{ cargoLengthIn, cargoWidthIn, cargoHeightIn, doorWidthIn, doorHeightIn, payloadLbs }` (all numbers) | Configurable van dimensions/payload for the pre-economics fit check (`checkVanFit()`). Defaults to published 2016 Ford Transit T250 148" figures (`VAN_PROFILE_DEFAULT` in `app.js`) until the driver edits Settings → Van Profile. |

Lives in the existing `settings` store — no new IDB object store, no `DB_VERSION` bump.
Already covered by the existing push/restore path with no additional code: `cloudPushBackup()`'s
`settings` dump is a full-store dump (secrets excepted, see above) so `vanProfile` is
included automatically, and X-07's add-only settings merge in `mergeRestoreData()` handles
any settings key generically — no per-key special-casing was needed for this field.

- **7A** (concept tags: OPERATIONAL vs. TAX) — pending inventory approval (Amendment 5)
  before implementation; fields TBD.
- **7B** (recovery verification) — TBD, this phase not yet implemented.
- **7C** (health/release badge) — TBD, this phase not yet implemented.

## Verification

`tests/integration/backup-restore-parity.spec.mjs` (added in Phase 4) asserts a full
backup → 3 delta syncs → wipe local data → restore round-trip preserves trips (base +
all 3 deltas), settings, receipts, and gpsLogs, and separately that a confirmed delta
gap (simulated pruning) surfaces the visible partial-restore warning instead of a
silent success. Uses `tests/lib/mock-worker.mjs` (a local stand-in for the Worker's
KV-backed endpoints — see that file's header comment for why: this environment has no
live Cloudflare Worker to test against). Full run: 4/4 passing.

Once Phase 7 lands, this test (or a follow-up in the same commit) must also cover the
Phase 1 fields (`vehicleProfiles`, `activeVehicleId`, `insuranceBucket` on expense
records — already covered structurally since `expenses`/`settings` round-trip, but
worth a direct assertion) and every Phase 7 field added to this document. Phase 7 must
not be marked closed until that assertion is green.
