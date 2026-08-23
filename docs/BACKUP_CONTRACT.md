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

## Fields added in v24.1 (Confidence + Evidence)

### `bidHistory[].confidence` — optional evidence snapshot

| Key | Shape | Purpose |
|---|---|---|
| `confidence` | `{ schemaVersion, overall, domains{market,broker,operatingCosts,weatherSafety,vehicleFit}, materialDomains[], items[{key,source,sourceStatus,availability,freshness,sampleSize,confidence}], evaluatedAt }` | Compact snapshot of the evidence behind a logged bid outcome, so the decision can still be explained later. Written by `logBid()` from `confidenceSnapshot()`. |

**Optional and additive.** `bidHistory` keys on `id` and the field carries no index, so
this required **no schema change, no new store, and no `DB_VERSION` bump** — the v24.1
implementation map's persistence boundary is respected, and none of the v24.2 lifecycle
migration budget was consumed to ship confidence labels.

**Backward compatibility runs both ways.** A record written before v24.1 simply has no
`confidence` key and stays fully readable; a record written by v24.1 restores intact
through the existing generic `bidHistory` loop in `mergeRestoreData()` with no
per-field handling. Both directions are asserted by
`tests/integration/v24-1-confidence-authority.spec.mjs` `[V241-A09]`.

**Secret-free by contract.** The snapshot stores source *labels*, status codes, counts,
ages and categorical labels only — never API keys, tokens, or external payloads.
`[V241-A08]` asserts this and caps the snapshot size so it can ride along on every
record.

The same snapshot shape is also written to the session-scoped evaluation history
(`sessionStorage['fl_eval_hist']`), which is not part of the backup contract and is
listed here only so the two writers are documented together.

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
