# Backup Contract

Started in Phase 1 of v23.9 "Trust & Recovery" and maintained as the single normative list of what `cloudPushBackup()` uploads and what `cloudPullBackup()` → `mergeRestoreData()` must restore.

Current application contract: **FreightLogic v24.0.9 / IndexedDB v15 / Worker v15**.

## Rule

**Every persisted store or settings field uploaded by `cloudPushBackup()` must be restorable by `mergeRestoreData()`.** Credentials are the only documented exception. Any release that adds a durable store/field must update this document, push/export coverage, merge/restore coverage, integrity coverage when protected, and regression tests in the same release.

A restore must preserve newer local protected history. For revisioned records, import/restore is reconciliation, not blind overwrite. Scalar values and their provenance must travel together.

## Credentials exception

Cloud backup and `exportJSON()` exclude these secret settings:

- `cloudBackupToken` — the driver's bearer credential for this Worker
- `cloudAdminTokenEnc` — **v24.0.13.** The admin token at rest: an AES-GCM envelope
  (`{encrypted, iv, salt}`) keyed by PBKDF2 over the device PIN. It is excluded even
  though it is ciphertext rather than plaintext. It grants create/list/revoke over
  **every** driver account, and a portable payload that carries it moves the most
  powerful credential in the system to wherever that payload lands.
- `appLockPin` — PBKDF2 hash of the device PIN
- `appLockFailCount`, `appLockLockedUntil` — device-local lockout state
- `fmcsaApiKey`
- `eiaApiKey`

The exclusion is enforced by one policy — `isSettingExportSafe()` /
`exportSafeSettings()` (`app.js`, v24.0.4) — consumed by local export, cloud full
backup, cloud delta **and every checksum computed over settings**. It withholds a key
named above **or** whose name matches the credential pattern, so a secret added in a
future release is withheld by default rather than by memory.

### The import direction is a separate, narrower gate (Issue #219)

Export-side stripping governs what a payload **emits**; it never governed what a
payload is **allowed to install**. Until Issue #219 the local JSON import
allow-list admitted `cloudBackupToken`, `cloudBackupUrl`, `appLockPin`,
`fmcsaApiKey` and `eiaApiKey`, and wrote them through a blind `put()` — so a
crafted file fed to "Import Data" could repoint every later backup at another
endpoint with another bearer token, or replace the device PIN hash.

`isSettingImportSafe()` is now the gate for both portability inbound paths (local
JSON import, and the add-only settings merge in `mergeRestoreData()`). It is
deliberately **strictly narrower** than `isSettingExportSafe()`:

| Key | Exported / backed up | Accepted from an import |
|---|---|---|
| every secret in the list above | No | No |
| `cloudBackupUrl` | **Yes** — it is not a secret | **No** — it is endpoint authority |
| `appLockEnabled` | Yes | **No** — an import may not switch the lock off |
| ordinary preferences | Yes | Yes |

The asymmetry is the point and must not be "simplified" away. `cloudBackupUrl`
is safe to back up and unsafe to accept, because `cloudGetConfig()` reads it
back: an imported value silently redirects every subsequent backup and restore.
Nothing is lost by refusing it — absent the setting, the hardcoded
`CLOUD_WORKER_URL` still applies, and the passphrase and bearer token are not in
any payload and must be re-entered on a new device regardless.

Import-safe is a strict subset of export-safe, and
`integration/import-credential-trust-boundary.spec.mjs` ICT-06 asserts that
relation directly rather than key by key, so a key added to one gate cannot
quietly widen the other.

Both halves matter together. The filtered array must be the array that is
checksummed: computing `checksumFull` over an unfiltered dump while shipping a
filtered payload is the X-05 defect, where every honest export failed its own
integrity check on import. Filter first, then checksum.

No backup/import path may re-introduce any of them from an export payload.
`cloudAdminTokenEnc` is deliberately **absent from `ALLOWED_SETTINGS_KEYS`**, so an
import silently drops it: an admin credential must never arrive from a file.

## Store-level contract — current through v24.0.13 / DB v15 / Worker v18

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
| `settings` | Yes | Yes | Yes | Secret keys filtered on the way out; `isSettingImportSafe()` gates the way back in (Issue #219). Merge remains conservative/additive unless a setting has an explicit newer contract. |
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

## `normalizedEvidence` contract — current through v24.0.9 / DB v15

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

v24.0.2 introduced/retained the legacy `checksumFull` compatibility path and the current `checksumProtected` coverage. v24.0.9 keeps that contract unchanged. Current-generation integrity coverage includes at least:

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
| `driverDisplayName` | **v24.0.13.** The driver's name as recorded on the invite, written once by a successful claim. Ordinary non-secret settings data: backed up, restored, and admitted by the local JSON import allow-list. |
| `planningAvgMph` | optional operator-set pickup-planning average speed for v24.0.9 feasibility checks; valid runtime range 5–85 mph. There is deliberately no default. Missing/cleared means the gate is inapplicable and restore/import must never invent or clamp a value. |

These keys are covered through the settings-store backup/restore path; no separate store is required. `planningAvgMph` is also explicitly admitted by the local JSON import allow-list introduced with v24.0.9, so export/import may preserve a real operator-set value while an absent value stays absent. Secret exclusions above still apply.

## Expense field carried by this contract

`expenses.insuranceBucket` (`A | B | C | undefined`) travels with its parent expense record and is therefore covered by the `expenses` store contract.

## Verification

The release suite must continue to exercise the real shared paths, not helper-only substitutes. For the current v24.0.9 / DB v15 candidate that includes:

- full backup → delta(s) → wipe → restore;
- settings, receipts metadata, gpsLogs, lifecycle, and normalized-evidence preservation;
- preservation of explicit durable settings such as `planningAvgMph` without manufacturing missing settings;
- confirmed delta-gap warning behavior;
- zero-change delta push;
- stale lifecycle/evidence downgrade protection;
- `sourceRefs` de-duplicated union;
- scalar/provenance pairing on cloud restore;
- local JSON protected-record revision reconciliation;
- exact no-op evidence re-import;
- lifecycle/evidence protected-checksum mutation detection;
- legacy payload compatibility with absent lifecycle/evidence sections.

Relevant regression coverage includes `tests/integration/backup-restore-parity.spec.mjs`, the v24.0.x release-integrity/blocker specs, the v24.0.9 pickup-feasibility/UNKNOWN-setting coverage, and the M7 automated certification preflight. A green repository suite proves code-side behavior only; final completion certification still requires live Cloudflare and physical-device gates recorded against the exact release SHA.

## DB16 stable trip identity (v24.0.14 repair candidate)

`orderNo` is external evidence, not a unique internal identity. DB16 keeps the legacy `trips` store for rollback but routes logical trip operations to `tripRecords`, keyed by stable internal `id`, with a non-unique `orderNo` index. Pre-DB16 rows whose paid/unpaid provenance cannot be proven migrate with payment status UNKNOWN until the operator explicitly marks them.
