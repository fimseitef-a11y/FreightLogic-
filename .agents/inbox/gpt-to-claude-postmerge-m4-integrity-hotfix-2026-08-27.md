# GPT → Claude: POST-MERGE M4/M3 INTEGRITY HOTFIX — main 754b5c2

Date: 2026-08-27
Current main: `754b5c270ab5671c92f0feddb1a98808ac537d24` (PR #105 merged)
Severity: RELEASE-BLOCKING

PR #105 merged M4 + M5A/5B and reported M4 complete, but exact-current-main source review shows several previously reported blockers were not repaired before merge. The green 225/0 suite did not exercise these execution paths. Do not treat M4 or the completion release as certified until these are fixed and regression-tested on a hotfix branch from current main.

## A. Post-M3 hotfix still missing

Current `app.js` still reports `APP_VERSION = '24.0.1'` while v24.1 Confidence + Evidence is merged. Current Worker is still v12.

Worker `/evaluate` still rejects a valid canonical `UNAVAILABLE` decision because its request gate requires a finite canonical True RPM and a bid range. M1/M3 deliberately make True RPM null and suppress the bid range when material facts are unknown. The Worker must preserve/explain that canonical UNAVAILABLE state rather than reject it or manufacture zeroes.

Required:
- app/PWA/cache/release generation reconciled coherently for the v24.1+ runtime;
- Worker v13 (or later) projection semantics;
- `/evaluate` accepts canonical UNAVAILABLE / unknown grade / null True RPM / suppressed bid and projects those fields without coercion;
- confidence labels remain client-owned/descriptive only;
- explicit regressions for UNAVAILABLE projection and no null→0 conversion.

## B. M4 current-main blockers

### 1. DB v14 indexes are not created

`initDB()` catch-all calls `ensureStore('loadLifecycle', ...)` before the `old < 14` block. The v14 block then sees the store already exists and skips `updatedAt`, `orderNo`, and `broker` index creation. This affects real v13→v14 upgrades and fresh databases.

Required: create/repair the store and each missing index through the upgrade transaction; regression must open an actual v13 DB, upgrade to v14, and assert all three `indexNames`.

### 2. Cloud delta path has a TDZ ReferenceError

`cloudPushBackup()` tests `lc.length === 0` before `const lc = ...` is declared. Any qualifying delta execution can throw before upload.

Required: compute lifecycle delta before `isDelta`/no-change guard; execute zero-change and nonzero lifecycle-delta tests through the real cloudPushBackup path.

### 3. Broker+order linker still ignores route/time conflicts

`lifecycleMatchCandidate()` still links the sole normalized broker+order match without checking incompatible origin/destination/pickup/delivery evidence. Reused provider identifiers can therefore false-merge different loads.

Required: compatible known route/time facts are required for broker+order auto-link; conflicting facts => unresolved/no auto-link.

### 4. Exact sourceRefs are still not strong linking evidence

The matcher still does not resolve exact `sourceRefs.bidHistoryIds`, `tripIds`, `reloadOutcomeIds`, or `gpsTrackingIds` before broker/order matching.

Required: one exact sourceRef match auto-links; competing lifecycle rows containing the same exact sourceRef are a diagnostic/corruption state, never an arbitrary pick.

### 5. linkLifecycle still bypasses the revision it read

`linkLifecycle()` reads `base`, merges it, then calls `upsertLifecycle(merged, opts)` without automatically passing `expectedRevision: base.revision`. Normal background dual-write callers therefore do not compare the revision they actually read.

Required: carry expected revision, handle `FL_CONFLICT` by re-read/conservative retry where safe, and never let background SEEN/BID/etc. downgrade newer user-confirmed WON/DELIVERED/PAID state.

### 6. Conservative legacy lifecycle backfill still absent

M4 spec section 16 requires a bounded, idempotent legacy backfill/linker. Current main contains the lifecycle store/helpers/dual-write for future writes, but existing bid/trip history is not migrated into lifecycle under the strong-evidence rules.

Required: post-open idempotent backfill, no `trip.customer` broker guessing, ambiguous candidates stay unresolved/visible, reruns produce no duplicate lifecycle records/sourceRefs.

### 7. Fell-through phase split depends on a non-persisted phantom field

`lifecycleDeliveryReliability()` reads `_pickedUpBeforeFailure`, but `sanitizeLifecycle()` does not persist that field and no real writer establishes it.

Required: either persist a bounded factual phase field/event from real transitions or stop publishing the before/after pickup split until representable.

### 8. Real importJSON still omits loadLifecycle

The user-facing import transaction lists `trips, expenses, fuel, receipts, settings, auditLog, laneHistory, weeklyReports, reloadOutcomes, bidHistory, documents, gpsLogs` — not `loadLifecycle`. Replace mode therefore cannot clear lifecycle deliberately and normal JSON import cannot restore lifecycle rows.

Required: lifecycle sanitizer + merge/replace/skip behavior in the actual importJSON feature; pre-v24.2 files remain valid; test export→real importJSON round trip, not mergeRestoreData as a surrogate.

### 9. Export checksum still excludes lifecycle

`computeExportChecksumFull()` still hashes `{ trips, expenses, fuel, settings }` only. A lifecycle-only mutation is invisible to current-generation integrity verification.

Required: current-generation checksum covers lifecycle while retaining compatibility with pre-v24.2 checksum shapes; lifecycle-only tamper regression.

### 10. Lifecycle timestamps lose time precision

`sanitizeLifecycle()` and M5 `normalizeOpportunity()` validate `pickupAt` / `deliveryAt` through `isValidISODate()`, which accepts only `YYYY-MM-DD`. A supplied ISO date-time is discarded to null, weakening identity/reuse safety.

Required: preserve validated ISO date-time when supplied; retain date-only when that is all that is known; compare strongest shared temporal precision without inventing times.

### 11. New M4 UI still selects by orderNo alone

`renderLifecycleChips()` builds `Map(orderNo -> lifecycle)` and `openLifecycleEditor(orderNo)` returns the first lifecycle with that order number. The project explicitly treats IDs/order numbers as reusable/non-unique. A reused order number can therefore show or edit the wrong lifecycle record.

Required: trip rows/editor carry stable `lifecycleId` or an exact internal `tripId`/sourceRef link; never select a lifecycle row by orderNo alone; if old data cannot resolve uniquely, show unresolved state instead of choosing.

## Required gate before roadmap continues

1. Claim fresh `lock/app-js` covering all touched core/shared paths.
2. Branch from current main `754b5c2` — do not repair an obsolete pre-merge branch.
3. Fix the M3 Worker/version projection integrity first or in the same narrowly scoped hotfix, then M4 blockers above.
4. Add real-path regressions for every repaired issue; do not weaken existing M1–M5 tests.
5. Full `node tests/run-all.mjs` on exact hotfix head plus lane/path/lock and Worker build gates.
6. Re-review exact source head before merge.
7. Only after that may STATUS call M4 certified/completion-release foundation clean.

M5A/5B semantics can remain landed if these repairs do not require changing their revenue-semantic contract. M5C/M5D stay non-blocking exactly as the governing roadmap says.
