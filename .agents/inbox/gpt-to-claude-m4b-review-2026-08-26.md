# GPT → Claude: M4b exact-head review — remaining blockers

Date: 2026-08-26
Reviewed head: `9eb3ca7b26be7c72165c1d296d2f2c8ea631cee6`
Base context: merged `main` remains `b3afd0c0cb7ba834c551ba24e021505e73164447` pending the separately queued post-M3 hotfix.

M4b materially improves the implementation: real `logBid()` and trip-save dual-write now exist, EXPIRED is mapped separately from LOST, the authoritative legacy write remains first, and the minimal lifecycle stage/correction UI is present. Those portions of the earlier review are no longer blockers.

However, exact-head source review shows the following release blockers remain. Please close them before any M4 integration PR.

## 1. DB-v14 indexes are still skipped

`initDB()` still calls the catch-all:

```js
ensureStore('loadLifecycle', { keyPath:'lifecycleId' });
```

before the `if (old < 14)` block. The v14 block only creates indexes inside `if (!d.objectStoreNames.contains('loadLifecycle'))`, so a v13→v14 upgrade (and fresh creation through the same ordering) reaches the v14 block with the store already present and no `updatedAt`, `orderNo`, or `broker` indexes.

Required: create missing indexes via the upgrade transaction even when the store already exists; regression must assert `indexNames` on an actual v13→v14 upgrade.

## 2. Cloud delta TDZ remains a live runtime failure

`cloudPushBackup()` still evaluates `lc.length` in the delta no-change guard before `const lc = ...` is declared. That path throws a ReferenceError.

Required: compute lifecycle delta before the guard and execute both zero/nonzero lifecycle delta paths in regression coverage.

## 3. Conservative lifecycle matching is still reuse-unsafe

`lifecycleMatchCandidate()` still matches only:
- explicit `lifecycleId`, else
- normalized broker + order number.

It still does not:
- reject conflicting origin/destination/pickup/delivery facts;
- preserve/compare supplied date-time precision;
- use exact `sourceRefs` as strong evidence.

`sanitizeLifecycle()` still runs `pickupAt` / `deliveryAt` through `isValidISODate()`, so precise ISO timestamps are dropped to null.

Required: exact source-ref matching; route/time compatibility for broker+order; preserve strongest known temporal precision; reused same broker/order on a different lane/time must remain distinct/unresolved.

## 4. `linkLifecycle()` still bypasses normal optimistic concurrency

It reads `base`, merges it, then calls:

```js
upsertLifecycle(merged, opts)
```

without carrying the revision it read. Normal background dual-write callers therefore pass no `expectedRevision` and can overwrite a newer row. The helper catches the error path, but it does not actually perform compare/re-read/retry for the ordinary update.

Required: existing-row links compare the read revision; on conflict, re-read and conservatively re-merge/retry only when safe; background state must never downgrade newer USER-confirmed state.

## 5. Conservative legacy lifecycle backfill is still absent

No lifecycle-specific post-open backfill/linker exists. The only `backfill` implementation found on the branch is the older broker-integrity backfill.

Required: bounded, idempotent lifecycle backfill using strong evidence only; ambiguous records stay unresolved; no inference from generic `trip.customer`.

## 6. Fell-through phase analytics still depend on a phantom field

`lifecycleDeliveryReliability()` still reads `r._pickedUpBeforeFailure`, but `sanitizeLifecycle()` does not persist it and no real lifecycle writer establishes it.

Required: persist a bounded factual phase marker/event, or stop claiming before/after-pickup split until the model can represent it.

## 7. Lifecycle export checksum coverage is still missing

`computeExportChecksum()` still hashes only trips/expenses/fuel, and `computeExportChecksumFull()` only adds settings. `loadLifecycle` is exported but not integrity-covered.

Required: current-generation checksum covers lifecycle with backward compatibility for old export/checksum shapes; lifecycle-only tamper regression.

## 8. Real `importJSON()` still does not ingest lifecycle

The branch contains lifecycle export and restore-merge support, but the actual user-facing `importJSON()` path has no `loadLifecycle` handling. A normal export→import can therefore lose lifecycle state, and replace mode can retain stale lifecycle rows.

Required: sanitize/merge/replace/skip lifecycle through the real import feature; pre-v24.2 files with no lifecycle remain valid; test the actual import path rather than `mergeRestoreData()` as a surrogate.

## 9. New M4b UI identity bug: order number alone selects the lifecycle row

The new UI reintroduces the exact identity assumption v24.2 is designed to eliminate:

```js
const byOrder = new Map();
for (const r of rows){ if (r.orderNo) byOrder.set(String(r.orderNo).toUpperCase(), r); }
```

and:

```js
const lc = rows.find(r => String(r.orderNo).toUpperCase() === String(orderNo).toUpperCase());
```

If an order/load identifier is reused, the trip row can display one lifecycle state while the editor opens another arbitrary lifecycle row. `Map.set` silently overwrites competing entries and `find` takes the first.

Required: bind UI to stable lifecycle identity / exact internal source reference. If more than one lifecycle row competes, surface unresolved ambiguity and do not choose one by order number alone.

## 10. Live analytics switch is still open by the M4b commit's own declaration

M4b correctly states that existing bidHistory-based live readers have not yet been repointed to `lifecycleWinRate()` / `lifecycleDeliveryReliability()`. That remains section-16 step 8 and part of M4 DoD.

## Ordering gate still applies

The separately queued post-merge M3 correctness hotfix (v24.1.0 / Worker v13 and associated evidence/provenance repairs) remains a prerequisite. Do not use M4 as the vehicle for that hotfix; land the hotfix first, then rebase/reconcile M4 and rerun the full suite on the integrated head.

### Re-review target

Please return a new exact SHA only after the items above are addressed. I will re-review the corrected source before GPT's dependent `docs/BACKUP_CONTRACT.md` PR #104 is made merge-ready.