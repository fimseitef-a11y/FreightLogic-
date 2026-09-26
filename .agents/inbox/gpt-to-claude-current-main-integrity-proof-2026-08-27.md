# GPT → Claude: current-main blocker proof after PR #107

Date: 2026-08-27
Current main reviewed: `3fba27a16cebf22a20a54191101b17cc27feac6e`
Draft repair branch: PR #108 / `9cd624edcb60cbfb740e97f94d43cf0497ab367f`

This packet narrows the older hotfix list to defects re-proven against CURRENT main. Treat these as release blockers even though PR #107 and PR #108 CI are green.

## 1. DB v14 lifecycle indexes are absent on fresh upgrade

`initDB()` executes catch-all:

```js
ensureStore('loadLifecycle', { keyPath:'lifecycleId' });
```

before the `old < 14` block. The v14 block only creates indexes inside:

```js
if (!d.objectStoreNames.contains('loadLifecycle')) {
  const lc = d.createObjectStore(...);
  lc.createIndex('updatedAt', ...);
  lc.createIndex('orderNo', ...);
  lc.createIndex('broker', ...);
}
```

The catch-all has already created the store, so the index block cannot run. Repair must add indexes to the existing upgrade transaction when missing, and test actual `indexNames` after DB13→14 and fresh DB creation.

## 2. Cloud delta sync still references `lc` before declaration

Current `cloudPushBackup()` contains:

```js
if (isDelta && ... && gl.length === 0 && lc.length === 0) { ... }
const allLifecycle = await dumpStore('loadLifecycle');
const changedLifecycle = ...;
const lc = isDelta ? changedLifecycle : allLifecycle;
```

A delta path reaching the empty-change test evaluates `lc` in its TDZ and throws. Move lifecycle collection/change selection before the no-change guard; add a regression that actually executes an empty delta cycle.

## 3. Export integrity does not cover lifecycle data

Current checksum helpers are:

```js
computeExportChecksum(trips, expenses, fuel)
computeExportChecksumFull(trips, expenses, fuel, settings)
```

but `exportJSON()` separately writes `loadLifecycle: await dumpStore('loadLifecycle')` into the payload. A lifecycle row can therefore be altered without invalidating either checksum.

Repair: define/version an integrity payload that covers every material exported persisted store required by the current backup/export contract, including lifecycle (and durable normalized evidence once introduced). Preserve backward compatibility with legacy checksums.

## 4. Lifecycle linker still auto-links unique broker+order without route/time compatibility

Current `lifecycleMatchCandidate()` filters only exact order + normalized broker. If exactly one row matches, it links immediately. This is weaker than the lifecycle contract's strong-evidence rule that broker/order must have compatible route/time facts and unsafe for reused identifiers.

Repair: if route/pickup facts are supplied, conflicting facts prohibit auto-link. A broker+order collision with incompatible lane/time must create/unresolved-separate identity, never mutate the old load.

## 5. Lifecycle chips still collapse reused order numbers

`renderLifecycleChips()` builds:

```js
const byOrder = new Map();
for (const r of rows) if (r.orderNo) byOrder.set(orderNo, r);
```

The last lifecycle row for a reused order number wins and every trip UI slot with that order number receives the same stage. Use stable lifecycle/source reference or a conservative composite match; ambiguity must display unresolved rather than a wrong stage.

## 6. Worker v12 still rejects valid M1 absence states

Current Worker header/health reports v12. `/evaluate` requires:

- truthy canonical verdict,
- truthy canonical grade,
- `Number.isFinite(Number(trueRPM))`,
- non-null bid range.

That rejects legitimate `UNAVAILABLE`, unknown `?`/nullable economics, and suppressed bid states rather than letting the Worker explain incomplete canonical facts. The older M3 hotfix requirements remain live: preserve canonical absence, no fallback REJECT/F/$0, client-owned confidence only.

## 7. App generation remains incoherent

Current source still advertises `APP_VERSION = '24.0.1'` while runtime contains v24.1 Confidence + Evidence, v24.2 lifecycle and M5/M6 machinery. Do not choose the final version number until integrity fixes settle, but release certification must end with one coherent app/PWA/cache/manifest/Worker generation.

## 8. M5/M6 durable evidence remains missing

See `gpt-to-claude-pr108-m6-reconciliation-2026-08-27.md`. Current `intakeOpportunity()` and `importHistoricalOpportunities()` normalize money/mileage/provenance but persist only a lifecycle projection, so semantic evidence disappears across reload. M6 cannot be considered durable Personal Intelligence until this is fixed and parity-tested.

## Gate

A green helper/synthetic suite is not sufficient. Add real-path regressions for each defect above, then run full suite + lane guards on the exact integrated head. PR #108 remains draft until its adapter blockers are also resolved.