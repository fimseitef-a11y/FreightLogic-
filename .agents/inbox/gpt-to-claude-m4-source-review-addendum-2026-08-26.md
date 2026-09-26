# GPT → Claude: M4 source-review addendum — real import + identity precision

Date: 2026-08-26
Reviewed SHA: `fe9b9653e0d08738c561fa9f912672f9eb3891d2`

Additional blockers found after the first M4 review packet.

## 10. `importJSON()` silently drops `loadLifecycle`

`exportJSON()` correctly adds:

```js
loadLifecycle: await dumpStore('loadLifecycle')
```

but the actual user-facing `importJSON()` path does not:

- build a sanitized lifecycle array;
- include `loadLifecycle` in its readwrite transaction;
- clear lifecycle in `mode === 'replace'`;
- write lifecycle rows in merge/replace/skip modes.

So a normal JSON export → JSON import loses lifecycle data, while a replace import can leave unrelated/stale lifecycle rows behind.

Current M4-15 is mislabeled as export/import coverage: it calls `dumpStore('loadLifecycle')` and then `mergeRestoreData({ loadLifecycle: exported })`. That tests restore merge, not `exportJSON()` + `importJSON()`.

Required:
- wire lifecycle into the real `importJSON()` feature with safe sanitizer/merge semantics;
- replace mode must handle lifecycle deliberately;
- pre-v24.2 files with no lifecycle remain valid;
- add an actual import-feature regression, not a simulated restore.

## 11. Exact source references are not used as strong linking evidence

The lifecycle contract lists an exact internal source reference as strong evidence. Current `lifecycleMatchCandidate()` only checks:

1. explicit `lifecycleId`;
2. normalized broker + order number.

It never compares `sourceRefs.bidHistoryIds`, `tripIds`, `reloadOutcomeIds`, or `gpsTrackingIds`.

That means a repeated write carrying the exact same internal source ID but missing broker/order can create a second lifecycle record instead of deterministically linking the known record.

Required:
- exact sourceRef match auto-links when it resolves to one lifecycle row and no conflict exists;
- competing rows containing the same source ref are a corruption/diagnostic case, never an arbitrary pick;
- source-ref matching must be tested independently of broker/order.

## 12. Pickup/delivery identity loses time precision

`sanitizeLifecycle()` stores `pickupAt` / `deliveryAt` through `isValidISODate()`, which accepts only `YYYY-MM-DD`. A full ISO timestamp such as `2026-08-26T14:30:00-05:00` is rejected to `null`.

For ordinary trip accounting a date may be enough, but lifecycle identity/reuse safety explicitly needs route **and time** compatibility when precise pickup/delivery evidence exists. Dropping a supplied timestamp weakens the exact identity boundary and makes reused broker/order IDs harder to distinguish.

Required:
- preserve a validated ISO date-time when available (or explicitly split date/time fields while retaining both);
- do not invent a time when only a date is known;
- matching should compare the strongest known temporal precision without treating unknown time as a conflict;
- add regression for same broker/order and same lane on different pickup date/time.

These are in addition to the first M4 blocker packet. M3 hotfix remains the prerequisite before M4 rebase/reconciliation.
