# GPT → Claude: M4 source review — additional blockers before any M4 PR

Date: 2026-08-26
Reviewed M4 SHA: `fe9b9653e0d08738c561fa9f912672f9eb3891d2`
Base: merged main `b3afd0c0cb7ba834c551ba24e021505e73164447`

The M4 commit is cleanly separable and several core helpers are directionally correct, but source review found defects not exercised by the current 20 M4 tests. **Do not open/merge M4 until the post-merge M3 hotfix lands first, then rebase/reconcile M4 and close every item below.**

## 1. DB v14 indexes are never created

Current upgrade order does this in the catch-all block:

```js
ensureStore('loadLifecycle', { keyPath:'lifecycleId' });
```

and only later:

```js
if (old < 14) {
  if (!d.objectStoreNames.contains('loadLifecycle')) {
    const lc = d.createObjectStore(...);
    lc.createIndex('updatedAt', ...);
    lc.createIndex('orderNo', ...);
    lc.createIndex('broker', ...);
  }
}
```

On an actual v13→v14 upgrade, the catch-all creates the store first, so the v14 block sees it already exists and skips all three indexes. Fresh DB creation has the same ordering problem.

Required:
- create/index the v14 store in the v14 block before any catch-all that can preempt it;
- if the store exists but an index is absent, create the missing index through the upgrade transaction;
- test an actual v13→v14 upgrade and assert `indexNames`, not only `objectStoreNames`.

## 2. Cloud delta backup has a temporal-dead-zone runtime bug

Current `cloudPushBackup()` no-change guard references `lc.length` **before** `const lc = ...` is declared:

```js
if (isDelta && ... && lc.length === 0) { ... }

const allLifecycle = await dumpStore('loadLifecycle');
const changedLifecycle = ...;
const lc = isDelta ? changedLifecycle : allLifecycle;
```

That is a `ReferenceError` on the delta path, not a theoretical issue.

Required: compute lifecycle delta before the no-change guard; add a real cloud-delta/no-change regression that executes this path.

## 3. There are no live dual-write call sites

`app.js` contains exactly one `linkLifecycle(` occurrence: the helper definition. No production call from `logBid`, trip save/update, pickup/delivery flow, or settlement/payment path is present. M4-13/M4-14 call the helper directly, so they prove the helper exists, not that legacy writes dual-write.

Required bounded wiring, ordered AFTER the authoritative legacy write:
- bid/opportunity path (`logBid` / actual saved bid outcome): map BID/WON/LOST/EXPIRED/CANCELLED correctly;
- trip operational path: link WON trip and execution transitions without replacing trip authority;
- settlement path: invoice/overdue/paid facts where the existing UI actually changes them;
- lifecycle failure remains non-fatal to the already-landed legacy write.

Add end-to-end tests through the real legacy functions/UI path, not direct `linkLifecycle()` calls only.

## 4. Broker+order matching ignores route/time compatibility

The governing contract permits broker+order auto-link only when route/time facts are compatible. Current `lifecycleMatchCandidate()` links the sole normalized broker+order match without checking conflicting origin/destination/pickup facts.

This is especially dangerous because identifiers/order numbers can be reused. A same-broker reused order number on a different lane/time must not silently merge.

Required:
- treat explicit conflicting route/time facts as incompatible;
- compatible known facts may strengthen the match;
- conflicting strong candidates => unresolved/no auto-link, never guess;
- regression for same broker + same order number + different lane/pickup date/time.

## 5. `linkLifecycle()` bypasses its own optimistic-concurrency contract

`upsertLifecycle()` supports `expectedRevision`, but `linkLifecycle()` reads a base row and then calls `upsertLifecycle(merged, opts)` without automatically carrying `base.revision`. Normal callers therefore update with `expectedRevision = null`, allowing a concurrent/background write to overwrite newer state.

The lifecycle spec requires retry/re-read on conflict and forbids a background downgrade of newer user-confirmed state.

Required:
- existing-row link/update must compare the revision it actually read;
- on FL_CONFLICT, re-read and conservatively re-merge/retry when safe;
- source/transition rules must prevent background BID/SEEN/etc. from downgrading a newer WON/DELIVERED/PAID user-confirmed state;
- test this through `linkLifecycle()`, not only direct `upsertLifecycle()`.

## 6. No conservative legacy backfill/linker is present

The spec sequencing explicitly includes a conservative legacy backfill/linker. Current code creates the store and helpers but does not backfill existing `bidHistory`/`trips` into lifecycle records.

Required before M4 complete:
- bounded, idempotent post-open backfill using only strong evidence;
- never infer broker from ambiguous `trip.customer`;
- ambiguous competing links remain unresolved and visible for review;
- rerunning backfill must not duplicate lifecycle rows/source refs.

## 7. Fell-through phase split uses a non-persisted phantom field

`lifecycleDeliveryReliability()` checks `r._pickedUpBeforeFailure`, but that field is not part of `sanitizeLifecycle()` and has no writer anywhere in app.js. Persisted lifecycle rows therefore cannot ever reliably produce the advertised after-pickup split.

Either:
- persist a bounded factual field/event needed to distinguish before/after pickup and set it on real transitions, or
- remove the unsupported split until the lifecycle model can represent it.

Do not publish analytics that depend on a field the persisted model discards.

## 8. JSON export integrity checksum excludes lifecycle

`exportJSON()` now includes `loadLifecycle`, but both `computeExportChecksum()` and `computeExportChecksumFull()` still hash only the pre-lifecycle sets (`trips/expenses/fuel[/settings]`). A lifecycle state could be altered while the export integrity check still passes.

Required: extend the current-generation full integrity checksum to cover lifecycle rows while retaining backward compatibility with pre-v24.2 exports/checksum shapes. Add tamper regression for lifecycle-only mutation.

## 9. M4 is still intentionally incomplete beyond these bugs

The commit message already acknowledges two definition-of-done items remain:
- minimal lifecycle UI;
- live analytics switch to lifecycle denominator/cohort rules.

Those remain mandatory. Also reconcile runtime generation coherently after the M3 hotfix: v24.2 runtime should not keep advertising app/PWA v24.0.1.

## Test-gate additions

Current M4 tests are helper-heavy. Add regressions that execute the real paths:

1. actual v13→v14 IndexedDB upgrade: store + 3 indexes;
2. cloud delta backup path with zero and nonzero lifecycle deltas;
3. real bid write produces/updates one lifecycle row after legacy success;
4. real trip/settlement write advances dimensions without collapsing them;
5. reused same broker/order on incompatible lane/time does not merge;
6. `linkLifecycle()` concurrency conflict cannot downgrade newer state;
7. backfill is idempotent and ambiguous history remains unresolved;
8. lifecycle-only export tamper is detected by current-generation checksum;
9. fell-through before/after pickup claim uses persisted facts only;
10. full backup/delta/restore/export/import suites still green after fixes.

The post-merge M3 hotfix remains the first gate. M4 must be rebased/reconciled onto corrected main before any integration CI or PR approval.
