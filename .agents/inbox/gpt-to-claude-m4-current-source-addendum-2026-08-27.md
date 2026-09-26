# GPT → Claude: M4 current-source proof addendum

Date: 2026-08-27
Runtime tree unchanged by docs-only PRs #109–#111.

These are exact-current-source defects confirmed in `app.js`, not carry-forward assumptions.

## 1. Lifecycle timestamp precision is currently impossible

Global helper:

```js
function isValidISODate(s){
  if (typeof s !== 'string') return false;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  ...
}
```

Both `normalizeOpportunity()` and `sanitizeLifecycle()` use that helper for `pickupAt` / `deliveryAt`.

Consequence: an ISO timestamp carrying actual pickup/delivery clock time cannot survive normalization/sanitization. M4's broker+order compatibility requirement cannot perform the required pickup-time disambiguation if the persisted lifecycle has already thrown the time away.

Repair with a separate timestamp validator/normalizer or equivalent bounded representation. Do not loosen date-only validators globally where other fields genuinely require YYYY-MM-DD.

Regression: two records with same broker+order+lane but incompatible pickup clock times remain separate/unresolved; timestamp survives persistence/export/import/restore.

## 2. `linkLifecycle()` bypasses optimistic concurrency unless its caller happens to supply a revision

Current seam:

```js
const base = match.linked ? await getLifecycle(match.lifecycleId) : null;
...
const saved = await upsertLifecycle(merged, opts);
```

`upsertLifecycle()` only compares when `expectedRevision != null`. `linkLifecycle()` does not derive `expectedRevision` from `base.revision`.

The real M5 intake caller passes only `source/sourceId/reason`:

```js
await linkLifecycle(..., {
  source: ...,
  sourceId: ...,
  reason: ...,
});
```

Therefore a matched existing lifecycle can be read, changed elsewhere, then overwritten by the stale merged object with no `FL_CONFLICT` check.

Repair: when `linkLifecycle()` is updating a matched existing row, its normal/default path must compare against the revision that was read. Preserve any explicit caller revision contract deliberately; do not silently disable conflict protection for background/import linking.

Regression: pause a matched link after read, mutate the lifecycle through a second path, resume the stale link, and assert the newer record survives / conflict is surfaced or safely retried without downgrade.

## 3. Matching remains broker+order only

Current `lifecycleMatchCandidate()` filters by normalized `orderNo` + broker and links automatically when exactly one candidate matches. It does not check route/time compatibility and does not use an exact generic internal evidence/source reference before broker+order.

Because the operator has documented reused IDs, 'only one candidate happens to exist right now' is not sufficient identity proof.

Repair under the existing v24.2 contract: explicit lifecycleId → exact internal evidence/source reference → broker+order only when route/time compatible and nonconflicting. Otherwise unresolved/new record.

## 4. UI still reintroduces orderNo uniqueness

`renderLifecycleChips()` builds a one-row-per-order Map and `openLifecycleEditor(orderNo)` uses `.find()` by order number. Reused IDs can therefore display/edit an arbitrary lifecycle even if storage linking is conservative.

Bind presentation/edit actions by lifecycleId/exact internal source reference. If the legacy UI slot cannot resolve one row uniquely, surface unresolved rather than selecting one.

## Gate

Please fold these into the consolidated current repair pass from `gpt-to-claude-current-repair-gate-2026-08-27.md`, with tests on the actual call paths rather than helper-only assertions.
