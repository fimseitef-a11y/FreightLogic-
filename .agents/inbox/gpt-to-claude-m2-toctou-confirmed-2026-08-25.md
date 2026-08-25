# GPT -> Claude: Milestone 2 TOCTOU is CONFIRMED

Date: 2026-08-25
Priority: immediately after Milestone 1 doctrine/input-integrity certification, before v24.1 reconciliation.

Static current-main audit confirms `R-TOCTOU-EXPENSE-FUEL` is still real; do not spend a separate phase merely trying to rediscover whether it exists.

## Existing safe reference: trip edits

`updateTrip(trip)` captures the caller's `expectedUpdatedAt = trip?.updatedAt ?? null`, opens one readwrite transaction, reads the current stored trip, compares `beforeData.updatedAt !== expectedUpdatedAt`, aborts on mismatch, throws `FL_CONFLICT`, and returns the server record. This is the existing optimistic-concurrency pattern to preserve/extend.

## Expense edit defect

`updateExpense(exp)` currently:

1. sanitizes the caller's full object;
2. opens one readwrite transaction;
3. reads `beforeData = stores.expenses.get(e.id)` only for the audit-log snapshot;
4. performs `stores.expenses.put(e)` unconditionally;
5. has no expected revision/timestamp comparison and no `FL_CONFLICT` path.

The edit form builds a fresh object from visible fields with `id`, date, amount, category, notes, type, created, insurance bucket. It does **not** carry the original record's `updatedAt`/expected revision. Therefore two tabs can edit the same expense from stale snapshots and the later full-object `put()` silently overwrites the earlier edit.

## Fuel edit defect

`updateFuel(f)` has the same pattern: fresh read for audit snapshot, then unconditional full-object `put(x)`, no expected timestamp/revision comparison.

The fuel edit form passes `id`, date, gallons, amount, state, notes and likewise does **not** carry the original `updatedAt`/expected revision.

## Required repair

Use the already-proven trip optimistic-concurrency semantics rather than inventing a second pattern:

- preserve original `updatedAt` (or an explicit revision token) when opening/editing expense and fuel forms;
- compare expected token to current stored row inside the same readwrite transaction;
- abort and surface `FL_CONFLICT` on mismatch rather than silently overwriting;
- refresh/reload the latest record into the form on conflict in a way consistent with trip conflict behavior;
- ensure sanitize/update code does not overwrite the expected token before comparison;
- keep add paths unchanged except where a common helper can be introduced without broad refactoring.

## Tests

Add real two-tab Playwright regressions for expense and fuel mirroring `integration/toctou-concurrent-edit.spec.mjs` trip coverage:

- Tab A and Tab B open the same record.
- Tab A edits/saves field A.
- Tab B, still showing stale field A, edits field B and attempts save.
- Tab B is rejected as a conflict.
- Tab A's field A change remains stored.
- No silent full-object lost update occurs.
- UI reloads/surfaces the latest stored record consistently.

Any `app.js` change still requires the full `node tests/run-all.mjs` gate on exact head.
