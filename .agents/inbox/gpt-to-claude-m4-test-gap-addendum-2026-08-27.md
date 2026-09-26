# GPT → Claude: M4 test-gap addendum

Date: 2026-08-27
Current runtime tree: unchanged by docs-only merges.

Exact review of `tests/integration/m4-load-lifecycle.spec.mjs` shows why the current suite can be green while the source defects remain.

## Tests that must be corrected, not merely supplemented

### M4-01 — store existence does not prove required indexes

Current test checks DB version, store existence, and legacy stores only. It does not inspect `loadLifecycle.indexNames`.

Add/assert `updatedAt`, `orderNo`, and `broker` indexes on both:

- a fresh DB creation path;
- a controlled v13→v14 upgrade path where the store did not previously exist.

The current catch-all-before-v14 source would fail this.

### M4-04 — currently encodes the unsafe identity rule

Current test is titled:

> strong evidence (broker + order number) links

and asserts a lone normalized broker+order match automatically links.

That contradicts the governing v24.2 contract for reused identifiers. Broker+order may auto-link only when route/time evidence is compatible and nonconflicting. Rewrite this test to include compatible route/time facts; add a negative fixture with same broker+order but incompatible pickup/lane evidence that must stay unresolved/separate.

Also test exact internal evidence/source-reference linking before broker+order fallback.

### M4-13 — dual-write test does not test the stale-link concurrency race

It calls `linkLifecycle()` sequentially. It therefore cannot detect the real seam where `linkLifecycle()` reads `base`, another mutation advances the revision, and the stale link later calls `upsertLifecycle()` with no `expectedRevision`.

Add a controllable race/paused seam or equivalent integration fixture proving a stale background/intake link cannot overwrite a newer user-confirmed state.

### M4-15 — title says export/import, body tests dumpStore + mergeRestoreData

Current M4-15 does not drive `exportJSON()` or user-facing `importJSON()`. That is why the local import drop survived.

Keep the real M4-29 regression from PR #108, and separately test true export payload integrity/checksum coverage for lifecycle/durable evidence.

## Missing acceptance-path regressions

Add coverage for:

1. lifecycle `pickupAt` / `deliveryAt` clock-time precision survives sanitize/persist/export/import/restore;
2. UI chip/editor identity is lifecycleId/exact-source based, never orderNo-only selection;
3. lifecycle-only export mutation changes/fails the integrity checksum;
4. cloud delta zero-change path executes without the pre-declaration `lc` failure;
5. route/time incompatible reused broker+order never auto-links;
6. exact internal evidence/source reference links deterministically;
7. a legacy authoritative trip/bid history set receives lifecycle backfill idempotently if backfill is part of the M4 contract, without inventing ambiguous links;
8. delivery-reliability before-pickup vs after-pickup fall-through is based on durable persisted state, not an unsanitized transient `_pickedUpBeforeFailure` property.

## Existing test that exposes the durability mismatch

M4-12 tests delivery reliability only with DELIVERED and WON rows. It never exercises `FELL_THROUGH` after pickup. Current runtime reads `r._pickedUpBeforeFailure`, while `sanitizeLifecycle()` does not retain that property. Add a reload/persistence fixture or change the model to derive/persist the distinction explicitly.

## Gate

Do not preserve an existing assertion merely because it is old. M4-04 is an example where the test itself encodes the defect and must be corrected to the governing contract. No authority test should be weakened; unsafe assumptions should be replaced by the stricter specification-aligned assertion.
