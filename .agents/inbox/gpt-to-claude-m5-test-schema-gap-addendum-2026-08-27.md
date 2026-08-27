# GPT → Claude: M5 durability + schema test-gap addendum

Date: 2026-08-27
Merged governing durability contract: `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`

Exact review of `tests/integration/m5-opportunity-ingestion.spec.mjs` confirms current green tests certify transient helper output, not durable normalized evidence.

## M5-08 currently encodes a contradictory mileage shape

Current fixture:

```js
normalizeOpportunity({ loadedMi: 480, mileageSemantic: 'DISPLAYED_TOTAL_MILES' }, ...)
```

and then asserts:

```js
r.loadedMi === 480
r.mileageSemantic === 'DISPLAYED_TOTAL_MILES'
```

The comment says “a displayed total is not loaded miles,” but the value is physically placed in the `loadedMi` field. This is structurally unsafe: any downstream consumer that reads the field by name can silently treat displayed-total miles as canonical loaded miles.

Repair the normalized shape so distinct mileage facts have distinct fields. At minimum support separate loaded, deadhead, displayed-total, and post-delivery-reposition values with their actual semantics/provenance. A generic evidence-value representation is also acceptable if it cannot be mistaken for canonical loaded mileage.

Rewrite M5-08 so a displayed total never populates the canonical loaded-mile slot.

## Current M5-12/M5-13 only prove lifecycle persistence

M5-12 manual intake asserts a lifecycle SEEN row exists.

M5-13 email intake reads `res.normalized.canonicalRevenue` directly from the transient return object, then checks lifecycle `lastMutation.source`. It does not reload any durable semantic evidence.

These tests therefore cannot prove:

- amount/price semantic survives reload;
- mileage facts/semantics survive reload;
- sourceName/sourceType/raw evidence/timestamps survive reload;
- confirmation/confidence/source-health survives reload;
- later history/calibration can recover the evidence without the original function return value.

Add a close/reopen or fresh-page fixture that retrieves the persisted evidence by internal `evidenceId` / lifecycle link and verifies the semantic fields.

## M5-14 does not prove an actual user/email call path

It directly calls `intakeOpportunity()` from `window.__FL_TESTS`. That proves the helper is local; it does not prove the real manual intake UI or email-normalization entry point calls it.

Completion M5B requires a real call path. Add fixtures through the actual manual intake surface and the actual email-derived normalization seam, with durable evidence assertions.

## Vocabulary coverage is incomplete

Tests currently cover only the runtime's narrow enum. Add contract-aligned fixtures for at least:

Price semantics:
- `BOARD_TARGET_RATE`
- `POSTED_RATE`
- `MARKET_BENCHMARK`
- `UNKNOWN_PRICE_SEMANTIC`

Mileage semantics:
- `POST_DELIVERY_REPOSITION_MILES`
- displayed total distinct from loaded
- map estimate distinct from source-displayed miles

Provenance roles:
- platform distinct from source name;
- broker, carrier, company/customer/shipper not conflated;
- `observed_at` vs source timestamp where applicable;
- source health/freshness when applicable.

None of those evidence-only semantics may become canonical carrier revenue or True RPM inputs unless their semantic gate permits it.

## Required durability path tests

Under the merged contract, add end-to-end tests for:

1. manual normalize → persist evidence → lifecycle link → reload → evidence intact;
2. email normalize → persist evidence/source reference → reload → evidence intact;
3. full cloud backup/restore preserves durable evidence;
4. delta backup/restore preserves durable evidence;
5. local export/import merge and replace preserve durable evidence;
6. integrity checksum detects an evidence-only mutation;
7. stale concurrent user evidence correction is rejected rather than overwriting newer evidence;
8. unresolved lifecycle link does not discard the evidence;
9. reused external IDs do not collapse distinct evidence records;
10. provider/bookable/target/posted/benchmark amounts remain evidence-only after reload.

## Gate

Do not certify M5 by asserting `res.normalized` in the same call frame. M5 certification requires semantic evidence to survive the loss of that transient JavaScript object and remain auditable through the repository's actual protection/recovery paths.
