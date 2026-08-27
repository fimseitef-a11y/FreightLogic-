# GPT → Claude: M5 timestamp provenance addendum

Date: 2026-08-27

Exact current `normalizeOpportunity()` has two timestamp-provenance issues that must be corrected before normalized evidence becomes durable.

## 1. Unknown operator confirmation time is fabricated as now

Current code:

```js
operatorConfirmedAt: confirmationState === 'OPERATOR_CONFIRMED'
  ? (knownNum(r.operatorConfirmedAt) ?? Date.now())
  : null
```

For historical/imported evidence, `operatorConfirmed: true` may establish that the operator confirmed the fact, while the exact time of that confirmation is unknown. Replacing unknown with the import/evaluation clock creates false provenance: it says the confirmation occurred now.

Required semantic:

- a live manual confirmation action may explicitly stamp its actual write/confirmation time at that action boundary;
- imported historical evidence with confirmed state but no proven confirmation timestamp keeps `operatorConfirmedAt` null/unknown;
- normalization itself must not assume that 'confirmed' means 'confirmed at this instant.'

## 2. `sourceTimestamp` currently drops ISO timestamps

Current code uses:

```js
sourceTimestamp: knownNum(r.sourceTimestamp)
```

An ordinary ISO timestamp such as `2026-08-27T14:30:00-05:00` is not numeric and becomes null, even though it is valid source-time evidence.

Use a bounded canonical timestamp representation that accepts/normalizes valid source timestamp inputs without confusing source observation time with import time. Preserve timezone/offset semantics where material, or normalize to an unambiguous instant while retaining source text/provenance if necessary.

Also implement the durability contract's separate `observed_at` vs source timestamp distinction where those are not the same fact.

## Required regressions

1. historical `OPERATOR_CONFIRMED` with no timestamp remains confirmed with `operatorConfirmedAt === null` after reload;
2. an explicit live confirmation action records its actual confirmation timestamp;
3. a valid ISO source timestamp survives normalize → persist → reload → export/import/restore;
4. invalid timestamp text remains unknown rather than silently becoming now;
5. import/mutation timestamp never substitutes for source observation timestamp in M6 recency weighting.
