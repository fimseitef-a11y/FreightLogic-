# GPT → Claude: M6 recency/provenance addendum

Date: 2026-08-27

Exact current source has a recency-integrity defect in M6 calibration.

## 1. Undated evidence receives maximum recency weight

`calibrateWinningRange()` currently does:

```js
const decay = (observedAt) => {
  const t = knownNum(observedAt);
  if (t === null) return 1;
  ...
};
```

That converts UNKNOWN observation age into the same weight as an observation from `now`.

This conflicts with the repository's UNKNOWN/provenance doctrine: missing age must not be silently interpreted as maximally fresh evidence.

Do not invent a favorable timestamp/weight. Choose and document a conservative deterministic policy, e.g. exclude undated records from recency-weighted winning-range calibration or place them in an explicit unknown-date cohort that cannot receive full-current weight. The exact policy should preserve data without manufacturing freshness.

## 2. `calibrateFromLifecycle()` can replace source age with import/mutation time

Current mapping:

```js
observedAt: knownNum(info.observedAt) ?? knownNum(r.updatedAt)
```

For an imported historical lifecycle row, `r.updatedAt` can be the time FreightLogic imported or mutated the lifecycle—not when the market/load observation actually occurred.

That can make old historical evidence look newly observed simply because it was loaded into the app today.

Use source evidence `observed_at` / source timestamp for recency. Lifecycle mutation/import time is provenance about FreightLogic state, not market-observation age, and must not substitute for it.

If no source observation time is defensible, keep it unknown under the conservative policy above.

## Required regressions

1. an undated winning observation does not receive the same effective freshness as a truly current observation;
2. importing a 2025/early-2026 record today does not refresh its market-observation age to today's lifecycle `updatedAt`;
3. changing only a lifecycle correction today does not make an old market/rate observation fresher;
4. source observation timestamp survives durable evidence backup/export/import and is the timestamp calibration reads;
5. identical semantic inputs still produce deterministic output.

## Gate

Recency weighting is useful only when it is weighting observation recency. Do not use FreightLogic mutation/import timestamps as a fallback market timestamp.
