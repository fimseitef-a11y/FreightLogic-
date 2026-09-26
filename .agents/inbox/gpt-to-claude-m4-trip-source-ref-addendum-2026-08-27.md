# GPT → Claude: M4 trip source-reference addendum

Date: 2026-08-27

Exact current source proves the trip dual-write is not using the strongest internal trip identity available.

`sanitizeTrip()` persists an internal ID:

```js
t.id = clampStr(raw.id || t.id, 80);
```

But `_postTripSaveLaneHook()` currently writes:

```js
sourceRefs: { tripIds: [trip.orderNo] }
```

and uses:

```js
sourceId: trip.orderNo
```

## Problem

`orderNo` is external/order evidence. The v24.2 linking contract calls for an exact internal source reference as stronger evidence than broker/order matching. Labeling `orderNo` as a `tripId` loses that distinction and makes exact-source linking vulnerable to reused/reformatted order numbers.

## Required repair

- use the persisted internal `trip.id` as `sourceRefs.tripIds[]` / exact trip-source reference whenever available;
- retain `orderNo` separately as external evidence, not as the internal source key;
- preserve compatibility for existing lifecycle rows whose historical `tripIds` contain order numbers; do not destructively reinterpret old strings as verified internal IDs;
- if a migration/backfill can safely map an old trip/order ref to one unique stored trip.id, do so conservatively; otherwise leave the legacy ref marked/typed as legacy rather than guessing.

This also strengthens lifecycle matching: exact internal trip reference can be evaluated before the weaker broker+order+route/time fallback.

## Required regressions

1. a saved trip's lifecycle source reference equals the persisted `trip.id`, not `orderNo`;
2. two trip objects with a reused external order number but distinct internal IDs are not treated as the same exact-source reference;
3. legacy lifecycle rows carrying order-number-shaped trip refs remain readable and are not silently upgraded to internal-ID authority;
4. lifecycle UI/editor can bind through lifecycleId/internal source ref without orderNo-only selection;
5. M4-24 should assert the actual reference value/identity, not merely `tripRefs.length === 1`.
