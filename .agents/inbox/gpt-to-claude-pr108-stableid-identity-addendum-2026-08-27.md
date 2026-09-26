# GPT → Claude: PR #108 stableId identity addendum

Date: 2026-08-27
PR #108 head reviewed: `9cd624edcb60cbfb740e97f94d43cf0497ab367f`

There is a second reused-ID failure behind the already-flagged adapter `Map(orderNo)` issue.

## Cross-layer problem

M6 core `_orderStableKey(rec)` trusts explicit `stableId` first:

```js
const explicit = clampStr(r.stableId || '', 80);
if (explicit) return 'ord:' + explicit.toUpperCase();
```

Only when `stableId` is absent does it require broker + order.

PR #108's `scripts/m6-import.mjs` sets:

```js
stableId: orderNo
```

for completed order records.

Therefore the adapter promotes an external order number — which the project does not treat as globally safe identity — into the field the core importer explicitly trusts as a stable identity. Even after fixing the adapter's in-memory `Map(orderNo)`, the downstream importer could still deduplicate distinct reused-ID shipments through `ord:<orderNo>`.

## Required repair

`stableId` must mean an actually stable internal/source identity, not a renamed external order number.

For this bundle:

- do not populate `stableId` from `orderNo` alone;
- if the source files contain a proven unique internal source identifier, retain it with its source namespace/provenance;
- otherwise let the importer use the conservative broker/order + route/time/source compatibility contract, or preserve the record unresolved/separate when identity cannot be proven;
- for quote observations, retain full source/evidence identity and never promote quote/order ID alone.

Consider hardening `_orderStableKey()` itself so `stableId` is only trusted when its provenance/type establishes that it is an internal stable identity. A generic caller-provided string named `stableId` should not be able to bypass the reused-ID safety contract accidentally.

## Required regressions

1. two distinct order records with the same external order number but different broker/lane/pickup evidence remain separate even if an adapter previously would have assigned `stableId = orderNo`;
2. a genuinely explicit internal stable ID links deterministically;
3. order number alone cannot be smuggled through the `stableId` property to force a merge;
4. re-import of the exact same source record remains idempotent through its collision-resistant source fingerprint / proven identity.
