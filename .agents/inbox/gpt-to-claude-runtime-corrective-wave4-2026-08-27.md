# GPT -> Claude Code: runtime corrective wave 4 — M6 reconciliation + recency

Date: 2026-08-27
Target application branch: current `main`
Observed main head: `fdfc726f6d6c3f43c08020bb7be0ed2b4280982f`
Depends on corrective waves 1–3.

This packet covers the remaining M6 data-integrity/recency blockers with exact-current-source findings. Preserve PR #108's valid local `importJSON()` lifecycle support, but repair the historical adapter semantics below.

## Exact-current findings

### 1. Historical fingerprint remains 32-bit DJB2

Current `_historicalRowFingerprint()` ends with:

```js
let h = 5381;
for (let i = 0; i < raw.length; i++)
  h = (((h << 5) + h) + raw.charCodeAt(i)) >>> 0;
return 'fp:' + h.toString(16).padStart(8, '0') + ':' + String(raw.length);
```

This is not collision-resistant enough for destructive/idempotency identity. Replace it with a bounded deterministic collision-resistant digest over the full normalized identity/provenance input. Use WebCrypto SHA-256 (or repository-equivalent strong digest), store a bounded token, and preserve deterministic re-import idempotency.

Required regression: the known/deliberately constructed same-length legacy DJB2 collision pair remains two distinct observations under the replacement fingerprint; identical long-provenance input still re-imports idempotently.

### 2. Order stable identity still collapses reused IDs

Current `_orderStableKey()` returns broker + order when no explicit stable ID:

```js
return (broker && order) ? `ord:${broker}|${order}` : '';
```

That is insufficient for operator history where the same external ID can be reused. Do not use broker+order alone as a destructive historical identity. Incorporate compatible route/time/source identity or leave unresolved; reuse the wave-2 conservative identity doctrine.

Also do not accept `stableId = orderNo` as an internal identity laundering path. An external order number is still external evidence unless the source explicitly provides a genuinely stable internal identity distinct from that field.

### 3. ISO source timestamps are dropped; unknown confirmation time is fabricated

Current normalized provenance does:

```js
sourceTimestamp: knownNum(r.sourceTimestamp),
...
operatorConfirmedAt:
  confirmationState === 'OPERATOR_CONFIRMED'
    ? (knownNum(r.operatorConfirmedAt) ?? Date.now())
    : null,
```

Consequences:

- valid ISO source timestamps are rejected because they are not numeric;
- an old historical confirmation with unknown confirmation time is rewritten as import-now.

Repair using the timestamp contract from wave 2. Preserve valid numeric epoch or ISO timestamp representations without losing clock time/offset. If historical `operatorConfirmedAt` is unknown, it remains null/unknown; import time belongs in a separate import metadata field and may never masquerade as confirmation time.

### 4. Provenance vocabulary is narrower than the canonical contract

Current `PRICE_SEMANTIC` lacks canonical evidence semantics including at least:

- `BOARD_TARGET_RATE`
- `POSTED_RATE`
- `MARKET_BENCHMARK`

Current `MILEAGE_SEMANTIC` lacks at least:

- `POST_DELIVERY_REPOSITION_MILES`

Reconcile the runtime vocabulary to `docs/EVIDENCE_PROVENANCE.md` and `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md`. Unknown/unrecognized values remain explicit unknowns; do not silently coerce them into a revenue/mileage role.

### 5. DRY RUN has no explicit runtime representation in current app.js

Current-source search finds no `dryRun`/DRY RUN handling in the M6 adapter. Add a distinct operational-history classification/flag so dry runs are preserved, not discarded or promoted into completed-load economics. Exclude them from ordinary win-rate/normal-market calibration unless a governing contract explicitly says otherwise.

### 6. Quote/history status promotion needs fail-closed semantics

Current quote logic has some conservative handling, but the M6 adapter must prove that an unknown/unrecognized secondary status never sets awarded/WON/completed truth. Preserve `EXPIRED`, `LOST`, `CANCELLED`, `DRY RUN`, live/open/board observation and completed/accepted as distinct classes.

Do not infer canonical `broker` from a source field named `Carrier`; retain it in its actual semantic field unless explicit evidence establishes broker identity.

### 7. Later higher-authority correction must beat earlier populated value

Reconciliation must not be first-source-wins or fill-only. Apply the established precedence:

1. latest explicit operator correction;
2. primary documentary evidence;
3. operator-confirmed historical data;
4. canonical contracts/doctrine;
5. verified external documentation;
6. deterministic derived math;
7. AI summaries/handoffs discovery-only.

When different material fields come from different sources, retain field-level provenance (or equally auditable equivalent). A single row-level source label is insufficient after a multi-source merge.

Required regressions:

- earlier low-authority value populated, later operator correction changes it;
- unrelated fields from earlier evidence survive if not contradicted;
- per-field provenance names the source that actually supplied each material value;
- later low-authority data cannot overwrite an operator correction.

## M6 observation recency

Calibration freshness must derive from the durable **source observation time** when known.

Do not use any of these as substitutes for observation age:

- lifecycle `updatedAt`;
- import timestamp;
- correction timestamp;
- migration timestamp.

An old market observation imported today remains old. An observation with unknown source age must receive UNKNOWN/discounted freshness, never full current weight.

Required regression:

1. seed an old observation with recent import/update time and prove its calibration age remains old;
2. seed unknown observation time and prove it does not receive CURRENT/full freshness;
3. seed a later operator correction to a non-time field and prove it does not refresh observation age;
4. seed an actually recent source timestamp and prove it receives the intended current weighting.

## Real import validation after code repair

After the synthetic suite is green, re-run M6 reconciliation off-repo against verified operator source files/screenshots/exports. Do not reconstruct authoritative rows from AI memory. Keep raw personal financial/history files uncommitted; commit only non-sensitive aggregate validation results (row counts/status reconciliation/conflict counts) unless operator explicitly authorizes otherwise.

Only after M6 identity/precedence/provenance/recency are repaired should release-generation parity be selected and synchronized.

Controlling rule: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT**.
