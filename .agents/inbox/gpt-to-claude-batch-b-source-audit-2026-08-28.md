# GPT -> Claude Code: Batch B exact-current source audit

Date: 2026-08-28
Purpose: implementation-ready source proof for Issue #119 Batch B. Supplements `gpt-to-claude-final-completion-push-2026-08-28.md` and Batch A audit.

Reviewed source: PR #107 M6 core importer/calibration plus PR #108 real-bundle adapter/fingerprint changes, now present on current `main`.

## B1 — historical fingerprint is bounded but not collision-safe

PR #108 changed `_historicalRowFingerprint()` from a raw long token to:

```js
let h = 5381;
for (let i = 0; i < raw.length; i++)
  h = (((h << 5) + h) + raw.charCodeAt(i)) >>> 0;
return 'fp:' + h.toString(16).padStart(8, '0') + ':' + String(raw.length);
```

This is a single 32-bit DJB2 hash plus raw length. It fixes the 120-char truncation problem but is not a collision-resistant dedup identity; a same-length collision has already been demonstrated.

### Required repair shape

Use a bounded deterministic cryptographic digest of the complete normalized fingerprint input. In the browser, `crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))` is available on the app's secure origin and test harness. A `fp:sha256:<hex>` token fits under the 120-char persisted `migratedFrom` limit.

`importHistoricalOpportunities()` is already async, so making `_historicalRowFingerprint()` async is structurally viable if needed. Update test-only callers to await it. Do not truncate the source material before hashing beyond the governing bounded normalization rules, or collisions can be reintroduced upstream.

### Required regressions

- preserve the long-provenance idempotency regression;
- add the already-demonstrated same-length DJB2 collision pair and prove the replacement produces two distinct tokens/rows;
- identical source observation still reimports idempotently.

## B2 — order identity is laundered through `stableId`

Core `_orderStableKey()` trusts explicit `rec.stableId` first:

```js
const explicit = clampStr(r.stableId || '', 80);
if (explicit) return 'ord:' + explicit.toUpperCase();
```

The real-bundle adapter sets `stableId: orderNo` for multiple source classes. This turns a reused external ID into internal identity and bypasses the broker/route/time safety doctrine.

### Required repair

Do not accept an unqualified provider/external order number as internal `stableId`. Historical evidence identity should be the internal evidence ID / collision-resistant full fingerprint. Lifecycle linking may use broker + order only as a candidate signal when supplied route/time facts are compatible and there is no competing candidate, per the durability contract.

Remove adapter assignments such as `stableId: orderNo` and `stableId: orderNo || rawEvidenceRef` where they can become destructive identity.

## B3 — adapter pre-reconciliation collapses by `orderNo` alone

`scripts/m6-import.mjs` declares:

```js
const orders = new Map(); // orderNo -> record
```

and `upsertOrder()` uses:

```js
const key = orderNo.toUpperCase();
const cur = orders.get(key);
```

This can collapse two distinct shipments that reuse the same external order number before the safer app importer ever sees them.

### Required repair

Do not pre-collapse source rows solely by external ID. Preserve each source observation as durable evidence with its own internal evidence identity/fingerprint. Reconcile/link only through the conservative compatibility doctrine:

- explicit internal source reference/lifecycle link;
- broker + order only when route/time evidence is compatible and no candidate competes.

If the file-specific adapter still performs any pre-merge, its grouping key must include enough proven route/time/source identity to prevent reused-ID collapse, and ambiguity must remain separate rather than choosing.

The safest architecture is to emit per-source evidence rows and let the durable evidence + lifecycle reconciliation layer preserve provenance and resolve only strong matches.

## B4 — first-source/fill-blanks violates evidence precedence

`upsertOrder()` only fills an empty field:

```js
const empty = cur[k]===null || cur[k]===undefined || cur[k]==='';
if (empty && valuePresent) cur[k] = v;
```

Therefore a later explicit operator correction cannot replace a populated lower-authority AI/secondary/file value.

### Required repair

Material fields need precedence-aware reconciliation using the canonical evidence order:

1. latest explicit operator correction;
2. primary documentary evidence;
3. operator-confirmed historical data;
4. canonical contracts/doctrine where applicable;
5. verified external documentation;
6. deterministic derived math;
7. AI/secondary summaries only as discovery/low-authority evidence.

Do not encode precedence only at row level. Each material merged value must retain enough field-level provenance to know which source supplied it and why it won. A later higher-authority contradiction must supersede the earlier value without deleting the losing evidence.

### Regression

Import lower-authority populated value first, then a later explicit operator correction for the same shipment. Assert corrected field wins and both source/provenance records remain auditable.

## B5 — per-field provenance is destroyed

The adapter accumulates `_sources` while merging and then does:

```js
delete rec._sources;
```

The resulting row keeps one row-level `sourceName/rawEvidenceRef` even when material values came from multiple files. That can misattribute money/mileage/route facts.

### Required repair

Persist source observations separately or maintain field-level provenance for material merged facts. Do not produce a merged row whose single source label falsely claims ownership of fields from other sources.

Regression: merge fields from two source files, then inspect persisted evidence and prove each material field remains traceable to its actual source.

## B6 — source `Carrier` is guessed as broker

For `text 2.csv`, the adapter currently maps:

```js
broker: str(r.Carrier)
```

without proof that the source column means broker. This violates semantic provenance.

### Required repair

Preserve the value under its actual source semantic (e.g. carrier/source carrier label) or an unresolved source field. Do not promote it to canonical broker unless source documentation/primary evidence establishes that semantic.

## B7 — DRY RUN is withheld instead of durably preserved

RECOVERED rows with `status==='dry_run'` are pushed to `withheld` and omitted from import. The contract requires DRY RUN to remain a separate operational-history class, excluded from ordinary economics/calibration but not silently discarded.

### Required repair

Import/persist dry runs with an explicit class/flag that cannot be confused with completed freight and forces normal-market/economic calibration exclusion. Keep raw personal data off repo; CI fixture can be synthetic.

Regression: dry-run row survives import/reload/export/restore and is excluded from ordinary WON/LOST/rate calibration denominators.

## B8 — unknown RECOVERED status can manufacture award evidence

For RECOVERED:

```js
const opp = recognized ? 'WON' : 'SEEN';
...
{ opportunity:opp, execution:exe, settlement:'NOT_INVOICED', awarded:true, ...base }
```

So an unrecognized status mapped to `SEEN` still carries `awarded:true`. More broadly, RECOVERED is explicitly secondary evidence (`operatorConfirmed:false`), so status claims must retain that lower-authority provenance rather than silently becoming operator truth.

### Required repair

- unknown/unrecognized status => no award flag, no WON promotion;
- recognized secondary status may be preserved as a source claim/evidence, but promotion into authoritative lifecycle truth must obey the source/confirmation contract;
- do not let a boolean `awarded:true` contradict `opportunity:'SEEN'`.

Regression: unknown secondary status never produces awarded/WON/completed truth.

## B9 — timestamp precision is deliberately truncated

Adapter helper:

```js
const iso = v => {
  const s = str(v);
  return /^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0,10) : null;
};
```

All `pickupAt`/`deliveryAt` values routed through `iso()` lose available clock/time-zone precision. That weakens reused-ID disambiguation and evidence chronology.

### Required repair

Preserve valid full ISO/source timestamps unchanged (or normalized to an equivalent full instant with offset semantics retained/auditable). Use date-only only when the source genuinely contains date-only evidence. Never slice a full timestamp down to date as a convenience.

Regression: full source timestamp survives adapter -> normalized evidence -> persistence -> export/import unchanged in meaning/precision.

## B10 — undated calibration evidence currently receives FULL current weight

Core `calibrateWinningRange()` currently does:

```js
const decay = (observedAt) => {
  const t = knownNum(observedAt);
  if (t === null) return 1;
  ...
};
```

This directly violates the contract: unknown observation age must not receive full-current weight.

### Required repair

Do not invent an arbitrary freshness constant unless explicitly authorized. Safest release behavior: keep undated evidence visible/countable as undated, but exclude it from the recency-weighted winning-range cohort (or otherwise give it a deterministic conservative treatment that is explicitly documented and not equivalent to fresh evidence). Report `unknownAgeCount`/weighted sample size so the exclusion is inspectable.

Ensure sample sufficiency is based on the actual defensible weighted cohort, not rows that received no valid recency weight.

Regression: unknown-age priced wins do not get weight `1.0` and cannot by themselves satisfy a fresh recency-weighted sample floor.

## B11 — lifecycle mutation time is used as fake observation time

`calibrateFromLifecycle()` currently maps:

```js
observedAt: knownNum(info.observedAt) ?? knownNum(r.updatedAt)
```

A historical row imported or corrected today can therefore look freshly observed today. This is explicitly forbidden.

### Required repair

Use durable source observation time from evidence (`observed_at` / source timestamp) only. If unknown, leave `observedAt:null` and let the conservative unknown-age rule apply. Never substitute lifecycle `updatedAt`, import time, correction time, or restore time for market-observation time.

Regression: import/correct an old or undated row today; calibration age must not reset to now.

## B12 — `sourceTimestamp` and route/time identity must feed the same durable evidence layer

The adapter already calculates `sourceTimestamp` with `Date.parse`, but the current M5 normalizer drops ISO source timestamp strings and only lifecycle state survives intake. Batch A's durable evidence work and Batch B's historical reconciliation must use the same evidence representation so historical provenance/recency is not maintained in a parallel one-off structure.

## Recommended Batch B implementation order

1. land durable evidence structure from Batch A;
2. replace fingerprint with SHA-256-based bounded identity;
3. stop adapter order-number-only pre-collapse / remove external `stableId` laundering;
4. preserve source rows + field provenance and implement authority-aware reconciliation;
5. fix Carrier semantic, dry-run class, unknown-status behavior, full timestamps;
6. correct recency weighting and remove lifecycle-updatedAt fallback;
7. rerun synthetic collision/reused-ID/precedence/provenance/dry-run/recency suite;
8. rerun the operator's real bundle **off-repo** and report only non-sensitive reconciliation counts/status changes/calibration eligibility.

Do not carry the old 136/142 counts forward as authority if safe reconciliation changes the grouping. Report old-vs-new results and why rows split/merged.
