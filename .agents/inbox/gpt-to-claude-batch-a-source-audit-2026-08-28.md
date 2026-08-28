# GPT -> Claude Code: Batch A exact-current source audit

Date: 2026-08-28
Purpose: implementation-ready root-cause notes for Issue #119 Batch A. This supplements, not replaces, `gpt-to-claude-final-completion-push-2026-08-28.md`.

Reviewed source ancestry: current `main` after PRs #105/#108/#116/#118; exact current baseline was `a6d5f9ff5ed5c88a025b9c8e6eea3fdc750d2ed9` when this audit began. Reconcile from newer `main` before editing.

## A1 — DB v14 lifecycle indexes: root cause confirmed

In `initDB()` the generic store setup executes:

```js
ensureStore('loadLifecycle', { keyPath:'lifecycleId' });
```

before the v14 migration block. The v14 block then does:

```js
if (old < 14) {
  if (!d.objectStoreNames.contains('loadLifecycle')) {
    const lc = d.createObjectStore('loadLifecycle', ...);
    lc.createIndex(...)
  }
}
```

Therefore on a fresh/upgrade transaction `loadLifecycle` can already exist by the time the index block checks `objectStoreNames`, so the index creation body is skipped. Existing M4 tests assert store existence/version, not actual `indexNames`.

### Required repair shape

Keep migration idempotent. After ensuring/creating the store, obtain the upgrade transaction's object store and create each missing index individually:

- `updatedAt`
- `orderNo`
- `broker`

Guard with `lc.indexNames.contains(name)` so both fresh creation and v13->v14 migration work safely. Do not delete/recreate the store.

### Regression

Test actual resulting `indexNames` in:

1. clean/fresh DB creation;
2. explicitly seeded v13 DB upgraded to v14.

Store-exists-only coverage is insufficient.

## A2 — `cloudPushBackup()` empty-delta TDZ: root cause confirmed

Current code evaluates the empty-delta guard with:

```js
... && gl.length === 0 && lc.length === 0
```

before these declarations:

```js
const allLifecycle = await dumpStore('loadLifecycle');
const changedLifecycle = ...;
const lc = isDelta ? changedLifecycle : allLifecycle;
```

That is a real temporal-dead-zone failure on a valid delta path.

### Required repair shape

Compute `allLifecycle`, `changedLifecycle`, and `lc` before the empty-delta guard, alongside the other changed-store arrays. Then keep the empty-delta early return exactly where it is semantically appropriate.

### Regression

Drive the real `cloudPushBackup()` delta path with no changed records in any store and prove it returns/no-ops cleanly rather than throwing before the request decision.

## A3 — background lifecycle concurrency: root cause confirmed

`linkLifecycle()` does:

```js
const base = match.linked ? await getLifecycle(match.lifecycleId) : null;
...
const saved = await upsertLifecycle(merged, opts);
```

`upsertLifecycle()` already has the correct compare-and-abort contract, but `linkLifecycle()` does not pass the revision it read. A user mutation can land between `getLifecycle()` and `upsertLifecycle()`, then the background link writes a merged stale base without `expectedRevision`.

### Required repair shape

When `base` exists, call `upsertLifecycle()` with the observed `base.revision` as `expectedRevision` (while preserving source/sourceId/reason from `opts`). New-record path remains no expected revision. Do not swallow `FL_CONFLICT` into a successful link; preserve failure-safe dual-write behavior but report the conflict result accurately.

### Regression

Create a deterministic stale background-link race: read base through link path, mutate same lifecycle to a newer revision, then let link persist. Assert newer state survives and link reports conflict/failure rather than overwriting.

## A4 — reused identifier lifecycle safety: root cause confirmed

`lifecycleMatchCandidate()` currently links a **single** normalized `broker + orderNo` match immediately:

```js
if (matches.length === 1)
  return { linked:true, lifecycleId: matches[0].lifecycleId, reason:'broker + order number' };
```

It does not reject that match when supplied route/time facts conflict. This is unsafe because real external order/quote IDs are reused.

### Required behavior

A broker/order pair is strong only when any supplied compatibility facts do not conflict:

- origin
- destination
- pickup timestamp
- delivery timestamp

If the incoming record supplies a route/time fact and the candidate supplies the same fact but they conflict, do **not** auto-link. Treat the reused-ID situation as unresolved/fail-safe. If multiple compatible candidates remain, unresolved. Missing compatibility facts may remain unknown; do not invent geocoding or approximate matching.

Preserve available clock precision. Do not truncate valid source/pickup/delivery timestamps to date-only before matching.

### UI call sites that are also unsafe

`renderLifecycleChips()` builds:

```js
const byOrder = new Map();
for (const r of rows){ if (r.orderNo) byOrder.set(String(r.orderNo).toUpperCase(), r); }
```

so duplicate order numbers overwrite each other.

`openLifecycleEditor(orderNo)` does:

```js
rows.find(r => String(r.orderNo).toUpperCase() === String(orderNo).toUpperCase())
```

so it can edit the wrong shipment.

Replace order-number-only UI lookup with conservative lifecycle resolution using the trip/source record's route/time/broker evidence or a persisted lifecycleId. Ambiguity should produce no chip / explicit unresolved warning and should not open an arbitrary editor record.

### Regressions

- same broker + same external orderNo + conflicting origin/destination -> distinct/unresolved;
- same broker + same orderNo + conflicting pickup clock timestamp -> distinct/unresolved;
- chips/editor never choose one arbitrary lifecycle from reused-ID candidates.

## A5 — normalized opportunity durability/semantics: root causes confirmed

Current `normalizeOpportunity()` / `intakeOpportunity()` has several exact defects.

### 1. Normalized evidence is transient

`intakeOpportunity()` normalizes, then calls `linkLifecycle()`, then returns:

```js
return Object.freeze({ normalized: norm, link });
```

The semantic evidence object itself is not durably persisted. This fails the durability contract.

**Required architecture:** use a dedicated bounded durable evidence structure/store (preferred over turning `loadLifecycle` into a catch-all ledger). Every evidence row needs internal `evidenceId`, may link to `lifecycleId`, and must survive reload/full+delta backup/restore/local export/import/checksum. Evidence must remain preservable when lifecycle linking is unresolved.

### 2. `sourceTimestamp` rejects valid ISO timestamps

Current provenance does:

```js
sourceTimestamp: knownNum(r.sourceTimestamp)
```

A valid ISO timestamp string therefore becomes null. Preserve valid ISO source timestamps with clock/time-zone precision; do not coerce them through numeric-only normalization.

### 3. historical unknown confirmation time is fabricated as now

Current code does:

```js
operatorConfirmedAt:
  confirmationState === 'OPERATOR_CONFIRMED'
    ? (knownNum(r.operatorConfirmedAt) ?? Date.now())
    : null
```

For imported/historical operator-confirmed evidence with no known confirmation clock, this manufactures the current import time. Unknown must remain unknown/null. A real current manual confirmation event may explicitly stamp now at the user action boundary, but normalization of historical evidence must not.

### 4. displayed total stored in a field named loaded miles

Current normalization reads `loadedMi` independently of `mileageSemantic`, and the test explicitly accepts:

```js
{ loadedMi:480, mileageSemantic:'DISPLAYED_TOTAL_MILES' }
```

This violates the durability contract: displayed total is not loaded mileage. The durable shape needs semantically distinct mileage fields/evidence so `DISPLAYED_TOTAL_MILES` never occupies canonical `loadedMi`.

### 5. vocabulary is narrower than governing evidence contract

Current `PRICE_SEMANTIC` includes:

- `CARRIER_PAYOUT`
- `OPERATOR_BID`
- `SHIPPER_BOOKABLE_PRICE`
- `CONTRACT_RATE`
- `SETTLED_AMOUNT`
- `UNKNOWN_PRICE_SEMANTIC`

Durable evidence must also preserve governing semantics such as `BOARD_TARGET_RATE`, `POSTED_RATE`, `MARKET_BENCHMARK` (and any exact canonical vocabulary in `EVIDENCE_PROVENANCE.md`) without collapsing them to unknown or revenue. Expand the evidence vocabulary deliberately while keeping revenue promotion gated.

### Required production path

A real shipped manual/email-compatible surface must execute:

`production intake -> normalize -> persist evidence -> conservative lifecycle link`

Helper exposure under `window.__FL_TESTS` does not qualify. Manual path must work offline. Email/import path must preserve underlying source reference. No provider authorization may be fabricated.

### Required regressions

- production UI/manual intake -> reload -> semantic evidence still present;
- ISO source timestamp survives unchanged;
- historical operator-confirmed evidence with unknown confirmation time stays null;
- displayed total remains structurally distinct from loaded miles;
- evidence survives local export/import and full+delta cloud restore;
- evidence mutation changes protected checksum; deliberately corrupted evidence fails integrity validation;
- unresolved lifecycle link still preserves evidence.

## A6 — lifecycle/evidence export integrity

Current local export contains `loadLifecycle`, but the existing checksum regression only proves the legacy protected shape. Once durable normalized evidence exists, both lifecycle and durable evidence must be included in the protected checksum contract.

Do not treat `exportJSON()` presence as integrity coverage. Add explicit tests proving mutation of lifecycle/evidence changes the checksum and untouched/corrupted payloads validate/fail correctly.

## A7 — M7 runner semantics

PR #116's script currently can print:

`AUTOMATED CERTIFICATION PASSED. Freeze the release after the operator gates pass.`

while the canonical certification state is HOLD with uncovered source defects. Repair the script in the Claude-owned `scripts/` lane:

- default fast run = **release preflight**, not certification;
- skipped full suite = SKIP/PENDING, not PASS;
- while canonical state is HOLD/unresolved blockers exist, fail closed or print `NOT CERTIFIABLE`; never tell the operator to freeze;
- only after blocker regressions exist and `--suite` is actually run/green may suite evidence contribute to certification;
- keep automated preflight, full suite, live Cloudflare, and physical iPhone checks visibly separate.

## Batch A sequencing recommendation

To minimize migration churn:

1. repair existing v14/index/TDZ/concurrency/reused-ID defects first;
2. implement dedicated durable normalized evidence store/shape and bump DB version once, if a schema bump is required;
3. wire backup/export/import/checksum parity for that store in the same coherent batch;
4. wire the real production M5B surface;
5. repair Worker absence/M3 real-path wiring;
6. repair M7 runner semantics;
7. run exact full suite and then continue to Batch B.

Do not version-freeze until Batch A+B are stable.
