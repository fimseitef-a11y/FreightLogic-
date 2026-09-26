# GPT -> Claude Code: runtime corrective wave 2

Date: 2026-08-27
Target application branch: current `main`
Observed main head: `fdfc726f6d6c3f43c08020bb7be0ed2b4280982f`
Depends on: `gpt-to-claude-runtime-corrective-wave1-2026-08-27.md`

This packet covers certification blockers 4–6 with exact-current-source evidence. GPT is not editing Claude-owned core/test paths. Keep the release HOLD until these are implemented, regression-tested, merged, and exact-current source is re-reviewed.

## 4. Reused-ID lifecycle safety + timestamp preservation

### Exact-current defect: broker + order can override contradictory route/time evidence

Current `lifecycleMatchCandidate()` reduces strong matching to normalized order + broker:

```js
const order = clampStr(record?.orderNo || '', 60).trim().toUpperCase();
const broker = normBroker(record?.broker || '');
if (!order || !broker) return { linked:false, unresolved:false, reason:'insufficient strong evidence' };

const matches = list.filter(c =>
  clampStr(c.orderNo || '', 60).trim().toUpperCase() === order &&
  normBroker(c.broker || '') === broker);

if (matches.length === 1)
  return { linked:true, lifecycleId:matches[0].lifecycleId, reason:'broker + order number' };
```

This is unsafe for real operator history where external IDs are reused. If the incoming record supplies origin/destination/pickup/delivery evidence that conflicts with the single broker+order candidate, current code still links it.

### Required matching behavior

- explicit internal `lifecycleId` may resolve directly when valid;
- normalized broker+order may be a candidate selector, not a contradiction override;
- when both incoming and candidate contain material route/time evidence, incompatible origin/destination or materially conflicting pickup/delivery timestamps must prevent automatic linking;
- if broker+order identifies one candidate but supplied route/time contradicts it, return unresolved/fail-safe, not linked;
- if several reused-ID candidates exist, compatible route/time may narrow only when the evidence is sufficiently exact and unique; otherwise unresolved;
- missing route/time on one side does not fabricate compatibility — preserve conservative behavior.

Add synthetic regressions for same broker + same order reused across two distinct shipments and for a single stale candidate contradicted by incoming route/time.

### Exact-current defect: lifecycle timestamps reject valid ISO datetimes

`isValidISODate()` intentionally accepts only `YYYY-MM-DD`:

```js
if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
```

But both normalized opportunity and lifecycle sanitization use it for `pickupAt`/`deliveryAt`:

```js
pickupAt: isValidISODate(r.pickupAt) ? r.pickupAt : null,
deliveryAt: isValidISODate(r.deliveryAt) ? r.deliveryAt : null,
```

Therefore a valid source timestamp such as `2026-08-26T18:30:00-05:00` is discarded rather than preserved. This weakens reused-ID disambiguation and violates the durability contract.

### Required timestamp repair

Do not broaden `isValidISODate()` globally because many existing date-only fields legitimately depend on that contract. Add/use a timestamp-capable validator/normalizer for evidence/lifecycle datetime fields that:

- accepts valid `YYYY-MM-DD` when only a date is known;
- accepts valid ISO-8601 date-time strings with clock time and timezone/offset when supplied;
- preserves the available source precision instead of slicing to date-only;
- rejects garbage;
- does not invent a time or timezone for a date-only observation.

Use this consistently in `normalizeOpportunity()`, `sanitizeLifecycle()`, historical intake, durable evidence, and any identity compatibility logic.

### Exact-current UI defects: stage chips and editor are keyed by order number alone

Current lifecycle chip hydration builds a one-value map by order number:

```js
const byOrder = new Map();
for (const r of rows){ if (r.orderNo) byOrder.set(String(r.orderNo).toUpperCase(), r); }
...
const lc = key && byOrder.get(key);
```

A reused order number silently overwrites whichever lifecycle was inserted earlier.

Current editor does the same class of lookup:

```js
async function openLifecycleEditor(orderNo){
  const rows = await listLifecycle();
  const lc = rows.find(r => String(r.orderNo).toUpperCase() === String(orderNo).toUpperCase());
```

Trip detail calls it with only `t.orderNo`.

### Required UI repair

Do not pick a lifecycle solely from `orderNo` for display or editing.

Preferred direction:

- carry a resolved `lifecycleId` / internal source reference when the relationship is already known;
- otherwise resolve through the same conservative identity matcher using the trip/evidence context (broker, route, pickup/delivery) and show unresolved state if unique identity cannot be established;
- editor must refuse ambiguous selection and require explicit resolution rather than opening an arbitrary record;
- stage chips must not display another shipment's state simply because the external order number is reused.

Regress the actual rendered chip/editor path with two lifecycles sharing order number but differing lane/time.

---

## 5. Background lifecycle-link optimistic concurrency

### Exact-current defect

`linkLifecycle()` does a read/merge/write sequence:

```js
const base = match.linked ? await getLifecycle(match.lifecycleId) : null;
const merged = sanitizeLifecycle({ ...(base || {}), ...patch, ... });
const saved = await upsertLifecycle(merged, opts);
```

`upsertLifecycle()` already has the correct compare-and-abort contract when `expectedRevision` is supplied, but `linkLifecycle()` does not automatically carry `base.revision` into that write. Normal background/intake callers can therefore read revision N, a user mutation can commit revision N+1, then the stale background merge can overwrite fields from N because `expectedRevision` remains null.

### Required repair

For an existing matched lifecycle, the background link must commit against the revision it actually read. Conceptually:

- read `base`;
- merge patch conservatively;
- call `upsertLifecycle(..., { ...opts, expectedRevision: base.revision })` unless the caller is supplying an even stricter expected revision under the same contract;
- on `FL_CONFLICT`, do not blindly retry last-writer-wins. Preserve the authoritative legacy write, return/report unresolved/conflict for the lifecycle side, and allow a deliberate fresh reconciliation pass if appropriate.

For creation, keep the normal no-existing-row semantics.

### Required real stale-race regression

Add a deterministic test that forces this interleaving:

1. background `linkLifecycle()` reads lifecycle revision N;
2. user/edit path writes revision N+1 with a material state change;
3. background link resumes with stale base N;
4. stale write must abort/conflict and the N+1 user value must remain intact.

A helper-only test of `upsertLifecycle(expectedRevision)` is insufficient; the regression must exercise `linkLifecycle()` itself. If a test barrier/hook is needed, keep it test-gated and non-production-authoritative.

---

## 6. Worker canonical-absence compatibility

### Client contract on current main

The client intentionally represents incomplete canonical facts as:

- authority verdict `UNAVAILABLE`;
- grade `?` / unknown;
- `economics.trueRPM = null` and the rest of unavailable economics null;
- `bid.range = null` with `suppressed: true`.

This is the M1 money-integrity rule: missing inputs are not zeros and must not become a confident rejection.

### Exact-current Worker incompatibility

`cloud-backup-worker.js` `/evaluate` currently rejects this legitimate client state before model invocation:

```js
if (!payload.canonicalDecision?.authority?.verdict ||
    !payload.canonicalDecision?.authority?.grade ||
    !Number.isFinite(Number(payload.canonicalDecision?.economics?.trueRPM)) ||
    !payload.canonicalDecision?.bid?.range) {
  return ... 400;
}
```

Even if an incomplete decision reached projection, the sanitizers manufacture certainty:

```js
function canonicalVerdict(v){
  ...
  return new Set(['ACCEPT','REJECT','STRATEGIC','DZ-EXIT']).has(s) ? s : 'REJECT';
}

function canonicalGrade(g){
  ...
  return /^[A-F]$/.test(s) ? s : 'F';
}
```

`canonicalTrueRpmLabel()` converts through `Number(...)`; `Number(null) === 0`, so a null True RPM risks becoming a calculated-looking `$0.00 / true mile` unless null is checked before numeric coercion.

`canonicalBidAdvice()` also assumes a normal range path and should preserve explicit bid suppression/unavailability rather than inventing substitute advice that looks canonical.

### Required Worker repair

The Worker is review-only. It must accept and faithfully project BOTH complete and incomplete canonical client decisions.

For incomplete state:

- verdict stays `UNAVAILABLE`;
- grade stays `?` (or the exact client unknown token), never `F`;
- True RPM stays null/unavailable; never `$0.00`;
- bid remains suppressed/null; do not manufacture a dollar amount or alternate canonical bid;
- AI may explain why facts are missing and suggest what fact to collect next, but may not replace the client-owned canonical answer;
- any client-owned confidence/evidence labels passed into the review context may be explained/challenged, not replaced by model-authored competing labels.

Do not weaken token/auth/rate-limit/body-size boundaries.

### Required Worker regressions

Add direct Worker tests for at least:

1. complete canonical decision projects exact verdict/grade/True RPM/bid as before;
2. incomplete decision with `UNAVAILABLE`, `?`, `trueRPM:null`, `range:null/suppressed:true` is accepted for review and returns those same canonical absence semantics;
3. null True RPM cannot render `$0.00` through coercion;
4. malformed payload that is structurally missing the canonical decision is still rejected;
5. AI output attempting to contradict verdict/grade/bid cannot overwrite the client projection;
6. auth denial/rate limits remain unchanged.

Prefer testing the actual `/evaluate` request/response boundary with a mocked OpenAI response, not sanitizers in isolation.

---

## Integration order

Wave 1 (migration/delta/integrity) should land first if it is already in progress, then wave 2. If implementation naturally combines them in one coherent core PR, preserve clear commits and all regressions; do not mix unrelated refactors.

After wave 2 merges green, continue without stopping to:

- M3 real-path confidence/evidence wiring;
- durable normalized evidence + real production M5B intake;
- M6 reconciliation correction + collision-resistant identity/precedence/field provenance/status semantics;
- M6 observation recency;
- release-generation parity;
- exact-SHA release checks and then finite operator/device M7 checks.

Full suite and lane protocol remain mandatory for every `app.js`/storage/Worker change. Do not mark release certified from green CI alone; exact-current source and real-path regressions must reconcile first.

Controlling rule: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT**.
