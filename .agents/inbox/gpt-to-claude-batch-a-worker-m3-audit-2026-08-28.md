# GPT -> Claude Code: Batch A Worker + M3 exact-source addendum

Date: 2026-08-28
Purpose: exact-current source findings for the two Batch A areas that were less source-specific in the first packet. This supplements `gpt-to-claude-batch-a-source-audit-2026-08-28.md` and does not change scope.

## Worker canonical-absence compatibility — exact root causes

Current `cloud-backup-worker.js` rejects legitimate incomplete canonical decisions before AI review:

```js
if (!payload.canonicalDecision?.authority?.verdict || !payload.canonicalDecision?.authority?.grade ||
    !Number.isFinite(Number(payload.canonicalDecision?.economics?.trueRPM)) || !payload.canonicalDecision?.bid?.range) {
  return json({ ok:false, error:'Canonical client decision, economics, and bid range are required ...' }, 400, cors);
}
```

That makes the Worker incompatible with the canonical client state introduced in M1, where a materially incomplete load is intentionally `UNAVAILABLE`, grade `?`, `trueRPM=null`, and bid suppressed/null.

The output projection also manufactures negative certainty at its sanitizer boundary:

```js
function canonicalVerdict(v){
  const s = String(v || '').toUpperCase().trim();
  return new Set(['ACCEPT','REJECT','STRATEGIC','DZ-EXIT']).has(s) ? s : 'REJECT';
}
function canonicalGrade(g){
  const s = String(g || '').toUpperCase().trim();
  return /^[A-F]$/.test(s) ? s : 'F';
}
```

`canonicalTrueRpmLabel()` currently does `Number(decision?.economics?.trueRPM)` and `canonicalBidAdvice()` substitutes generic advice if no range exists. Those paths must preserve canonical absence rather than generating a competing answer.

### Required repair

- `/evaluate` must accept the canonical incomplete shape as a valid review-only payload.
- Preserve `UNAVAILABLE` as `UNAVAILABLE`, grade `?` as `?`, `trueRPM=null` as null/explicit unavailable, and null/suppressed bid as unavailable.
- Never map unknown verdict -> `REJECT`, unknown grade -> `F`, null True RPM -> `$0.00`/numeric, or missing bid -> a canonical substitute recommendation.
- AI may explain why the client decision is unavailable and may challenge evidence, but it may not invent the canonical decision fields.
- Client-owned confidence/evidence labels remain projections/explanations, not model-authored replacements.

### Required regression

Drive the real Worker projection/helper boundary with:

```text
authority.verdict = UNAVAILABLE
authority.grade = ?
economics.trueRPM = null
bid.range = null/suppressed
```

and prove the returned shape preserves those values without `REJECT`, `F`, `$0.00`, numeric True RPM, or substitute canonical bid.

## M3 real evidence wiring — exact root causes

### 1. Fuel provenance is inferred from EIA health, not the price actually applied

`buildEvaluationEvidence()` currently decides the fuel source using:

```js
const usingLiveFuel = (typeof LIVE_SOURCE_HEALTH !== 'undefined')
  && LIVE_SOURCE_HEALTH.get && !!LIVE_SOURCE_HEALTH.get('EIA');
```

A truthy EIA health record proves only that an EIA attempt/health record exists. It does **not** prove the `economicsResult.fuelPrice` used in this evaluation came from EIA.

The EIA UI apply path writes only:

```js
await setSetting('fuelPrice', price);
```

so no durable/source label currently travels with the active fuel price.

**Repair:** persist/derive actual fuel-price provenance at the write/apply boundary (manual/user, EIA with source timestamp, static fallback, etc.), then build evidence from that exact provenance. Health and value provenance are separate concepts.

### 2. Lane/broker evidence fields are not wired from the evaluator

`buildEvaluationEvidence()` reads:

```js
ctx.usaResult?.laneSampleSize
ctx.usaResult?.laneLastSeenAt
ctx.usaResult?.brokerSampleSize
```

Exact-current source review found those property names only in the M3 evidence builder; the actual USA/evaluator result does not populate them. The resulting lane/broker sample/recency evidence is therefore not real evaluator input evidence.

Broker evidence also has no `observedAt`/recency passed at all.

**Repair:** wire actual deterministic lane/broker aggregate outputs (sample count + durable last observation time) into the evaluation context from the real data queries. If no broker was supplied, broker must not be a material confidence domain.

### 3. Vehicle/weather check inputs are synthetic

The production evaluation call currently assembles M3 evidence with:

```js
const evidenceItems = buildEvaluationEvidence({
  economicsResult, usaResult, geo, dest, broker,
  vanFitChecked: true,
  weatherChecked: !!(warnings || []).length,
});
```

`vanFitChecked: true` is hardcoded rather than derived from supplied dimensions/profile/capacity state.

`weatherChecked` is based on whether the general `warnings` array has entries, not whether NWS was successfully queried. General decision warnings are not weather-source evidence.

Exact-current search also shows these `vanFitChecked` / `weatherChecked` names are not consumed elsewhere in the builder, so they currently provide neither honest evidence nor a useful gate.

**Repair:** derive vehicle-fit evidence from the actual supplied measurements/profile and fit-check result; derive weather evidence from the actual NWS observation/health result. Do not add a HIGH/checked item when no check occurred.

### 4. NWS successful-zero and failure both collapse to `[]`

`checkRouteWeather()` returns an empty array when offline and also after failures, while a successful NWS response with zero alerts also yields an empty array. It does set source health, including successful `alertCount: 0`, but the current decision evidence path does not consume that distinction.

**Repair:** preserve/use the NWS health/observation record so `OK + alertCount:0 + lastSuccess` means a successful zero-alert observation, while OFFLINE/TIMEOUT/HTTP/PARSE/no-observation remains unavailable. Zero alerts is data; no observation is not zero.

### 5. Evaluation-history evidence snapshot is not persisted

`logBid()` writes the bid outcome record and timestamp/time window, then lifecycle-links it. Exact-current source shows no compact evaluation confidence/evidence snapshot attached to that historical record. M3 evidence therefore cannot later prove what source state supported the decision at evaluation time.

**Repair:** persist a compact, bounded, secret-free snapshot of the material confidence/evidence state at the appropriate evaluation/bid-history boundary. Store identifiers/status/freshness/sample/observation-time/reasons only as needed; never credentials, raw API keys, or unbounded payloads.

### Required M3 regressions

1. Active fuel price manually entered while EIA health exists -> evidence says manual/user, not EIA.
2. EIA-applied fuel price -> EIA provenance + source timestamp survives and is shown.
3. Successful NWS zero alerts -> AVAILABLE/OK zero observation, not NO_DATA.
4. NWS failure/offline -> unavailable, never interpreted as zero alerts/clear weather.
5. Real lane/broker sample counts + observation timestamps reach evidence from actual aggregate queries.
6. No broker supplied -> broker evidence does not lower/raise overall material confidence.
7. Vehicle-fit evidence reflects actual known measurements/profile/check result; no hardcoded checked=true.
8. Saved evaluation/bid history retains a bounded secret-free evidence snapshot after reload.
9. Confidence/evidence changes do not change canonical verdict/grade/economics/bid.

Do not create a second decision engine or a second source-health registry while fixing this. M3 remains descriptive-only.
