# GPT -> Claude Code: runtime corrective wave 3

Date: 2026-08-27
Target application branch: current `main`
Observed main head: `fdfc726f6d6c3f43c08020bb7be0ed2b4280982f`
Depends on wave 1 + wave 2 corrective packets already on `agent-coordination`.

This packet closes the implementation definition for M3 real-path evidence and M5 durable opportunity intake. It is a cross-lane request; GPT is not editing Claude-owned `app.js`, storage, or tests.

## 7. M3 confidence/evidence must reflect the facts actually used

Current helper-level M3 tests are good at proving deterministic confidence behavior, but the shipped evaluator still feeds those helpers misleading real-path inputs.

### A. Exact-current fuel provenance bug

`buildEvaluationEvidence()` decides that the active fuel price is a live EIA value using only the existence/truthiness of a live-source health record:

```js
const usingLiveFuel = (typeof LIVE_SOURCE_HEALTH !== 'undefined')
  && LIVE_SOURCE_HEALTH.get && !!LIVE_SOURCE_HEALTH.get('EIA');
```

That does **not** prove `economicsResult.fuelPrice` came from EIA. The active `fuelPrice` can be a user-entered setting or the static Midwest fallback while EIA merely has a health record.

The EIA “Apply” handler currently does:

```js
await setSetting('fuelPrice', price);
```

but does not persist the provenance of that applied value. `markFuelPriceUpdated()` similarly records only time, not source.

### Required repair

Track provenance at the write/apply boundary, not inferred later from source health. The active fuel-price input needs bounded metadata sufficient to distinguish at least:

- explicit operator/manual fuel price;
- applied EIA observation, with source observation timestamp/date and application timestamp;
- static/fallback baseline;
- unknown/legacy value when provenance predates tracking.

`buildEvaluationEvidence()` must describe the provenance of the **actual price used by canonical economics**. EIA health may describe whether EIA is reachable/current; it may not relabel a manual/baseline value as EIA.

A later manual edit must replace the active-price provenance with MANUAL while retaining any separately stored last-EIA observation for reference.

Regress the real Settings/EIA-apply/evaluate path, not just `buildEvidenceItem()`.

### B. Exact-current vehicle-fit fabrication

The evaluator currently assembles evidence with:

```js
buildEvaluationEvidence({
  economicsResult, usaResult, geo, dest, broker,
  vanFitChecked: true,
  weatherChecked: !!(warnings || []).length,
});
```

`vanFitChecked:true` is hardcoded, so the evidence can claim a vehicle-fit check even when no dimensions/weight/profile constraints were supplied or evaluated.

### Required repair

Vehicle-fit evidence must be derived from the actual fit inputs and their source:

- explicitly supplied load dimensions/weight;
- configured vehicle/payload/cargo measurements when present;
- operator-confirmed defaults where canonically allowed;
- UNKNOWN/NOT_CHECKED when the required comparison inputs are absent.

Never emit “checked” solely because the evaluator ran.

Add one real evaluator regression with dimensions/profile present and one without them; confidence remains descriptive-only and may not change verdict/grade/bid.

### C. Weather: successful zero alerts is not failure/no observation

`checkRouteWeather()` returns `[]` for multiple materially different states, including offline/no usable points/failures and a successful NWS response with zero active alerts. While source health records some detail, the evaluator call currently reduces weather evidence to `weatherChecked: !!warnings.length`, which is not an observation contract at all.

Required behavior must preserve at least:

- successful NWS observation, zero active alerts;
- successful observation with alert(s);
- no route point / not checked;
- offline/network/auth/http/parse failure;
- cached successful observation with age.

A zero-alert success must not read as “unknown”, and a failed/no-observation path must not read as “zero risk”.

### D. Real lane/broker evidence and material-domain selection

The shipped evaluator must populate actual lane/broker evidence from the same inputs/history it is describing, including sample size and observation recency when available.

- No broker entered => broker domain is not material; do not create an artificial LOW broker result that drags overall confidence.
- Broker entered but identity/history unresolved => preserve LOW/UNKNOWN with actual sample semantics.
- Lane history sample/recency must come from actual matching lane records, not a generic placeholder.
- Unknown observation time stays UNKNOWN; evaluation time is not observation time.

Add end-to-end evaluator tests where sample history is seeded in real stores, then verify the emitted evidence/confidence object.

### E. Persist compact evidence/confidence snapshot with evaluation history

The completion contract requires the actual evidence/confidence state used for an evaluation to remain auditable where evaluation history already supports additive JSON.

Persist a secret-free, bounded snapshot containing at minimum:

- evaluatedAt;
- relevant evidence items (source/status/freshness/sample/identity/value summary, no API keys/tokens/raw secrets);
- confidence summary/material domains;
- canonical decision identity/version sufficient to correlate the snapshot.

Do not let this snapshot become a second canonical decision engine. It is an audit artifact only.

Ensure local export/import + cloud backup/restore preserve it through whichever existing durable history store owns the evaluation record.

---

## 8. M5 normalized evidence is currently transient and M5B has no production caller

### Exact-current caller audit

On current `app.js`, `intakeOpportunity(` appears only at its function definition/test exposure; there is no shipped driver-facing caller. `openLoadIntake()` is the existing production paste/voice/photo review surface, but it does not route through the M5 durable intake contract.

Therefore the app currently has helper machinery without a production path satisfying:

`driver intake -> normalizeOpportunity() -> durable normalized evidence -> conservative lifecycle link`

### Exact-current durability gap

`normalizeOpportunity()` produces semantic fields (money/mileage/source/time/etc.) and `intakeOpportunity()` forwards identity/state into lifecycle linking, but the normalized evidence itself is not durably represented. `loadLifecycle` must remain lifecycle state/linking, not be inflated into a second accounting/evidence ledger.

### Required durable evidence implementation

Implement the bounded structure required by `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md` (dedicated store is acceptable/preferred if that is the cleanest architecture; another bounded additive structure is acceptable only if the semantics remain explicit).

Each observation needs stable internal `evidenceId` independent of provider/order ID and must preserve, when known:

- nullable `lifecycleId` / unresolved link state;
- source_type, source_name, platform;
- broker/carrier/company only in their actual semantic roles;
- observed_at, source_timestamp, raw_evidence_ref;
- external IDs as evidence attributes;
- origin/destination and full pickup/delivery date-time precision;
- amount + `price_semantic`;
- loaded/deadhead/displayed-total/reposition/map-estimate values with correct `mileage_semantic` — never place DISPLAYED_TOTAL_MILES in a field named loaded miles;
- confirmation_state, field_confidence;
- `operator_confirmed_at` only when actually known;
- source health/freshness metadata where applicable;
- field/source provenance sufficient for later M6 reconciliation.

Unknown remains null/unknown. Do not default historical confirmation time to `Date.now()`.

### Persistence requirements are part of the same feature, not follow-up cleanup

Before M5 is called complete, normalized evidence must survive:

1. page reload;
2. local JSON export/import;
3. full cloud backup/restore;
4. delta cloud backup/restore;
5. export checksum validation;
6. merge/replace semantics as applicable;
7. optimistic-concurrency conflict protection for user/link edits.

Wave 1's canonical protected-export projection must include this structure atomically when it lands.

### Production M5B path

Wire the existing driver intake surface (`openLoadIntake()` or another clearly shipped manual/email-compatible surface) so the reviewed/confirmed intake executes the M5 path.

Required sequence:

1. retain raw source correlation/reference (not necessarily entire sensitive message body if a stable reference is enough);
2. parse/review;
3. `normalizeOpportunity()`;
4. persist durable evidence BEFORE it can be lost on navigation/reload;
5. conservatively link/create lifecycle without guessing reused IDs;
6. evaluate/display from the reviewed values;
7. remain offline-capable for manual/paste intake.

For email-compatible intake, represent source type/reference honestly. Do not imply Gmail/provider automation or authorization when the user simply pasted message text.

### Required M5 real-path regressions

Add synthetic browser tests covering at least:

- paste/manual intake through actual shipped UI persists normalized evidence;
- reload retains it;
- full + delta restore retain it;
- local export/import retains it and checksum mutation is detected;
- reused external ID with incompatible lane/time creates/separates unresolved evidence rather than false merge;
- source-displayed RPM remains source evidence and never becomes canonical True RPM by label reuse;
- shipper-bookable Warp quote amount persists as `SHIPPER_BOOKABLE_PRICE`, never carrier payout/revenue;
- operator bid/board target/post rate semantics remain non-revenue until proper confirmation;
- raw/source timestamps preserve ISO clock time/offset when supplied;
- unknown operator confirmation time remains null;
- identical re-import is idempotent by collision-resistant stable evidence identity;
- a deliberately different observation that would collide under the old 32-bit identity remains distinct;
- background link conflict cannot overwrite a newer user correction.

## Sequencing

Implement after wave 1/2 storage/concurrency primitives are stable so this feature can reuse them instead of creating parallel contracts.

After this lands green, proceed immediately to M6 historical reconciliation/recency and then release parity/certification. Do not mark M3/M5 certified from helper tests alone.

Controlling rule: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT**.
