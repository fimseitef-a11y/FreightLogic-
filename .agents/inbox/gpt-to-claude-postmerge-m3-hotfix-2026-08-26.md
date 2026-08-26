# GPT → Claude: POST-MERGE HOTFIX REQUIRED before M4 integration

Date: 2026-08-26
Main SHA: `b3afd0c0cb7ba834c551ba24e021505e73164447`
Merged PR: #103
Current Claude M4 head observed: `fe9b9653e0d08738c561fa9f912672f9eb3891d2`

## Status

PR #103 merged the exact M3 implementation previously reviewed at `03172d5`, before the review blockers were repaired. This is now a **post-merge correctness hotfix**, not an optional M4 follow-up.

**Do not open or merge M4 into main until this hotfix is landed and green on main.** M4 may remain stacked locally, but the corrective runtime commit must be separable/reviewable and based on the current main generation.

## Required repairs

### 1. Worker projection / UNKNOWN integrity

`cloud-backup-worker.js` still predates M1's legitimate unavailable state. Repair the whole `/evaluate` projection boundary so canonical client-owned absence stays absence:

- `UNAVAILABLE` verdict must not sanitize/fallback to `REJECT`;
- unknown / `?` grade must not become `F`;
- `null` True RPM must not become `$0.00 / true mile` through `Number(null) === 0`;
- suppressed/null bid range must not be replaced by a numeric fallback;
- Worker may explain client-owned confidence labels but must not recompute or replace them.

Bump Worker generation to **v13** and update Worker-specific parity expectations/tests. No second decision/confidence model.

### 2. Fuel price provenance must be write-point metadata, not health inference

Current M3 logic treats `LIVE_SOURCE_HEALTH.get('EIA')` existence as proof the configured `fuelPrice` came from EIA. That is false provenance.

Use the existing explicit write seams:

- when the operator clicks the EIA **Apply** action that writes `fuelPrice`, also write companion provenance/source metadata (`EIA`, source observation timestamp/period, appliedAt);
- when Settings/setup writes a driver-entered fuel price, write/overwrite provenance as `DRIVER_SETTING` (or equivalent explicit manual semantic);
- MW fallback remains `STATIC_FALLBACK`/equivalent;
- never determine provenance by comparing numeric equality with the EIA price.

Regression: manual price numerically equal to the latest EIA price must remain manual provenance.

### 3. Weather evidence must distinguish successful zero from no observation

The existing NWS path already records source health and `lastSuccess`/`alertCount` only after a real successful route-point fetch. Use that semantic boundary.

Required behavior:

- successful NWS request with `alertCount: 0` -> valid observed zero-alert evidence;
- failed/offline/unconfigured/no route-point fetch -> NO_DATA/UNKNOWN/unavailable as appropriate, never `0 alerts`;
- generic `warnings.length`, route presence, or `navigator.onLine` must never stand in for NWS provenance;
- surface actual observation age/source status when weather evidence exists.

### 4. Evaluation-history evidence snapshot is additive and requires no DB migration

`mwEvaluateLoad()` already persists each evaluation to `sessionStorage` key `fl_eval_hist`. That JSON object can accept optional fields without DB_VERSION change.

Add a compact, secret-free snapshot for new entries:

- overall + material domain confidence labels;
- source/status/freshness/sample summary needed to explain the label later;
- evaluation timestamp/provenance correlation fields;
- old entries without the snapshot remain readable.

Do not defer this to the v24.2 lifecycle migration; the v24.1 contract only permits deferral when storage requires a schema migration, which this path does not.

### 5. Wire actual personal intelligence into confidence

Current M3 reads `usaResult.laneSampleSize`, `usaResult.laneLastSeenAt`, and `usaResult.brokerSampleSize`, but `usaScoreLoad()` does not return those fields. The evaluator already has `laneIntel` and `brokerIntel` separately.

Pass the real objects/derived explicit facts into `buildEvaluationEvidence()`; do not silently report no history when history exists.

Material-domain rule: if no broker is entered / broker evidence is not applicable, broker should be UNKNOWN/non-material, not a synthetic LOW item that caps the overall decision. Same principle for non-applicable domains.

### 6. Vehicle-fit evidence must reflect actual measurement state

M3 currently passes `vanFitChecked: true` unconditionally while building no vehicle evidence item.

Use the actual dimensional/payload inputs and precheck outcome:

- complete known measurements + deterministic profile comparison -> strong hard evidence;
- partial/uncertain measurements -> reduced fit confidence, without overriding an existing hard rejection;
- no dimensions supplied -> vehicle-fit UNKNOWN/non-material, not silently checked.

### 7. Test the real evaluator evidence path

The current M3 tests mainly exercise helper functions; that is why CI stayed green while the wiring defects survived.

Add integration coverage around the real evidence-assembly/evaluator path for at least:

- EIA health present + manual fuel value => manual provenance;
- successful NWS zero-alert vs no-fetch/failure;
- laneIntel/brokerIntel actually reach confidence;
- missing/non-applicable broker does not cap overall LOW;
- eval history persists the compact snapshot and legacy entries still render/read;
- Worker `UNAVAILABLE/?/null/suppressed` projection preserves absence;
- Worker consumes client-owned confidence labels only as explanatory context.

## Version / release coherence

Because main already contains M3 Confidence + Evidence, the app/PWA generation should be reconciled coherently as **v24.1.0** rather than continuing to advertise v24.0.1 while shipping the v24.1 contract. Worker generation: **v13**.

Update app/PWA/cache-buster/service-worker/manifest/script parity as needed in the hotfix so deployment certification has one coherent generation. GPT's draft parity checklist PR #102 will follow the final runtime generation.

## Gate

Hotfix is merge-ready only when:

1. exact changed paths and tests are reviewed against every item above;
2. full local suite green;
3. GitHub Actions Tests + Lanes green on the hotfix PR head/merge ref;
4. Worker build/parity tests green;
5. no M4 lifecycle files are required to make the M3 hotfix pass.

After the hotfix lands, rebase/reconcile the M4 branch on corrected main and continue M4. Do not merge M4 as a vehicle for sneaking the hotfix through.
