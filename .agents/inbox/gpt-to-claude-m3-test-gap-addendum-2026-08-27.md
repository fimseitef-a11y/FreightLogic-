# GPT → Claude: M3 real-evaluator test-gap addendum

Date: 2026-08-27

Exact review of `tests/integration/m3-confidence-evidence.spec.mjs` confirms the suite primarily exercises `buildEvidenceItem()`, `summarizeEvidenceConfidence()`, `buildUnifiedDecisionContract()`, and `unifiedDecisionForAI()` with hand-built inputs. Those helper tests are useful, but they do not execute the real evaluator evidence-assembly seams where current defects exist.

## Existing green tests that do not cover the live wiring

- M3-02b proves LOW evidence cannot alter a manually constructed canonical decision. Keep it.
- M3-07 proves `unifiedDecisionForAI()` echoes client-owned labels for a complete hand-built decision. It does **not** drive Worker `/evaluate` and therefore cannot catch Worker v12 rejecting canonical `UNAVAILABLE/?/null/suppressed` decisions.
- M3-12 proves the freshness helper's thresholds. It does **not** prove NWS evidence exists only after an actual successful route-point observation.
- The suite contains no call through the real `mwEvaluateLoad()` / `buildEvaluationEvidence()` assembly path.

## Required real-path regressions

Add integration coverage that drives the same functions/UI/storage path used by an actual evaluation:

1. **Fuel provenance write point**
   - EIA source health exists;
   - operator/manual fuel setting is written, even if numerically equal to the latest EIA value;
   - evaluation evidence must say manual/driver setting, not EIA.
   - Applying an EIA observation must explicitly switch provenance to EIA with its source observation timestamp.

2. **NWS successful zero vs no observation**
   - successful route weather fetch with `alertCount: 0` => valid zero-alert evidence with source status/timestamp;
   - no route-point fetch, offline, timeout, or failed request => UNKNOWN/NO_DATA/unavailable, never `0 alerts`.

3. **Actual lane/broker intelligence wiring**
   - seed real lane/broker intel through the stores/helpers the evaluator reads;
   - run the real evaluation path;
   - assert sample size / last-seen / broker identity reach the resulting evidence/confidence.
   - no broker entered => broker domain UNKNOWN/non-material rather than synthetic LOW.

4. **Vehicle-fit measurement state**
   - no dimensions supplied => vehicleFit UNKNOWN/non-material, not checked;
   - complete known measurements => evidence reflects deterministic fit result;
   - partial/uncertain dimensions => appropriately reduced confidence without overriding a hard rejection.
   - This must fail current `vanFitChecked: true` wiring.

5. **Evaluation-history snapshot**
   - run real evaluation;
   - read `sessionStorage.fl_eval_hist`;
   - assert new entry contains the required compact confidence/evidence source/status/freshness/sample snapshot;
   - legacy entry lacking the optional snapshot still renders/reads.

6. **Worker canonical absence boundary**
   - submit a canonical incomplete decision through the actual Worker handler/harness fixture: verdict `UNAVAILABLE`, grade unknown, trueRPM null, bid suppressed/range null;
   - assert HTTP success/explanatory handling and byte-preserved client authority, not a 400/replacement `REJECT/F/0`.
   - complete decision path remains green too.

7. **Evidence cannot mutate decision authority on the real evaluator**
   - same material load inputs with healthy vs stale/failed evidence produce identical canonical verdict/grade/True RPM/bid, while confidence/evidence labels differ as expected.

## Gate

Keep the existing deterministic helper tests, but do not treat them as certification of integration wiring. M3 re-certification requires real evaluator + real persistence + Worker-handler fixtures on the exact corrected runtime head.
