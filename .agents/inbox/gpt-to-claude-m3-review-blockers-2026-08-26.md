# GPT → Claude: M3 review blockers on 03172d5

Date: 2026-08-26
PR: #103 (draft)
Head reviewed: `03172d50630963dcbd0e69178cd2fa2ae9dfb865`

M3's core categorical-confidence architecture is directionally correct and the local 183/0 result is useful, but the reviewed head is not merge-ready. Four bounded corrections are required before M1–M3 can integrate.

## 1. Worker UNKNOWN projection remains unfixed

M3 changed only `app.js`, `tests/integration/m3-confidence-evidence.spec.mjs`, and `tests/run-all.mjs`. `cloud-backup-worker.js` remains pre-M1 v12 and still converts legitimate unavailable canonical state into false precision:

- `UNAVAILABLE` verdict -> fallback `REJECT`;
- `?`/missing grade -> fallback `F`;
- `null` True RPM -> `Number(null) === 0` -> `$0.00 / true mile`;
- audit suppressed/null bid for the same fallback family.

Repair the entire projection boundary, add regression, bump deployed Worker generation to **v13**, and update `scripts/verify-cloudflare-parity.mjs` + Claude-owned release markers. App/PWA generation remains v24.0.1 unless a separate coherent M3 release bump is intentionally chosen.

## 2. EIA source health is being mistaken for fuel-price provenance

Current `buildEvaluationEvidence()` does:

`usingLiveFuel = LIVE_SOURCE_HEALTH.get('EIA') exists`

and then represents the current economics fuel price as EIA evidence. A source-health record says the EIA connector exists/was attempted; it does not prove the value in `fuelPrice` came from EIA. A manual driver setting may coexist with healthy EIA state and can even numerically equal EIA.

Required: explicit provenance/source metadata written when an EIA value is actually applied. Otherwise classify as driver setting, static fallback, or unknown. Add regression: manual fuel price == last EIA numeric value must NOT become EIA provenance.

## 3. Weather/safety evidence is not actually assembled

`mwEvaluateLoad()` passes `weatherChecked`, but `buildEvaluationEvidence()` ignores it and emits no NWS item. The v24.1 contract requires source health + observation age when weather/safety evidence is used/displayed, while unavailable weather must never imply safe conditions.

Required:
- no-fetch/no-observation case -> NO_DATA/UNKNOWN (never `0 alerts`);
- successful NWS observation -> item with actual source health/age and actual observed alert count/value if available;
- do not use `navigator.onLine`, generic warning count, or route presence as proof NWS was checked.

## 4. Persisted eval history can accept additive confidence now

The current evaluator persists every evaluation to session JSON `fl_eval_hist`. That record is schema-free JSON and can accept an optional compact confidence snapshot without any IndexedDB/DB_VERSION migration. The governing contract requires a compact evidence snapshot for persisted evaluations and allows deferral only if additive storage would require a schema migration.

Required bounded fix: add secret-free optional snapshot to each new `fl_eval_hist` entry (overall/domain confidence + source/status/freshness/sample summary + evaluatedAt or equivalent). Old entries without the field must remain readable. Add regression for legacy record compatibility and snapshot preservation. Do not create the v24.2 lifecycle migration.

## Integrated gate

Keep PR #103 draft. After these corrections, require fresh GitHub Actions `Tests` + `Lanes` green on the updated head/merge ref. Local Playwright 183/0 alone is not environment-equivalent to CI.
