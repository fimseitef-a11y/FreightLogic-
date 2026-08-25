# GPT -> Claude: Completion Release Milestone 1

Date: 2026-08-25
Owner request: Claude core lane
User authorization: standing instruction is to proceed with the FreightLogic roadmap without redundant approval pauses; repository lock/test/lane rules still apply.

## Current main at latest handoff update

`fbe6922bb5a69d5dd545013106272209be7250d9`

This includes the docs-only finite completion release plan from PR #90. Do a fresh fetch before claiming work and use the actual current main SHA if it advanced.

Fresh current-runtime baseline evidence before core edits: PR #90 synthetic merge ref `de77f9c6990ca3ff11ce3d850fbcad8679c8528e`, GitHub Actions run `32833036042` / job `97755739019`, `node tests/run-all.mjs` => **119 passed, 0 failed across 19 specs**, no rerun. PR #90 was docs-only, so runtime/test bytes matched base main `96224bc...`; after merge only the completion-plan doc changed.

## Required first action

Claim the appropriate `agent-coordination` lock(s), including `lock/app-js` before any `app.js` edit. Do not start protected work until the lock claim is confirmed. Log baseline/test results in `TEST_LEDGER.md` and substantive state in `STATUS.md`.

## Milestone 1 — doctrine + money-integrity certification

This is now the highest-priority completion-release work and must precede PR #87 runtime reconciliation.

Current-source confirmed defects:

1. `midwest-stack-config.json`
   - `appTarget` still says `FreightLogic v23.5.x`.
   - authority is still `Midwest Stack v2 - Operator System`.
   - effective date is still `2026-05-27`.
   - Toledo remains Tier 2.
   - Cincinnati remains Tier 2.
   Latest governing doctrine requires Toledo and Cincinnati in Tier 1 and the v11/Level X+ authority generation to supersede the older May source.

2. `midwest-stack-authority.js`
   - `CONFIG.modes.DEAD_ZONE.floor` is still `0.91`; formal absolute F20/DZ floor is `0.90`.
   - `CONFIG.hardStops.absoluteTrueRpmReject` is already `0.90`, so the overlay currently contains an internal floor mismatch.
   - `marketRoles.tier2` still includes Toledo/Cincinnati and `tier1` does not.
   - `finite(value, fallback)` uses `Number(value)` and falls back to zero; `assessLoad()` calls it for revenue, loaded miles, deadhead miles, weight, etc. Missing numeric operational facts can therefore become false zeroes and manufacture precise True RPM/economics.

3. `app.js` canonical path — now independently confirmed, not merely an audit request
   - `deriveUnifiedEconomics(facts)` currently does:
     - `Math.max(0, Number(f.loadedMi || 0))`
     - `Math.max(0, Number(f.deadMi || 0))`
     - `Math.max(0, Number(f.revenue || 0))`
     - and returns `trueRPM = 0`, `loadedRPM = 0`, `breakEvenRPM = 0`, `deadheadPct = 0`, etc. when required facts are absent. This explicitly collapses UNKNOWN into a real numeric zero.
   - `deriveUnifiedGrade(trueRPM)` currently does `Number.isFinite(Number(trueRPM)) ? Number(trueRPM) : 0`, so an unknown RPM is converted into an authoritative F/REJECT grade rather than represented as unavailable/provisional.
   - `deriveUnifiedAuthority(facts)` currently normalizes `trueRPM`, `totalMi`, `deadheadPct`, `effectiveRevenue`, `netAfterFuel`, `profitMarginPct`, and other material facts through `Number(f.x || 0)`, again collapsing missing facts to real zeroes before hard-gate logic and driver-facing detail strings.
   - Therefore Milestone 1 must repair the canonical contract itself, not only the standalone Midwest adapter.
   - Unknown loaded/deadhead mileage or revenue must never become zero merely to produce a numeric True RPM/grade/verdict. Core economics should become explicitly unavailable/provisional until required facts exist. If the product chooses a conservative safety state for an incomplete load, that state must be distinguished from a calculated `$0.00/mi` load and must not pretend the economics were computed.
   - Add/normalize mileage source status `VERIFIED | ESTIMATED | UNKNOWN` while keeping loaded, deadhead/empty, platform-displayed, and post-delivery reposition mileage distinct.

## Architecture boundaries

- Do not create another decision/bid engine.
- `app.js` Unified Decision Engine remains sole authority for verdict, grade, economics, and bid.
- `midwest-stack-authority.js` remains `ADAPTER_ONLY` / evidence presentation.
- Do not let stale/static/live external evidence relax protective floors.
- Do not change DAT RateView into cargo-van authority; `dat-rateview.js` stays dormant/non-authoritative unless the owner later explicitly re-authorizes a bounded role. Current `index.html` and `service-worker.js` do not load or precache `dat-rateview.js`, so its dormant state is presently intact.
- Do not mix this parity repair with v24.1 confidence implementation or broad refactoring.

## Tests required

Add or extend Claude-owned tests to prove at minimum:

- exact grade boundaries remain unchanged for complete valid facts;
- Toledo is Tier 1;
- Cincinnati is Tier 1;
- F20/DZ exact `0.90` floor behavior and the full condition matrix;
- blank/null/undefined/non-finite revenue/mileage facts do not become zero;
- unknown deadhead cannot manufacture a precise True RPM;
- unknown revenue cannot manufacture `$0.00/mi` economics that look calculated;
- unknown RPM cannot flow through `deriveUnifiedGrade()` as a real numeric 0 without an explicit incomplete/provisional contract;
- incomplete facts cannot produce an apparently complete canonical verdict/bid decision;
- explicit zero remains distinguishable from unknown where zero is a valid real input (for example real `deadMi: 0`);
- mileage provenance status survives canonical decision projection;
- Midwest overlay remains advisory and cannot become verdict/bid authority;
- existing v24 authority/economics tests remain unchanged/green for valid complete inputs.

Any `app.js` change requires full `node tests/run-all.mjs` suite. Record exact SHA and result.

## After Milestone 1 green

Immediately continue with:

1. revalidate `R-TOCTOU-EXPENSE-FUEL`; fix only if still reproducible, with focused regression coverage;
2. rebase/reconcile PR #87 onto current main **after** parity fixes, preserving its descriptive categorical confidence contract. A GPT review note is already attached to PR #87 documenting these blockers; preserve its strict `_evidenceNum`, categorical confidence, source health/freshness, and descriptive-only authority boundary during reconciliation;
3. report any PR #87 conflicts caused by the parity changes rather than weakening either contract;
4. after v24.1 is green, proceed to v24.2 lifecycle using clean rebased PR #91 (`docs/V24_2_LOAD_LIFECYCLE_SPEC.md`) after its docs gate/disposition. PR #89 was closed unmerged as the stale/diverged predecessor.

## Definition of done for this handoff

Milestone 1 is done only when the canonical path cannot manufacture precise economics from unknown operational inputs, v11/Level X+ geography/F20 parity is exact, and the full suite is green on the exact implementation head.
