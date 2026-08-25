# GPT -> Claude: Completion Release Milestone 1

Date: 2026-08-25
Owner request: Claude core lane
User authorization: standing instruction is to proceed with the FreightLogic roadmap without redundant approval pauses; repository lock/test/lane rules still apply.

## Current main at latest handoff update

`3a26a974d959efadb079340f6235abb8224acd81`

This includes the docs-only finite completion release plan from PR #90 and the docs-only v24.2 lifecycle contract from PR #91. Do a fresh fetch before claiming work and use the actual current main SHA if it advanced.

Fresh current-runtime baseline evidence before core edits:

- PR #90 synthetic merge ref `de77f9c6990ca3ff11ce3d850fbcad8679c8528e`, GitHub Actions run `32833036042` / job `97755739019`, `node tests/run-all.mjs` => **119 passed, 0 failed across 19 specs**, no rerun.
- PR #91 synthetic merge ref `4643ddc53d4ba791ebd42ee66f5c4790b43cee8f`, GitHub Actions run `32833614614` / job `97757536353`, `node tests/run-all.mjs` => **119 passed, 0 failed across 19 specs**, no rerun.
- Both PRs were docs-only, so current application/runtime/test bytes remain the same runtime tree audited below.

## Required first action

Claim the appropriate `agent-coordination` lock(s), including `lock/app-js` before any `app.js` edit. Do not start protected work until the lock claim is confirmed. Log baseline/test results in `TEST_LEDGER.md` and substantive state in `STATUS.md`.

## Milestone 1 — doctrine + money-integrity certification

This is now the highest-priority completion-release work and must precede PR #87 runtime reconciliation.

Current-source confirmed defects:

### 1. `midwest-stack-config.json`

- `appTarget` still says `FreightLogic v23.5.x`.
- authority is still `Midwest Stack v2 - Operator System`.
- effective date is still `2026-05-27`.
- Toledo remains Tier 2.
- Cincinnati remains Tier 2.

Latest governing doctrine requires Toledo and Cincinnati in Tier 1 and the v11/Level X+ authority generation to supersede the older May source.

### 2. `midwest-stack-authority.js`

- `CONFIG.modes.DEAD_ZONE.floor` is still `0.91`; formal absolute F20/DZ floor is `0.90`.
- `CONFIG.hardStops.absoluteTrueRpmReject` is already `0.90`, so the overlay currently contains an internal floor mismatch.
- `marketRoles.tier2` still includes Toledo/Cincinnati and `tier1` does not.
- `finite(value, fallback)` uses `Number(value)` and falls back to zero; `assessLoad()` calls it for revenue, loaded miles, deadhead miles, weight, etc. Missing numeric operational facts can therefore become false zeroes and manufacture precise True RPM/economics.

### 3. `app.js` canonical path — independently confirmed, not merely an audit request

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

### 4. `app.js` canonical Midwest geography + display taxonomy are also stale

- Canonical `MW.tier1` is currently `['chicago','indianapolis','cleveland','columbus','detroit']`.
- Canonical `MW.tier2` still contains `cincinnati` and `toledo`.
- Therefore the canonical `mwGeoCheck()` path itself still treats Cincinnati and Toledo as Tier 2; this is not limited to the standalone config/adapter.
- `MW.rpmTiers` still labels `$1.35–$1.49` as `Minimum Standard` / ACCEPT, while the canonical v24 authority floor is `$1.40` and `deriveUnifiedGrade()` uses D from `$1.40–$1.49`.
- The rendered grade ladder also still displays `D — WEAK — NEGOTIATE — $1.35–$1.49` and `E — STRATEGIC ONLY — $1.25–$1.34`, which conflicts with the governing Level X+ bands `D $1.40–$1.49`, `E $1.25–$1.39`.
- Do not merely change visible copy while leaving `MW.rpmTiers` stale. Reconcile the shared taxonomy so helper classifications and driver-facing labels cannot disagree with the canonical authority.
- `MW.dzFloorRPM` itself is already correctly `0.90`; preserve that while aligning the standalone adapter/config to it.

## Architecture boundaries

- Do not create another decision/bid engine.
- `app.js` Unified Decision Engine remains sole authority for verdict, grade, economics, and bid.
- `midwest-stack-authority.js` remains `ADAPTER_ONLY` / evidence presentation.
- Do not let stale/static/live external evidence relax protective floors.
- Do not change DAT RateView into cargo-van authority; `dat-rateview.js` stays dormant/non-authoritative unless the owner later explicitly re-authorizes a bounded role. Current `index.html` and `service-worker.js` do not load or precache `dat-rateview.js`, so its dormant state is presently intact.
- Do not mix this parity repair with v24.1 confidence implementation or broad refactoring.

## Tests required

Add or extend Claude-owned tests to prove at minimum:

- exact Level X+ grade boundaries remain internally consistent for complete valid facts: A `>=1.75`, B `1.60–1.74`, C `1.50–1.59`, D `1.40–1.49`, E `1.25–1.39`, Reject `<1.25` outside active DZ;
- `MW.rpmTiers`, `deriveUnifiedGrade()`, canonical authority thresholds, and rendered ladder copy cannot drift from one another;
- Toledo is Tier 1 through the canonical `mwGeoCheck()` path and adapter/config mirrors;
- Cincinnati is Tier 1 through the canonical `mwGeoCheck()` path and adapter/config mirrors;
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

1. fix `R-TOCTOU-EXPENSE-FUEL`; it has now been statically reconfirmed on current main, so it is no longer a mere revalidation item. Exact defect and two-tab regression requirements are in `/.agents/inbox/gpt-to-claude-m2-toctou-confirmed-2026-08-25.md`;
2. rebase/reconcile PR #87 onto current main **after** parity + TOCTOU fixes, preserving its descriptive categorical confidence contract. A GPT review note is already attached to PR #87 documenting the Milestone-1 blockers; preserve its strict `_evidenceNum`, categorical confidence, source health/freshness, and descriptive-only authority boundary during reconciliation;
3. report any PR #87 conflicts caused by the parity changes rather than weakening either contract;
4. after v24.1 is green, implement v24.2 lifecycle against merged `docs/V24_2_LOAD_LIFECYCLE_SPEC.md` from PR #91. PR #89 was closed unmerged as the stale/diverged predecessor.

## Definition of done for this handoff

Milestone 1 is done only when the canonical path cannot manufacture precise economics from unknown operational inputs, Level X+ geography/grade/F20 parity is exact across canonical + adapter + display surfaces, and the full suite is green on the exact implementation head.
