# GPT -> Claude: Completion Release Milestone 1

Date: 2026-08-25
Owner request: Claude core lane
User authorization: standing instruction is to proceed with the FreightLogic roadmap without redundant approval pauses; repository lock/test/lane rules still apply.

## Current main at handoff

`96224bc04ede159ffd09bc57d574a7938e2e927e`

Do a fresh fetch before claiming work and use the actual current main SHA if it advanced.

## Required first action

Claim the appropriate `agent-coordination` lock(s), including `lock/app-js` before any `app.js` edit. Do not start protected work until the lock claim is confirmed. Log baseline/test results in `TEST_LEDGER.md` and substantive state in `STATUS.md`.

## Milestone 1 — doctrine + money-integrity certification

This is now the highest-priority completion-release work and should precede PR #87 runtime reconciliation.

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

3. Canonical-path requirement
   - Audit `app.js` intake + `buildUnifiedDecisionContract()` facts/economics path for the same unknown-vs-zero conflation.
   - Unknown loaded/deadhead mileage must never become zero merely to produce a numeric True RPM.
   - Unknown core economics should be unavailable/provisional, not falsely precise.
   - Add/normalize mileage source status `VERIFIED | ESTIMATED | UNKNOWN` while keeping loaded, deadhead/empty, platform-displayed, and post-delivery reposition mileage distinct.

## Architecture boundaries

- Do not create another decision/bid engine.
- `app.js` Unified Decision Engine remains sole authority for verdict, grade, economics, and bid.
- `midwest-stack-authority.js` remains `ADAPTER_ONLY` / evidence presentation.
- Do not let stale/static/live external evidence relax protective floors.
- Do not change DAT RateView into cargo-van authority; `dat-rateview.js` stays dormant/non-authoritative unless the owner later explicitly re-authorizes a bounded role.
- Do not mix this parity repair with v24.1 confidence implementation or broad refactoring.

## Tests required

Add or extend Claude-owned tests to prove at minimum:

- exact grade boundaries remain unchanged;
- Toledo is Tier 1;
- Cincinnati is Tier 1;
- F20/DZ exact `0.90` floor behavior and the full condition matrix;
- blank/null/undefined/non-finite revenue/mileage facts do not become zero;
- unknown deadhead cannot manufacture a precise True RPM;
- explicit zero remains distinguishable from unknown where zero is a valid real input;
- mileage provenance status survives canonical decision projection;
- Midwest overlay remains advisory and cannot become verdict/bid authority;
- existing v24 authority tests remain unchanged/green.

Any `app.js` change requires full `node tests/run-all.mjs` suite. Record exact SHA and result.

## After Milestone 1 green

Immediately continue with:

1. revalidate `R-TOCTOU-EXPENSE-FUEL`; fix only if still reproducible, with focused regression coverage;
2. rebase/reconcile PR #87 onto current main **after** parity fixes, preserving its descriptive categorical confidence contract;
3. report any PR #87 conflicts caused by the parity changes rather than weakening either contract;
4. after v24.1 is green, proceed to v24.2 lifecycle using PR #89 contract after disposition.

## Definition of done for this handoff

Milestone 1 is done only when the canonical path cannot manufacture precise economics from unknown operational inputs, v11/Level X+ geography/F20 parity is exact, and the full suite is green on the exact implementation head.
