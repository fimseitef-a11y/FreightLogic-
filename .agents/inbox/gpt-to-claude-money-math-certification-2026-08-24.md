# GPT → Claude: Money-Math / True-RPM Certification

Date: 2026-08-24
User authorization: user said to proceed with FreightLogic. Existing standing authorization still applies; lane/lock/full-suite rules remain mandatory.

## Goal
Certify the existing v24 canonical economics engine before adding new live market feeds or redesigning decision logic. Do **not** create a second money engine. `deriveUnifiedEconomics`, `deriveUnifiedAuthority`, and `deriveUnifiedBid` remain the canonical client-owned path unless a defect is proven.

## Requested scope (Claude-owned `tests/` + core review)
1. Add a narrow golden-economics regression suite around `deriveUnifiedEconomics` using explicit, deterministic inputs.
2. Include at least one operator-verified FreightLogic historical load shape as a golden case.
3. Review the economics contract for the edge cases below.
4. If the tests expose a production defect, stop and report the exact defect + proposed minimal repair before changing `app.js`.
5. Full `node tests/run-all.mjs` gate is required for any `app.js` change.

## Golden operator case
Use this only as a deterministic certification case; the fuel price/op-cost assumptions below are test inputs, not a claim about the actual fuel receipt for that historical trip.

Historical load: Adrian, MI → Tulsa, OK (#632684)
- revenue: 1050
- loadedMi: 851
- deadMi: 97
- totalMi expected: 948
- mpg: 17.5
- fuelPrice: 4.54
- opCPM: 0.40 (explicitly excludes fuel)
- borderAdminCost: 0

Expected current-engine outputs (cent-rounded, matching current contract):
- trueRPM: 1.11
- loadedRPM: 1.23
- fuel: 245.94
- operatingCost: 379.20
- totalCost: 625.14
- trueProfit: 424.86
- profitMarginPct: 40.46
- breakEvenRPM: 0.66
- profitPerMile: 0.45
- estHours: 19
- profitPerHour: 22.36

## Edge cases to certify / review

### A. Raw-vs-rounded floor authority
Current `deriveUnifiedEconomics` rounds `trueRPM` to cents before downstream classification/authority. Test values immediately below hard boundaries (for example raw 1.394, 1.395, 1.399, 1.400; and equivalents near 1.50) and document whether the intended policy is:
- decision authority on raw RPM with display rounding, or
- authority on cent-rounded RPM.
Do not silently change this policy; surface the result.

### B. Missing operating-cost setting
When `opCPM === 0`, the engine deliberately falls back to fuel-only margin checks. Verify the UI/contract never represents that case as full all-in profitability. This should integrate cleanly with the planned v24.1 `operatingCosts` confidence domain.

### C. “After all costs” semantics
`deriveUnifiedEconomics` currently models fuel + `opCPM` + border admin cost. Known trip-specific tolls/parking/lumper/other one-off costs are not part of the canonical economics input. Review whether any UI says “after all costs” in a way that could overstate certainty when those costs are known but unrepresented. Prefer semantic correction before formula expansion unless product scope explicitly adds trip-specific cost inputs.

### D. Operating-cost double-count guard
The Settings UI correctly labels `opCostPerMile` as “excl. fuel.” Add a regression guard/documentation assertion so future changes do not treat an all-in CPM as fuel-exclusive and then add fuel again.

### E. Profit-per-hour semantics
Current `estHours = max(1, round(totalMi / 50))`. Verify this is clearly an estimate and not represented as actual trip labor time; it excludes wait/loading/sleep/dwell. No redesign required unless labeling is misleading.

### F. Zero / malformed inputs
Certify no divide-by-zero/NaN/negative-value leakage for zero loaded miles, zero total miles, zero MPG, negative revenue/cost inputs, and missing fields.

## Architecture constraint
This certification is intentionally prior to Live Market Snapshot / Warp / Direct Freight / 123Loadboard runtime work. Market feeds must eventually feed evidence into the existing canonical decision path, not create parallel economics or bid authorities.

## No DAT expansion
`dat-rateview.js` remains frozen/non-authoritative for cargo-van expedite. Do not build certification around DAT dry-van rates.
