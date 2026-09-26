# GPT → Claude: Milestone 3 / PR #87 reconciliation packet

Date: 2026-08-26
Target: reconcile PR #87 (`claude/proceed-l4aacv`, old head f66d28c...) onto integrated Milestones 1+2 main.
Owner: Claude core (`app.js`, `cloud-backup-worker.js`, Midwest core, tests, release markers); GPT handles docs-only parity checklist separately.

## Gate

Do not start the M3 merge until PR #103 (M1+M2) is integrated green and its Worker UNKNOWN projection blocker is closed. Then rebase/reconstruct v24.1 from the then-current `main`; do not merge the old PR #87 tree wholesale.

## Architecture to preserve from old PR #87

- categorical `HIGH | MEDIUM | LOW` confidence only; no calibrated win percentage;
- strict evidence numeric guard (`null`/blank must not become 0);
- source-health + freshness + sample-size + provenance evidence items;
- confidence is descriptive only and cannot alter verdict, grade, True RPM, economics, protective floor, or bid authority;
- domain/overall aggregation is conservative, not an average;
- missing/no-data/source-unavailable remain visibly distinct;
- client owns confidence labels; Worker may explain/project only;
- additive optional persistence only; no v24.2 lifecycle migration.

## Mandatory post-M1/M2 reconciliation rules

1. **Preserve M1 UNKNOWN semantics.** Do not reintroduce `Number(null)`, `Number(x || 0)`, default `F`, default `REJECT`, or `$0` for missing canonical facts. `factsComplete`, `unknownFacts`, unavailable economics, `?` grade, suppressed bid range, and mileage provenance remain authoritative.
2. **Preserve M1 doctrine.** Cincinnati + Toledo stay Tier 1 in canonical/overlay/config; Level X+ bands stay A>=1.75, B 1.60-1.74, C 1.50-1.59, D 1.40-1.49, E 1.25-1.39, reject below 1.25 outside DZ; F20/DZ floor stays exactly 0.90; fallback MPG stays 17.5 with explicit user MPG overriding.
3. **Preserve M2 concurrency.** `sanitizeExpense`/`sanitizeFuel` revision preservation, add first-stamp, compare-and-abort `FL_CONFLICT`, edit-form revision carriage, and F-8 no-id-on-new-record tests must remain byte/behavior compatible.
4. **Current roadmap only.** `docs/V24_ROADMAP.md` was retired. Any source comments/docs/runtime pointers introduced by PR #87 must reference `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` plus the governing v24.1 contract, not recreate or point to the deleted roadmap.

## Known defects in old PR #87 that MUST NOT survive reconciliation

### A. False EIA provenance by price equality

Old PR #87 inferred `fuelPriceSource = 'EIA_LIVE'` when configured fuel price numerically equaled the last EIA price. Numeric equality is not provenance: the driver can manually enter the same number. Replace with an explicit source marker/metadata written when the EIA value is actually applied, or classify as driver setting/static fallback when provenance is not explicitly known. UNKNOWN provenance must stay unknown; do not guess.

### B. Weather `0 alerts` without an observed weather result

Old PR #87 sets `weatherChecked` from online + route presence and `weatherAlertCount: 0`, then builds NWS evidence. That can claim a healthy current `0 active alerts` without a route-weather observation ever being fetched. Evidence may say `0 alerts` only from an actual successful NWS result tied to the route/query. Otherwise use NO_DATA / SOURCE_UNAVAILABLE / UNKNOWN as appropriate. `navigator.onLine` is not evidence that NWS was checked.

### C. Worker UNKNOWN/default coercion

M1 makes canonical unavailable/null states legitimate. Worker projection must preserve `UNAVAILABLE`/missing verdict, `?`/missing grade, null True RPM, and suppressed/null bid without converting any of them to REJECT/F/$0.00/$0. This blocker is already attached to PR #103; M3 Worker changes must keep that repaired boundary.

### D. Static/fallback source semantics

Old PR #87 classifies fallback evidence MEDIUM by default. Keep the governing confidence contract and Gate-0 provenance rule: static fallback may be useful, but must never be represented as live/personal observation, and stale fallback is LOW. If exact provenance/age is unknown, confidence cannot silently become HIGH.

### E. Operator truth / provider semantics

Do not treat Warp shipper-bookable price as carrier payout or expected carrier revenue. 123Loadboard and Direct Freight free-account access is not API authorization. DAT RateView remains dormant/non-authoritative. M3 should not add provider adapters or new feeds.

## Worker boundary required in M3

- Client-computed confidence labels are the only labels the Worker may return/project.
- AI output cannot publish a competing confidence label/score/probability.
- Low confidence means verify evidence, not lower the floor.
- Missing/failed/stale evidence remains missing/failed/stale, never safe/zero/favorable.
- Preserve repaired M1 UNKNOWN canonical projection at the same boundary.

## Release/version integration

M1 establishes app/PWA generation v24.0.1 with Worker v12. M3 may advance to v24.1.0 / Worker version as required, but every version/cache-buster/parity surface must move coherently. GPT draft PR #102 is only the M1 v24.0.1 markdown parity checklist and must be reconciled/closed appropriately once M3 supersedes it; do not leave a stale intermediate checklist on main.

## Required regression envelope

- all M1 doctrine-integrity tests remain unchanged/green;
- all M2 expense/fuel concurrency tests remain unchanged/green;
- existing v24 authority/economics/bid tests remain unchanged/green;
- v24.1 deterministic confidence/evidence acceptance tests restored/reconciled;
- explicit EIA manual-price-equals-EIA-value case proves no false EIA provenance;
- explicit no-weather-fetch case proves no fabricated `0 alerts` observation;
- explicit Worker unavailable canonical case proves no REJECT/F/$0 projection;
- backup/export/restore preserves optional confidence snapshots without schema migration;
- integrated GitHub Actions `Tests` + `Lanes` green on final PR head/merge ref. Local green alone is not sufficient.

## PR #87 disposition

Treat old PR #87 as source material, not a merge candidate. Reconcile valuable code into a fresh branch from integrated post-M2 main, then either retarget/update #87 only if history stays reviewable or close #87 unmerged and open a clean M3 PR. Prefer the cleanest auditable path; never resolve conflicts by taking the old branch's pre-M1 app.js/overlay/service-worker wholesale.
