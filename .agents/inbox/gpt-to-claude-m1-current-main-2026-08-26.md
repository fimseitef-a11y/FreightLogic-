# GPT → Claude: Milestone 1 Current-Main Kickoff

Date: 2026-08-26
Current canonical main: `da62c114885a2549f94bc26059f6d0cc51431e8b`
Runtime-defect inspection base: `86ae9b1eb60b1452370acb443982d1c35ef66c45`
Roadmap authority: `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`
Gate 0: COMPLETE
Implementation owner: Claude/core lane

## Why this refresh exists

The older M1 handoff was written against main `3a26a974...`. Main has since gained Gate 0 operator truth/provenance, the vision-ingest spec, duplicate-roadmap retirement, the operator-approved Milestone-5 sequencing, and the operator-approved MPG parity item. This file refreshes the M1 implementation packet against current main without broadening beyond the explicitly approved M1 scope.

PR #97 recorded the MPG mismatch as a proposal. PR #98 recorded the operator's explicit approval. PR #99 then synchronized that already-approved repair into the single canonical completion roadmap. PR #99 integrated gate: GitHub Actions run `32942947209`, job `98097573111`, `node tests/run-all.mjs` => **119 passed, 0 failed across 19 specs**, no rerun; merged main is `da62c114885a2549f94bc26059f6d0cc51431e8b`. PRs #97–#99 changed documentation only, so no runtime/test bytes changed after the defect inspection below and the findings remain current.

At the latest inspection there was no active lock file under `/.agents/locks/` beyond `.gitkeep`, and no active `agent/claude/*` Milestone-1 branch. Claim locks exactly as required by `AGENTS.md` before core work.

## Current live defects reconfirmed on the runtime tree

### `app.js`

Canonical UNKNOWN→0 remains live:

- `deriveUnifiedEconomics(facts)` still normalizes `loadedMi`, `deadMi`, and `revenue` with zero fallbacks and returns numeric zero economics when material facts are absent.
- `deriveUnifiedGrade(trueRPM)` still converts invalid/unknown RPM to numeric `0` before assigning a grade.
- `deriveUnifiedAuthority(facts)` still normalizes material facts including `trueRPM`, `totalMi`, `deadheadPct`, `effectiveRevenue`, `netAfterFuel`, and `profitMarginPct` through zero fallbacks.

Canonical geography/taxonomy drift remains live:

- `MW.tier1` still omits Cincinnati and Toledo.
- `MW.tier2` still includes Cincinnati and Toledo.
- `MW.rpmTiers` still contains `1.35–1.49 = Minimum Standard / ACCEPT`.
- rendered ladder still says D `$1.35–$1.49` and E `$1.25–$1.34`, while canonical `deriveUnifiedGrade()` already uses D from `$1.40` and E from `$1.25–$1.39`.

Canonical source-of-truth MPG drift remains live and is now explicitly authorized for repair:

- Gate 0 `OPERATOR_TRUTH.md` records the operator-confirmed loaded baseline as approximately `17.5 MPG`.
- `app.js` still carries `MW.mpg: 16.5` with a `Field-confirmed 2016 Transit T250 (gas)` comment and uses that value as fallback when no explicit vehicle-MPG setting is available.
- The operator explicitly approved reconciling this fallback/source label as part of Milestone 1 on 2026-08-26.

Maintenance-pointer drift:

- top-of-file v24 comment still points maintainers to retired `docs/V24_ROADMAP.md`. Since `app.js` must already be touched under M1, update that comment to the single canonical roadmap without changing behavior.

### `midwest-stack-authority.js`

- banner still identifies `Midwest Stack v2`.
- `DEAD_ZONE.floor` remains `0.91` while `hardStops.absoluteTrueRpmReject` is `0.90`.
- Tier 1 omits Toledo/Cincinnati; Tier 2 includes them.
- `finite(value, fallback)` still falls back to `(fallback || 0)`.
- `assessLoad()` still uses that helper for revenue/loaded/deadhead and can manufacture a precise `0`-based result from missing operational facts.

### `midwest-stack-config.json`

- `appTarget` remains `FreightLogic v23.5.x`.
- `authorityName` remains `Midwest Stack v2 - Operator System`.
- `effectiveDate` remains `2026-05-27`.
- Tier 1 omits Toledo/Cincinnati and Tier 2 includes them.

## Binding M1 outcomes

Implement only the existing roadmap scope plus the explicitly approved MPG parity repair:

1. UNKNOWN material revenue/mileage remains UNKNOWN/provisional, never silently zero.
2. Explicit real zero remains distinguishable from unknown (e.g. verified `deadMi: 0`).
3. Canonical economics do not expose calculated-looking `$0.00/mi` output when required facts are missing.
4. Incomplete facts cannot produce an apparently complete authoritative grade/verdict/bid path.
5. Mileage provenance/status is explicit (`VERIFIED | ESTIMATED | UNKNOWN`) and loaded/deadhead/platform/reposition semantics stay distinct.
6. Cincinnati and Toledo are Tier 1 through canonical + adapter/config mirrors.
7. Level X+ taxonomy is exact everywhere: A `>=1.75`, B `1.60–1.74`, C `1.50–1.59`, D `1.40–1.49`, E `1.25–1.39`, ordinary Reject `<1.25` outside active DZ.
8. DZ/F20 absolute floor is exactly `0.90` everywhere.
9. Unified Decision Engine remains sole canonical verdict/grade/economics/bid authority; Midwest overlay remains adapter/evidence only.
10. Correct the stale in-code roadmap pointer while `app.js` is already under lock.
11. **AUTHORIZED MPG parity:** reconcile the `MW.mpg` fallback/source label from stale `16.5` to the operator-confirmed approximately `17.5 MPG` loaded baseline. An explicit user vehicle-MPG setting remains higher priority and must continue to override the fallback. Do not turn this into a broader fuel-model redesign.

## Required regression matrix

At minimum add/extend Claude-owned tests for:

- valid grade thresholds immediately below/at `1.25`, `1.40`, `1.50`, `1.60`, `1.75`;
- canonical `MW.rpmTiers` and rendered ladder parity with `deriveUnifiedGrade()`;
- Toledo Tier 1 and Cincinnati Tier 1 through `mwGeoCheck()` plus adapter/config mirrors;
- DZ exact boundary immediately below/at `0.90` with required DZ activation conditions;
- `null`, `undefined`, blank string, `NaN`, and non-finite loaded/deadhead/revenue values remain unknown;
- verified explicit `deadMi: 0` remains a real zero;
- unknown deadhead does not calculate precise True RPM;
- unknown revenue does not calculate precise economics;
- unknown True RPM does not become a real grade F merely via numeric coercion;
- incomplete canonical facts cannot produce a normal authoritative bid/verdict payload;
- mileage provenance survives canonical contract projection;
- Midwest adapter cannot own canonical verdict/bid;
- `MW.mpg` fallback/source label matches the approved approximately `17.5 MPG` Gate 0 baseline;
- explicit user vehicle-MPG setting still overrides the fallback and canonical economics uses the explicit value exactly;
- all pre-existing valid-input v24 authority/economics behavior remains green.

Any `app.js` change requires full `node tests/run-all.mjs` suite and exact SHA logging in `TEST_LEDGER.md`.

## Existing PR disposition

- PR #87 remains OPEN but explicitly HOLD / BLOCKED ON M1+M2. Do not merge or weaken it now. Reconcile it only after M1 + M2 are green.
- GPT closed stale PR #93 (Milestone 5 draft) and #94 (Milestone 6 draft) unmerged because they predated Gate 0 and approved sequencing. Their branches are historical drafting material only.

## MPG scope proposal — RESOLVED / AUTHORIZED

`docs/OPEN_QUESTIONS.md` item 33 is now **CONFIRMED — 2026-08-26** and the same requirement is explicitly present in the canonical roadmap after PR #99.

Operator authorization is explicit:

- reconcile stale `MW.mpg: 16.5` fallback/source label with Gate 0's operator-confirmed approximately `17.5 MPG` loaded baseline;
- preserve explicit user MPG settings as higher-priority overrides;
- add regression coverage proving that override behavior;
- keep the change narrowly bounded to M1 parity. No broader fuel/economics redesign is authorized by this approval.

## After M1

Continue exactly in roadmap order:

1. Milestone 2 expense/fuel optimistic-concurrency repair.
2. Reconcile PR #87 v24.1.
3. Implement v24.2 lifecycle.
4. Only then activate Milestone 5 sequencing from current roadmap.

No provider adapter, vision runtime expansion, or later-milestone implementation should leapfrog these gates.
