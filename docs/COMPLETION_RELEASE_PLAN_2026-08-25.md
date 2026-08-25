# FreightLogic Completion Release Plan — 2026-08-25

Status: active finite completion plan. This document converts the broad v24 roadmap and the 2026-08-24 completion-audit handoff into the shortest safe route to a coherent FreightLogic completion release.

## Current source state

- Main reference at plan start: `96224bc04ede159ffd09bc57d574a7938e2e927e`.
- Evidence update reference after PR #90 and PR #91 docs gates: `3a26a974d959efadb079340f6235abb8224acd81`.
- v24.0.0 Unified Decision Engine is already the canonical client authority for verdict, grade, economics, and bid range.
- CSS presentation extraction is complete; `styles.css` is the GPT-owned presentation seam.
- `app.js` remains SHARED/serialized and core runtime behavior is Claude-owned under `/.agents/LANES.md`.
- PR #87 (`v24.1.0 — Confidence + Evidence`) remains open and must be reconciled onto the integrity-fixed main rather than blindly merged.
- `docs/V24_2_LOAD_LIFECYCLE_SPEC.md` is now merged as the governing v24.2 lifecycle contract (PR #91; stale predecessor PR #89 was closed unmerged).
- `dat-rateview.js` exists on main but project policy freezes it as dormant/non-authoritative for cargo-van expedite pricing. It is not loaded by `index.html` or precached by `service-worker.js`.

## Confirmed current-source parity defects

These are release-blocking correctness issues because they can alter, mislabel, or falsely sharpen load decisions.

1. `midwest-stack-config.json` is still stamped `appTarget: FreightLogic v23.5.x`, authority `Midwest Stack v2 - Operator System`, effective date `2026-05-27`.
2. `midwest-stack-config.json` still places Toledo and Cincinnati in Tier 2 instead of Tier 1.
3. `midwest-stack-authority.js` still exposes `DEAD_ZONE.floor: 0.91` even though the formal F20/DZ absolute floor is `0.90` and its own hard-stop value is `0.90`.
4. `midwest-stack-authority.js` uses a `finite()` coercion helper that converts missing/non-finite numeric facts to `0`; `assessLoad()` therefore risks manufacturing precise economics from unknown revenue/mileage/deadhead inputs.
5. Canonical `app.js` has the same UNKNOWN-to-zero problem: `deriveUnifiedEconomics()`, `deriveUnifiedGrade()`, and `deriveUnifiedAuthority()` normalize absent material facts into numeric zeroes before economics/grade/hard-gate projection.
6. Canonical `MW.tier1` still excludes Cincinnati and Toledo while `MW.tier2` includes them, so `mwGeoCheck()` itself still applies stale geography.
7. `MW.rpmTiers` and rendered grade-ladder copy still treat `$1.35–$1.49` as the D/minimum-standard band, while the governing Level X+ / v24 authority boundary is D `$1.40–$1.49` and E `$1.25–$1.39`.
8. Current overlay/config source/version labels still describe the older Midwest Stack generation and must be reconciled to the latest governing v11/Level X+ doctrine without creating a second decision engine.
9. `R-TOCTOU-EXPENSE-FUEL` is confirmed present on current main: expense and fuel edits read the latest row only for audit logging and then unconditionally `put()` the stale full object. Unlike trip edits, they do not compare the caller's expected `updatedAt`/revision and do not abort with `FL_CONFLICT` when another tab has already saved.

## Completion release definition

FreightLogic reaches a completion release when the current cargo-van decision product is coherent, safe, and certifiable end to end. It does **not** require every future third-party API or broad v25 market-data expansion.

A completion release must have:

- one canonical decision authority;
- Midwest Stack v11 / Level X+ money, geography, taxonomy, and input-integrity parity;
- categorical confidence/evidence on material inputs;
- one stable load lifecycle identity across opportunity, execution, and settlement;
- safe manual/email-normalized ingestion path that future APIs can feed;
- historical data import path with provenance and denominator rules;
- green automated regression suite;
- backup/restore/import/export parity;
- iPhone/offline field certification;
- live Cloudflare Pages/Worker parity and auth verification;
- a frozen release marker and rollback point.

## Milestone 1 — Doctrine and money-integrity certification

Priority: CRITICAL. Complete before v24.1 runtime integration.

Core-owned files expected:

- `app.js`
- `midwest-stack-authority.js`
- `midwest-stack-config.json`
- `tests/`
- possibly `schemas/` only if an additive validation contract is required

Required outcomes:

- Align Cincinnati and Toledo to Tier 1 through the canonical `MW` geography path and all adapter/config mirrors.
- Align Level X+ grade bands everywhere: A `>=1.75`, B `1.60–1.74`, C `1.50–1.59`, D `1.40–1.49`, E `1.25–1.39`, ordinary Reject `<1.25` outside active DZ.
- Remove the stale `$1.35–$1.39` "minimum standard" classification from helpers and driver-facing grade-ladder copy.
- Align formal F20/DZ absolute floor to exactly `0.90` everywhere; preserve the already-correct canonical `MW.dzFloorRPM = 0.90`.
- Treat blank/undefined/null/non-finite operational mileage and revenue facts as UNKNOWN, never zero.
- If required mileage/revenue is unknown, canonical economics must be unavailable/provisional rather than fabricated. A conservative incomplete/safety state must be visibly distinct from a calculated `$0.00/mi` load.
- Add explicit mileage provenance/status: `VERIFIED | ESTIMATED | UNKNOWN`.
- Keep loaded miles, deadhead/empty miles, platform-displayed miles, and post-delivery reposition miles distinct.
- Preserve v24 Unified Decision Engine as sole verdict/grade/economics/bid authority.
- Keep Midwest overlay `ADAPTER_ONLY` / evidence-only.
- Add exact Level X+ regression boundaries for grade thresholds, deadhead bands, geography, F20, invalid inputs, and unknown inputs.

Definition of done:

- Full Playwright suite green on exact implementation head.
- No weakened existing authority tests.
- No false-precision path remains for unknown core mileage/economics inputs.
- `MW.rpmTiers`, `deriveUnifiedGrade()`, authority thresholds, and rendered ladder cannot drift from one another.
- F20 `0.90` boundary and Tier 1 geography covered by explicit tests.

Rollback point: pre-milestone main SHA.

## Milestone 2 — Close remaining money/data-integrity risks

Priority: HIGH.

Primary target:

- Fix the confirmed `R-TOCTOU-EXPENSE-FUEL` optimistic-concurrency defect.

Confirmed current behavior:

- `updateTrip()` already captures the caller's expected `updatedAt`, reads the stored record and compares the token inside one readwrite transaction, aborts on mismatch, and surfaces `FL_CONFLICT`.
- `updateExpense()` and `updateFuel()` do not perform that comparison; their edit forms also do not carry the original `updatedAt`/revision token into the save call.
- Two stale edit tabs can therefore still silently overwrite unrelated changes through a later full-object `put()`.

Rules:

- Reuse the proven trip optimistic-concurrency pattern rather than inventing a second model.
- Preserve the original record's expected timestamp/revision through the expense/fuel edit form and compare it inside the same readwrite transaction before writing.
- Abort/surface a conflict rather than silently overwrite; refresh the stale form with the latest stored record consistently with trip conflict behavior.
- Do not mix broad refactoring with the repair.
- Preserve existing accounting/expense/fuel behavior and backup contract.
- Any IndexedDB/storage path change requires full-suite and backup/restore validation.

Definition of done:

- Two-tab Playwright tests reproduce the stale-edit scenario for both expense and fuel.
- Tab B is rejected after Tab A has saved; Tab A's unrelated field change remains stored.
- No silent full-object lost update occurs.
- Full suite and backup/restore parity remain green.

## Milestone 3 — Reconcile and land v24.1 Confidence + Evidence

Priority: HIGH.

Dependency: Milestones 1 and 2 must be green first so confidence describes trustworthy canonical facts and the large `app.js` reconciliation does not race a known integrity repair.

Disposition of PR #87:

- Rebase/reconcile onto current main after Milestones 1 and 2.
- Preserve its core architecture: strict evidence-number normalization, source health, freshness, sample size, categorical HIGH/MEDIUM/LOW, no probabilities, no relaxed protective floors.
- Re-run all existing v24 authority tests unchanged.
- Keep live-source health unified with existing EIA/NWS/FMCSA/CBP health vocabulary.
- Keep Worker confidence projection client-owned; AI may explain, not replace.

External-source semantics to encode for future adapters:

- Warp: `SHIPPER_BOOKABLE_PRICE`, not carrier payout.
- 123Loadboard: carrier-side posted/market evidence only when API/terms authorize access and exact price semantics are known.
- Direct Freight: carrier-side posted evidence only when API/partner terms are verified.
- DAT RateView: dormant/non-authoritative for cargo-van expedite unless owner explicitly re-authorizes a bounded role later.

Definition of done:

- Full suite green on reconciled v24.1 head.
- Confidence cannot change verdict, grade, True RPM, or protective bid/floor logic.
- Failed/unavailable source health remains visibly unavailable/LOW rather than looking like no data.
- Version/service-worker/manifest/Worker parity updated as required by the release checklist.

## Milestone 4 — v24.2 Load Lifecycle

Priority: HIGH.

Governing contract: merged `docs/V24_2_LOAD_LIFECYCLE_SPEC.md` (PR #91).

Required state dimensions:

- Opportunity: `SEEN | QUOTED | BID | WON | LOST | EXPIRED | CANCELLED`
- Execution: `NOT_STARTED | EN_ROUTE_PICKUP | PICKED_UP | DELIVERED | FELL_THROUGH`
- Settlement: `NOT_INVOICED | INVOICED | OVERDUE | PAID | BAD_DEBT`

Non-negotiable analytics rules:

- EXPIRED is not LOST.
- CANCELLED is not LOST.
- WON does not imply DELIVERED.
- DELIVERED does not imply PAID.
- DZ-EXIT records are excluded from normal-market winning-range/floor calibration.

Migration requirements:

- DB version bump.
- Additive lifecycle store/shape.
- Conservative linking; no broker/order guessing from ambiguous customer text.
- Dual-write transition with existing `bidHistory` and `trips` paths.
- Optimistic concurrency/revision semantics from initial rollout.
- Full backup, delta, restore, export, and import parity.
- Pre-v24.2 backups remain valid.

Definition of done:

- One load can accumulate opportunity, execution, and settlement truth under one stable identity without discarding existing operational/accounting records.
- Full migration, concurrency, denominator, backup/restore, and compatibility suite green.

## Milestone 5 — Freight-source ingestion foundation

Priority: MEDIUM-HIGH, but only the provider-independent foundation is required for completion release.

Required before external API credentials are available:

- One normalized opportunity-ingestion contract that manual intake, screenshots/text extraction, email alerts, and future APIs all feed.
- Provenance fields must distinguish platform, broker, carrier/company, source, price semantic, source timestamp, and health/confidence.
- Email/manual intake must not bypass provider terms or fabricate API access.

Provider adapters:

- Warp adapter can land when approved endpoint/docs/credentials exist.
- 123Loadboard adapter can land only after separate API eligibility/terms are verified; free board access is not API access.
- Direct Freight adapter can land only after partner/API terms are verified; free account access is not API authorization.

Completion-release rule:

- Missing third-party API approval does not block release if the normalized ingestion contract and manual/email-compatible path are stable.

## Milestone 6 — Historical import + Personal Intelligence calibration

Priority: MEDIUM-HIGH.

Inputs:

- Operator-verified historical orders/loads.
- Operator-verified quote-board observations.

Rules:

- Deduplicate by Order ID where present.
- Preserve later user-confirmed status corrections.
- Preserve source-displayed mileage separately from inferred/estimated road mileage.
- Quote-board observations are not completed loads unless later awarded/confirmed.
- Preserve price semantic and source provenance.
- Keep DZ-EXIT as a separate calibration cohort.
- Do not infer broker identity from ambiguous customer text.

Definition of done:

- Import path can ingest verified history into lifecycle/personal-intelligence structures without source-code hardcoding.
- Win-rate and winning-range denominators obey lifecycle rules.
- Recency/sample-size weighting is deterministic and inspectable.

## Milestone 7 — Completion release certification

Priority: CRITICAL final gate.

Automated:

- Full Playwright/Chromium suite green on exact release SHA.
- Release/version/SW/manifest/Worker/CSP parity checks green.
- Backup full + delta + restore green.
- Import/export compatibility green.
- Representative Level X+ load fixtures green.

Field/deployment:

- iPhone Safari one-handed decision journey.
- Offline install/reload/update behavior.
- GPS/background resilience representative check.
- Live Cloudflare Pages deployment parity.
- Worker `/health` reachable and expected version/bindings present.
- Unauthorized admin behavior returns the expected denial.
- Live `/evaluate` and `/extract` authority boundary smoke tests using non-sensitive fixtures.
- Rollback procedure documented and executable.

Definition of done:

- Freeze a named completion release and stop adding roadmap scope until the release is certified.

## Explicit defer list

These do not block completion release unless a newly discovered dependency makes them necessary:

- direct bank account linking;
- unsupported/unapproved third-party freight APIs;
- broad v24.4 Next-Move expansion beyond existing safe positioning behavior;
- v24.5 full visual overhaul;
- v24.6 broader screenshot-first automation beyond the normalized ingestion foundation;
- v25 live-market expansion;
- calibrated percentage win probabilities before sufficient predicted-vs-actual lifecycle data exists.

## Execution order

1. Doctrine/money integrity.
2. Expense/fuel concurrency repair.
3. v24.1 reconciliation.
4. v24.2 lifecycle.
5. Normalized ingestion foundation and provider adapters as credentials permit.
6. Historical import / Personal Intelligence calibration.
7. Field + deployment certification.
8. Freeze completion release.

Do not invert this order merely to add more live sources. New data is only useful after the canonical math, lifecycle identity, provenance, and confidence contracts are trustworthy.
