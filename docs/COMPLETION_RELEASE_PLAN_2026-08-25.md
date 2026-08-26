# FreightLogic Completion Release Plan — 2026-08-25

Status: **active finite completion plan and the only roadmap file on `main`.**

Last governance update: 2026-08-26 — operator approved formal Gate 0, approved the Milestone 5 intake ordering, and explicitly approved the narrowly bounded Milestone-1 MPG fallback parity repair described below. Vision ingestion remains non-blocking for the completion release.

This document converts the broad v24 work and the 2026-08-24 completion-audit handoff into the shortest safe route to a coherent FreightLogic completion release.

## Roadmap discipline

1. This is the only active roadmap on `main`.
2. Existing runtime milestone order may not be reordered without operator approval.
3. Anything that enlarges the definition of the completion release must be proposed to the operator before it becomes release scope.
4. New live sources, APIs, automation, visual expansion, or convenience features may not jump ahead of correctness, lifecycle identity, provenance, confidence, offline safety, and certification.
5. Vision ingestion is an approved implementation track inside the ingestion milestone, but successful vision implementation is **not required** to freeze the named completion release.
6. Provider adapters may not leapfrog the normalized manual/email/vision intake sequence. If vision is deferred, provider-adapter expansion is deferred with it; the completion release may still proceed once the required provider-independent foundation is complete.

## Current source state

- Current governance baseline before this roadmap-sync PR: `762984afb3afe80a9a25d592927d8ec40b0f51ed`.
- `docs/OPERATOR_TRUTH.md`, `docs/EVIDENCE_PROVENANCE.md`, and `docs/OPEN_QUESTIONS.md` are durable on `main` and form Gate 0.
- `docs/VISION_LOAD_INGEST_CONTRACT.md` is the governing vision replacement specification. Runtime implementation remains Claude/core-owned.
- `docs/V24_ROADMAP.md` was retired so this file remains the single roadmap authority.
- v24.0.0 Unified Decision Engine is already the canonical client authority for verdict, grade, economics, and bid range.
- CSS presentation extraction is complete; `styles.css` is the GPT-owned presentation seam.
- `app.js` remains SHARED/serialized and core runtime behavior is Claude-owned under `/.agents/LANES.md`.
- PR #87 (`v24.1.0 — Confidence + Evidence`) remains subject to reconciliation onto integrity-fixed main rather than blind merge.
- `docs/V24_2_LOAD_LIFECYCLE_SPEC.md` is the governing v24.2 lifecycle contract.
- `dat-rateview.js` exists on main but project policy freezes DAT RateView as dormant/non-authoritative for cargo-van expedite pricing.
- Warp quote evidence, 123Loadboard, and Direct Freight remain subject to the source semantics and API-status rules in `EVIDENCE_PROVENANCE.md` and `OPEN_QUESTIONS.md`.

## Gate 0 — Operator truth and evidence provenance

Priority: CRITICAL GOVERNANCE.

Status: **COMPLETE as of 2026-08-26.**

Purpose: prevent conversational memory, stale AI summaries, or inference from silently becoming operational truth.

Required durable files:

- `docs/OPERATOR_TRUTH.md`
- `docs/EVIDENCE_PROVENANCE.md`
- `docs/OPEN_QUESTIONS.md`

Gate rules:

- Operator corrections and primary evidence outrank AI summaries.
- If a carried fact cannot be proven as operator-stated or primary-evidence-supported, it stays in `OPEN_QUESTIONS.md`.
- Price semantics, mileage semantics, lifecycle state, and source provenance must remain explicit.
- Quote/load ID alone is not guaranteed unique and cannot be used as destructive dedup identity.
- Source-displayed loaded/deadhead mileage must not be overwritten by map estimates.
- Provider account access must not be confused with API authorization.
- New provider/source semantics must be defined in `EVIDENCE_PROVENANCE.md` before they can influence FreightLogic intelligence.

Definition of done:

- All three files exist on `main`.
- Ambiguous carried claims remain outside confirmed truth.
- Future implementation work reads these files before promoting operational facts.

Gate 0 adds no runtime feature work and does not change the order of Milestones 1–7.

## Confirmed current-source parity defects

These remain release-blocking correctness issues because they can alter, mislabel, or falsely sharpen load decisions.

1. `midwest-stack-config.json` still carries stale v23.5/older Midwest authority metadata.
2. Toledo and Cincinnati remain stale Tier 2 entries where governing Level X+ doctrine requires Tier 1.
3. `midwest-stack-authority.js` still exposes `DEAD_ZONE.floor: 0.91` despite the formal F20/DZ absolute floor being `0.90`.
4. Midwest authority helpers can coerce missing/non-finite operational facts to `0`, manufacturing false precision.
5. Canonical `app.js` has corresponding UNKNOWN-to-zero paths in unified economics/grade/authority derivation.
6. Canonical `MW.tier1`/`MW.tier2` geography remains stale for Cincinnati and Toledo.
7. `MW.rpmTiers` and rendered grade-ladder copy still contain the stale `$1.35–$1.39` D/minimum-standard classification rather than Level X+ D `$1.40–$1.49` and E `$1.25–$1.39`.
8. Installed-app/source metadata still describes the older Midwest Stack generation and must be reconciled without creating a second decision engine.
9. `R-TOCTOU-EXPENSE-FUEL` remains a confirmed lost-update risk: expense/fuel edits can overwrite a newer concurrent edit because they do not enforce the trip path's revision/`updatedAt` conflict check.
10. **Operator-approved M1 parity repair:** Gate 0 records the loaded fallback baseline as approximately `17.5 MPG`, while current `app.js` still carries `MW.mpg: 16.5` with stale field-confirmed wording. The operator approved reconciling this fallback/source label while preserving explicit user vehicle-MPG settings as higher-priority overrides.

## Completion release definition

FreightLogic reaches a completion release when the current cargo-van decision product is coherent, safe, and certifiable end to end. It does **not** require every future third-party API, authenticated booking path, broad screenshot automation, or v25 market-data expansion.

A completion release must have:

- one canonical decision authority;
- Midwest Stack v11 / Level X+ money, geography, taxonomy, and input-integrity parity;
- categorical confidence/evidence on material inputs;
- one stable load lifecycle identity across opportunity, execution, and settlement;
- safe normalized opportunity ingestion with a working manual/email-compatible path that future adapters can feed;
- historical import with provenance and correct lifecycle denominators;
- green automated regression suite;
- backup/restore/import/export parity;
- iPhone/offline field certification;
- live Cloudflare Pages/Worker parity and auth verification;
- a frozen release marker and rollback point.

**Not required to freeze the completion release:** successful vision-model extraction, 123Loadboard/Direct Freight partner approval, provider booking, or provider-adapter expansion, provided the required provider-independent normalized ingestion/manual-email foundation is complete and stable.

## Milestone 1 — Doctrine and money-integrity certification

Priority: CRITICAL. Complete before v24.1 runtime integration.

Core-owned files expected:

- `app.js`
- `midwest-stack-authority.js`
- `midwest-stack-config.json`
- `tests/`
- release/display metadata touched only as required by release certification
- `schemas/` only if an additive validation contract is required

Required outcomes:

- Align Cincinnati and Toledo to Tier 1 through canonical geography and all mirrors.
- Align Level X+ grade bands everywhere: A `>=1.75`, B `1.60–1.74`, C `1.50–1.59`, D `1.40–1.49`, E `1.25–1.39`, ordinary Reject `<1.25` outside active DZ.
- Remove stale `$1.35–$1.39` minimum-standard treatment.
- Align formal F20/DZ absolute floor to exactly `0.90` everywhere.
- Treat blank/undefined/null/non-finite operational mileage and revenue as UNKNOWN, never zero.
- If required mileage/revenue is unknown, canonical economics must be unavailable/provisional rather than fabricated.
- Add explicit mileage provenance/status: `VERIFIED | ESTIMATED | UNKNOWN`.
- Keep loaded miles, deadhead/empty miles, platform-displayed miles, and post-delivery reposition miles distinct.
- Reconcile the stale `MW.mpg: 16.5` fallback/source label to the operator-confirmed approximately `17.5 MPG` loaded baseline. An explicit user vehicle-MPG setting remains higher priority and must override the fallback.
- Preserve v24 Unified Decision Engine as sole verdict/grade/economics/bid authority.
- Keep Midwest overlay adapter/evidence-only.
- Reconcile stale Midwest Stack generation wording in release/install metadata when versioned.
- Add exact Level X+ regression boundaries for grade thresholds, deadhead bands, geography, F20, invalid inputs, unknown inputs, and MPG fallback/override parity.

Definition of done:

- Full Playwright suite green on exact implementation head.
- No weakened authority tests.
- No false-precision path remains for unknown core mileage/economics inputs.
- Grade taxonomy, thresholds, geography, and rendered copy cannot drift from one another.
- F20 `0.90` and Tier 1 geography have explicit tests.
- MPG fallback behavior is explicit and tested: absent user MPG uses the approved approximately `17.5` fallback; an explicit user MPG value continues to override it.

Rollback point: pre-milestone main SHA.

## Milestone 2 — Close remaining money/data-integrity risks

Priority: HIGH.

Primary target: fix `R-TOCTOU-EXPENSE-FUEL` optimistic concurrency.

Rules:

- Reuse the proven trip concurrency pattern; do not invent a second model.
- Preserve the original expected revision/`updatedAt` through expense/fuel edit forms.
- Compare inside the same readwrite transaction before writing.
- Abort and surface `FL_CONFLICT` rather than silently overwriting a newer record.
- Refresh stale forms consistently with trip conflict behavior.
- Do not mix broad refactoring with the repair.
- Preserve accounting, backup, and import/export contracts.

Definition of done:

- Two-tab Playwright tests reproduce stale edits for expense and fuel.
- A later stale save is rejected and the earlier concurrent edit survives.
- No silent full-object lost update occurs.
- Full suite and backup/restore parity remain green.

## Milestone 3 — Reconcile and land v24.1 Confidence + Evidence

Priority: HIGH.

Dependency: Milestones 1 and 2 green first.

Required behavior:

- Reconcile v24.1 work onto integrity-fixed main.
- Preserve strict evidence-number normalization, source health, freshness, sample size, and categorical `HIGH | MEDIUM | LOW` confidence.
- No percentage win probabilities.
- Confidence cannot relax protective floors or alter verdict, grade, True RPM, or bid authority.
- Keep Worker confidence projection client-owned; AI may explain, not replace.
- Failed/unavailable source health remains visibly unavailable/LOW rather than being interpreted as no market signal.

Provider semantics for future adapters remain governed by `EVIDENCE_PROVENANCE.md`:

- Warp quote = `SHIPPER_BOOKABLE_PRICE`, not carrier payout.
- 123Loadboard evidence only after integration/partner authorization and exact field semantics are known.
- Direct Freight evidence only after required partner authorization/token model and terms are satisfied.
- DAT RateView remains dormant/non-authoritative unless explicitly re-authorized.

Definition of done:

- Full suite green on reconciled head.
- Existing v24 authority tests remain intact.
- Version/service-worker/manifest/Worker parity updated as required by release certification.

## Milestone 4 — v24.2 Load Lifecycle

Priority: HIGH.

Governing contract: `docs/V24_2_LOAD_LIFECYCLE_SPEC.md`.

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

- Additive DB/lifecycle migration.
- Conservative linking; no broker/order guessing from ambiguous text.
- Dual-write transition with legacy opportunity/trip paths where required.
- Optimistic concurrency/revision semantics from initial rollout.
- Full backup, delta, restore, export, and import parity.
- Pre-v24.2 backups remain valid.

Definition of done:

- One load can accumulate opportunity, execution, and settlement truth under one stable identity without discarding existing operational/accounting history.
- Migration, concurrency, denominator, backup/restore, and compatibility tests are green.

## Milestone 5 — Freight-source ingestion foundation

Priority: MEDIUM-HIGH.

### Completion-release requirement

Only the **provider-independent normalized ingestion foundation plus working manual/email-compatible intake** is required for the named completion release.

### Approved internal implementation order

The operator approved this order on 2026-08-26:

**5A. Normalized contract → 5B. Manual/email intake → 5C. Vision intake → 5D. Provider adapters**

Provider adapters may not be pulled ahead of the vision track merely because an API is easy to access.

If vision implementation is deferred, provider-adapter expansion is also deferred. That does **not** block the completion release because neither vision success nor provider adapters are required to freeze the release.

### 5A — Normalized opportunity-ingestion contract

Required:

- One normalized opportunity shape that manual intake, email normalization, vision extraction, historical observation import where appropriate, and future APIs can feed.
- Provenance fields distinguish platform, broker/carrier/company where actually known, source, source timestamp, price semantic, mileage semantic, health/confidence, and confirmation state.
- Provider evidence remains structurally separate from canonical expected carrier revenue until semantics explicitly permit carrier revenue or the operator confirms the amount.
- Unknown stays unknown; no missing-to-zero coercion.
- Identity must not rely on quote/load ID alone.

### 5B — Manual and email-normalized intake

Required for completion release:

- Manual opportunity intake works through the normalized contract.
- Email-derived opportunity/confirmation evidence uses the same normalized contract and preserves the underlying message/evidence semantics.
- Manual/email intake does not fabricate API access or bypass provider terms.
- Offline/manual behavior remains functional.

### 5C — Vision load intake

Approved implementation track; **not a completion-release blocker**.

Governing specification: `docs/VISION_LOAD_INGEST_CONTRACT.md`.

Required when implemented:

- photo/screenshot → vision model → schema-constrained JSON → deterministic validation → editable draft → explicit operator confirmation → normalized opportunity intake;
- field-level confidence/evidence rules from the governing contract;
- hallucinated fields rejected deterministically;
- no geocoding, hidden route math, bid/verdict/grade/lifecycle inference, or price-semantic promotion by the model;
- offline capture/manual fallback must never break PWA startup or field behavior;
- no model/provider secret in client JavaScript;
- multiple offers may not be merged into one record;
- delayed extraction may not overwrite operator-confirmed manual data;
- deterministic CI fixtures; no flaky required live-model test dependency.

Vision implementation remains Claude/core-owned under repository lock/test discipline.

### 5D — Authorized provider adapters

Provider-adapter work starts only after 5A–5C ordering has been respected. It is not required for completion release.

- **Warp quote evidence:** may use the documented quote-only path when implementation reaches this stage. Preserve `SHIPPER_BOOKABLE_PRICE`; never populate carrier revenue from the bookable quote. Booking/private actions remain out of scope unless explicitly authorized later.
- **123Loadboard:** implement only after integration/partner API authorization and provider terms/field semantics are verified. Free site/account access is not API approval.
- **Direct Freight:** implement only after partner API authorization/token handling and permitted data usage are verified. Free site/account access is not partner API approval.
- **DAT RateView:** remains dormant/non-authoritative unless explicitly re-authorized for a bounded role.

Completion-release rule:

- Missing vision implementation, 123Loadboard approval, Direct Freight approval, Warp authenticated booking access, or provider adapters does not block release once 5A and 5B are stable and all earlier release gates are satisfied.

## Milestone 6 — Historical import + Personal Intelligence calibration

Priority: MEDIUM-HIGH.

Inputs:

- operator-verified historical orders/loads;
- operator-verified quote-board observations.

Rules:

- Import from durable operator-verified source files/evidence; do not reconstruct missing row facts from AI memory.
- Deduplicate completed/order history by the appropriate stable identity; do not apply quote-ID-only dedup to quote-board observations.
- Preserve later operator-confirmed status corrections.
- Preserve source-displayed mileage separately from inferred/estimated road mileage.
- Quote-board observations are not completed loads unless later awarded/completed evidence exists.
- Preserve price semantic and source provenance.
- Keep DZ-EXIT as a separate calibration cohort.
- Do not infer broker identity from ambiguous customer text.

Definition of done:

- Verified history can enter lifecycle/personal-intelligence structures without source-code hardcoding.
- Win-rate and winning-range denominators obey lifecycle rules.
- Recency/sample-size weighting is deterministic and inspectable.

## Milestone 7 — Completion release certification

Priority: CRITICAL FINAL GATE.

Automated:

- Full Playwright/Chromium suite green on exact release SHA.
- Release/version/SW/manifest/Worker/CSP parity green.
- Backup full + delta + restore green.
- Import/export compatibility green.
- Representative Level X+ fixtures green.

Field/deployment:

- iPhone Safari one-handed decision journey.
- Offline install/reload/update behavior.
- GPS/background resilience representative check.
- Live Cloudflare Pages deployment parity.
- Worker `/health` reachable with expected version/bindings.
- Unauthorized admin behavior returns expected denial.
- Live `/evaluate` and `/extract` authority-boundary smoke tests with non-sensitive fixtures.
- Rollback procedure documented and executable.

Definition of done:

- Freeze a named completion release and stop adding roadmap scope until certification is complete.

## Explicit defer list

These do not block the completion release unless a newly discovered dependency is proven necessary and separately approved:

- direct bank-account linking;
- successful vision-model extraction/runtime rollout;
- unsupported/unapproved third-party freight APIs;
- provider-adapter expansion when vision has not yet landed;
- authenticated booking/dispatch through freight providers;
- broad Next-Move expansion beyond existing safe positioning behavior;
- full visual overhaul;
- screenshot automation beyond the bounded single-offer vision-ingest contract;
- v25 live-market expansion;
- calibrated percentage win probabilities before sufficient predicted-vs-actual lifecycle data exists.

## Execution order

0. **Gate 0 — Operator truth/provenance externalization: COMPLETE.**
1. Doctrine/money integrity, including the operator-approved MPG fallback parity repair.
2. Expense/fuel concurrency repair.
3. v24.1 Confidence + Evidence reconciliation.
4. v24.2 lifecycle.
5. Ingestion milestone in this internal order: **normalized contract → manual/email → vision → provider adapters**. Completion release requires the normalized contract + manual/email foundation; vision/provider adapters remain non-blocking.
6. Historical import / Personal Intelligence calibration.
7. Field + deployment certification.
8. Freeze completion release.

Do not invert this order merely to add more live sources. New data is only useful after canonical math, lifecycle identity, provenance, confidence, and ingestion semantics are trustworthy.