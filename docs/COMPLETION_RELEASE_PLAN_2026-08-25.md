# FreightLogic Completion Release Plan — 2026-08-25

Status: **active finite completion plan and the only roadmap file on `main`.**

Current status update: **2026-09-02.** Gate 0 and Milestones 1–6 are implemented on `main`, and the exact code candidate is green at **318 passed / 0 failed across 32 spec files**. The named completion release remains **ON HOLD** only for the live Cloudflare and finite physical-iPhone certification evidence. The current state is tracked in `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-02.md`; this roadmap remains the authority for order and scope.

Vision ingestion remains an approved but non-blocking track for the named completion release. Provider-adapter expansion remains non-blocking and must not leapfrog the approved sequence.

## Roadmap discipline

1. This is the only active roadmap on `main`.
2. Existing runtime milestone order may not be reordered without operator approval.
3. Anything that enlarges the definition of the completion release must be proposed before it becomes release scope.
4. Correctness, lifecycle identity, provenance, confidence, offline safety, backup/import parity, and certification outrank new live sources or convenience features.
5. Vision ingestion is approved inside Milestone 5, but successful model extraction is not required to freeze the named completion release.
6. Provider adapters may not leapfrog the sequence `normalized contract → manual/email → vision → provider adapters`.
7. Green tests do not overrule current-source evidence of an untested correctness defect.

## Current source state

- Current certification-state authority: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-02.md`.
- `docs/OPERATOR_TRUTH.md`, `docs/EVIDENCE_PROVENANCE.md`, and `docs/OPEN_QUESTIONS.md` are durable Gate-0 sources.
- `docs/V24_1_CONFIDENCE_EVIDENCE_SPEC.md` governs Confidence + Evidence behavior.
- `docs/V24_2_LOAD_LIFECYCLE_SPEC.md` governs lifecycle identity/state.
- `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md` is merged and defines the existing M5/M6 requirement that normalized evidence survive reload/backup/export/import with semantics intact.
- `docs/VISION_LOAD_INGEST_CONTRACT.md` governs the non-blocking vision track.
- `docs/V24_ROADMAP.md` is retired.
- The Unified Decision Engine remains the sole client authority for verdict, grade, economics, and canonical bid range.
- `app.js` remains SHARED/serialized and core runtime behavior remains Claude-owned under `/.agents/LANES.md`.
- DAT RateView remains dormant/non-authoritative for cargo-van expedite pricing unless explicitly re-authorized.
- Warp, 123Loadboard, and Direct Freight remain subject to `EVIDENCE_PROVENANCE.md` and verified API/partner authorization rules.

## Gate 0 — Operator truth and evidence provenance

Priority: CRITICAL GOVERNANCE.

Status: **COMPLETE.**

Purpose: prevent conversational memory, stale AI summaries, or inference from silently becoming operational truth.

Rules:

- Operator corrections and primary evidence outrank AI summaries.
- If a carried fact cannot be proven as operator-stated or primary-evidence-supported, it stays unresolved.
- Price semantics, mileage semantics, lifecycle state, and source provenance remain explicit.
- Quote/load/order ID alone is not guaranteed unique and cannot be used as destructive dedup identity.
- Source-displayed mileage must not be overwritten by inferred/map mileage.
- Provider account access must not be confused with API authorization.
- New source semantics must be defined before they influence canonical intelligence.

## Current certification blockers

The old pre-M1 defect list is retired because those repairs were implemented through Milestones 1–2. The current release blockers are the proof-backed items in `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-08-27.md`, including, at minimum until repaired and re-reviewed:

- Worker projection must preserve canonical `UNAVAILABLE`, unknown grade, null True RPM, and suppressed/null bid rather than requiring fabricated numeric completeness.
- v24.1 evidence wiring/history must reflect actual source provenance, actual lane/broker/vehicle evidence, successful-zero vs no-data semantics, and a persisted compact evaluation snapshot.
- lifecycle DB-v14 index creation must be correct for fresh/upgraded databases.
- cloud delta backup must not read lifecycle delta state before initialization.
- lifecycle/durable evidence must be covered by export integrity checks when exported as protected history.
- reused external IDs must not cause false lifecycle linking, display, editing, or import deduplication; route/time/internal-source compatibility remains required.
- normalized M5/M6 evidence must survive persistence, backup, export, import, and restore without losing price/mileage semantics or provenance.
- M5B requires a real production manual/email-compatible intake caller; a test-exposed helper alone does not satisfy the milestone.
- M6 historical reconciliation must honor evidence precedence, preserve status classes, use collision-resistant bounded import identity, and weight source observation time rather than import/mutation time.
- release/app/service-worker/manifest/Worker generation must be reconciled only after the corrected runtime is final.
- M7 iPhone/offline and live Cloudflare certification remain unverified until executed against the corrected release candidate.

A blocker leaves this list only after exact-current-source review and the applicable regression/full-suite gate are green.

## Completion release definition

FreightLogic reaches the named completion release when the cargo-van decision product is coherent, safe, durable, and certifiable end to end.

Required:

- one canonical decision authority;
- Midwest Stack v11 / Level X+ money, geography, taxonomy, MPG fallback, and UNKNOWN-vs-zero integrity;
- categorical confidence/evidence on material inputs without a second decision engine;
- stable load lifecycle identity across opportunity, execution, and settlement;
- durable normalized opportunity evidence with working production manual/email-compatible intake;
- historical import with provenance and correct lifecycle/calibration denominators;
- green automated regression suite on the exact release SHA;
- backup/full-delta/restore/import/export integrity parity;
- iPhone/offline field certification;
- live Cloudflare Pages/Worker parity and authority-boundary verification;
- named frozen release marker and executable rollback point.

Not required to freeze the completion release: successful vision-model extraction, 123Loadboard/Direct Freight partner approval, provider booking, or provider-adapter expansion, provided the required provider-independent M5 foundation is complete and stable.

## Milestone 1 — Doctrine and money-integrity certification

Priority: CRITICAL.

Implementation status: **IMPLEMENTED; prior M1 doctrine/money repairs are not current open defects.**

Required outcomes remain the regression contract:

- Cincinnati and Toledo Tier 1 across canonical geography/mirrors.
- Level X+ grade bands: A `>=1.75`, B `1.60–1.74`, C `1.50–1.59`, D `1.40–1.49`, E `1.25–1.39`; ordinary reject `<1.25` outside active DZ.
- F20/DZ absolute floor exactly `0.90`.
- Blank/null/non-finite operational mileage/revenue stay UNKNOWN, never zero.
- Canonical economics/grade/authority become unavailable/provisional when required facts are unknown.
- Mileage provenance distinguishes `VERIFIED | ESTIMATED | UNKNOWN` and keeps loaded/deadhead/displayed/reposition miles distinct.
- Approved approximately `17.5 MPG` fallback remains subordinate to an explicit user MPG setting.
- Unified Decision Engine remains sole verdict/grade/economics/bid authority; Midwest overlay remains advisory/evidence-only.

Definition of done remains enforced by regression tests and unchanged authority boundaries.

## Milestone 2 — Expense/fuel concurrency integrity

Priority: HIGH.

Implementation status: **IMPLEMENTED.**

Required invariant:

- expense/fuel edits reuse the trip optimistic-concurrency pattern;
- expected revision/updatedAt is preserved through edit forms and compared inside the same readwrite transaction;
- stale saves abort with `FL_CONFLICT` rather than overwriting newer data;
- new-record ID semantics, accounting, backup, and import/export behavior remain intact.

## Milestone 3 — v24.1 Confidence + Evidence

Priority: HIGH.

Implementation status: **IMPLEMENTED BUT RE-CERTIFICATION OPEN.**

Required behavior:

- evidence normalization is deterministic and source-aware;
- confidence remains categorical `HIGH | MEDIUM | LOW`, never a fake win percentage;
- confidence is descriptive only and cannot alter verdict, grade, True RPM, or canonical bid authority;
- failed/unavailable sources remain unavailable/LOW rather than becoming zero/no-risk;
- Worker may explain client-owned labels but may not replace them or require fabricated canonical facts;
- source provenance must be write-point/observation based rather than inferred from unrelated source-health state;
- successful zero observations must remain distinguishable from no observation/failure;
- actual lane/broker/vehicle evidence must reach the confidence path;
- persisted evaluations retain a compact secret-free confidence/evidence snapshot while old entries remain readable.

Certification requires exact-current integration tests plus final app/PWA/Worker generation parity.

## Milestone 4 — v24.2 Load Lifecycle

Priority: HIGH.

Implementation status: **IMPLEMENTED BUT RE-CERTIFICATION OPEN.**

Governing contract: `docs/V24_2_LOAD_LIFECYCLE_SPEC.md`.

State dimensions:

- Opportunity: `SEEN | QUOTED | BID | WON | LOST | EXPIRED | CANCELLED`
- Execution: `NOT_STARTED | EN_ROUTE_PICKUP | PICKED_UP | DELIVERED | FELL_THROUGH`
- Settlement: `NOT_INVOICED | INVOICED | OVERDUE | PAID | BAD_DEBT`

Non-negotiable rules:

- EXPIRED is not LOST.
- CANCELLED is not LOST.
- WON does not imply DELIVERED.
- DELIVERED does not imply PAID.
- DZ-EXIT is excluded from normal-market calibration.
- stable lifecycle identity cannot depend on reused external IDs alone.
- conservative linking requires strong evidence; competing candidates remain unresolved.
- migration/backfill is additive, restart-safe, and idempotent.
- dual writes occur after authoritative legacy writes and cannot corrupt the primary record.
- optimistic concurrency applies to user and background lifecycle mutations.
- full backup, delta, restore, local export/import, checksum, and pre-v24.2 compatibility are required.

## Milestone 5 — Freight-source ingestion foundation

Priority: MEDIUM-HIGH.

Implementation status: **5A NORMALIZATION HELPER IMPLEMENTED BUT DURABILITY OPEN; 5B PRODUCTION MANUAL/EMAIL CALL PATH NOT YET IMPLEMENTED; 5C/5D NON-BLOCKING.**

Approved order:

**5A normalized contract → 5B manual/email → 5C vision → 5D provider adapters**

### 5A — Normalized opportunity contract

Required:

- one provider-independent normalized shape for manual, email, historical, future vision, and future authorized adapters;
- provenance distinguishes source type/name, platform, broker/carrier/company where actually known, timestamps/evidence references, price semantic, mileage semantic, health/confidence, and confirmation state;
- provider evidence remains structurally separate from canonical carrier revenue unless semantics/operator confirmation authorize promotion;
- unknown remains unknown;
- external ID alone is not identity;
- normalized evidence must be durable and auditably linked, not merely returned transiently from a helper;
- displayed-total mileage, loaded mileage, deadhead mileage, post-delivery reposition mileage, and map estimates must occupy semantically distinct durable fields/evidence rather than a displayed total being stored in a field named `loadedMi`.

### 5B — Manual/email intake

Current source contains the `intakeOpportunity()` helper, but production-source review found no caller in `app.js`, `voice-load.js`, `admin-driver-ui.js`, `midwest-stack-authority.js`, or `index.html`; current tests call the helper through `window.__FL_TESTS`.

Completion release therefore still requires an actual production call path that normalizes, durably persists, and conservatively lifecycle-links manual/email-compatible evidence while preserving the underlying source reference and offline manual behavior.

### 5C — Vision

Approved track, not a completion-release blocker. Governed by `docs/VISION_LOAD_INGEST_CONTRACT.md`.

When implemented: schema-constrained extraction → deterministic validation → editable draft → explicit operator confirmation → normalized durable intake. No geocoding/hidden route math/bid/verdict/lifecycle inference by the model; no client-side model secret; no delayed overwrite of operator-confirmed data.

### 5D — Provider adapters

Non-blocking. Warp quote evidence retains `SHIPPER_BOOKABLE_PRICE`. 123Loadboard and Direct Freight require verified integration/partner authorization and exact field/data-use semantics. DAT RateView remains dormant unless explicitly re-authorized.

## Milestone 6 — Historical import + Personal Intelligence calibration

Priority: MEDIUM-HIGH.

Implementation status: **MACHINERY IMPLEMENTED; REAL-IMPORT/ADAPTER AND DURABILITY RE-CERTIFICATION OPEN.**

Inputs remain operator-verified durable source files/evidence; missing row facts may not be reconstructed from AI memory.

Rules:

- completed/order history dedups only by an appropriate stable identity proven to represent the same shipment;
- quote observations never dedup solely by quote ID;
- later operator-confirmed corrections outrank lower-authority prior values;
- merged material fields retain auditable provenance;
- source-displayed mileage/RPM stays semantically distinct from canonical loaded/deadhead/True RPM;
- quote observations are not completed loads without award/completion evidence;
- EXPIRED, LOST, CANCELLED, dry-run, live-quote, and other status classes remain distinct;
- dry runs remain separately represented rather than disappearing into normal-market economics;
- unknown/secondary statuses cannot manufacture award evidence;
- import fingerprints are bounded, deterministic, collision-resistant, and idempotent;
- DZ-EXIT remains a separate cohort;
- ordinary win rate uses `WON / (WON + LOST)`;
- unknown RPM is excluded, not zero;
- winning range remains unavailable below the defensible sample floor;
- recency/sample weighting is deterministic and inspectable;
- recency must use the source observation timestamp; unknown observation age must not receive full-current weight, and lifecycle import/mutation `updatedAt` must not substitute for market-observation time.

Raw operator financial/history source CSVs remain outside the public repository unless explicitly authorized. CI uses synthetic fixtures.

## Milestone 7 — Completion release certification

Priority: CRITICAL FINAL GATE.

Status: **NOT COMPLETE.**

Automated release-candidate gate:

- full Playwright/Chromium suite green on exact release SHA;
- release/app/SW/manifest/Worker/CSP generation parity green;
- full + delta backup/restore green;
- local export/import and integrity checks green for every protected data class;
- representative Level X+ and UNKNOWN/unavailable fixtures green;
- no open proof-backed M3–M6 blocker from the certification-state document.

Field/deployment gate:

- iPhone Safari one-handed decision journey;
- offline install/reload/update behavior;
- representative GPS/background resilience check;
- live Cloudflare Pages deployment parity;
- Worker `/health` reachable with expected version/bindings;
- unauthorized admin behavior returns the expected denial;
- live `/evaluate` and `/extract` authority-boundary smoke tests using non-sensitive fixtures;
- rollback procedure documented and executable.

Definition of done: freeze a named completion release and stop adding roadmap scope until certification is complete.

## Explicit defer list

These do not block the completion release unless a newly discovered dependency is proven necessary and separately approved:

- direct bank-account linking;
- successful vision-model extraction/runtime rollout;
- unsupported/unapproved third-party freight APIs;
- provider-adapter expansion when vision has not landed;
- authenticated booking/dispatch through freight providers;
- broad Next-Move expansion beyond existing safe positioning behavior;
- full visual overhaul;
- screenshot automation beyond the bounded single-offer vision contract;
- v25 live-market expansion;
- calibrated percentage win probabilities before sufficient predicted-vs-actual lifecycle data exists.

## Execution order

0. **Gate 0 — COMPLETE.**
1. **M1 doctrine/money integrity — IMPLEMENTED; keep regressions green.**
2. **M2 expense/fuel concurrency — IMPLEMENTED; keep regressions green.**
3. **M3 Confidence + Evidence — IMPLEMENTED; current-source re-certification repairs required.**
4. **M4 lifecycle — IMPLEMENTED; current-source re-certification repairs required.**
5. **M5A normalization helper — IMPLEMENTED but durable evidence incomplete. M5B production manual/email call path — NOT YET IMPLEMENTED. Vision/provider adapters remain non-blocking.**
6. **M6 historical-import/calibration machinery — IMPLEMENTED; real-import adapter/durability/recency reconciliation required.**
7. **M7 field + deployment certification — pending corrected release candidate.**
8. **Freeze completion release only after every release blocker is closed.**

Do not invert this order merely to add more live sources. New data is useful only when canonical math, lifecycle identity, provenance, confidence, ingestion durability, and certification are trustworthy.
