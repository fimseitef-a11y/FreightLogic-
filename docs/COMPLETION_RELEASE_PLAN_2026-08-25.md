# FreightLogic Completion Release Plan — 2026-08-25

Status: **active finite completion plan and the only roadmap file on `main`.**

Current status update: **2026-09-03.** Gate 0 and the planned M1–M6 product foundation are implemented on `main`. The merged source head reviewed for this update is `a1f4775a24fb1a912ebe9d061dd002efd4f1144e`, identified as **FreightLogic v24.0.3 / IndexedDB v15 / Worker v13**. The v24.0.3 freeze recorded **350 passed / 0 failed across 38 spec files** and green static parity, but a post-freeze exact-current-source reconciliation proved additional behavioral defects that the version-only v24.0.3 change did not repair. Therefore v24.0.3 is **not** the final completion candidate. A bounded v24.0.4 core correction slice is in progress under the repository lock protocol. The named completion release remains **ON HOLD** for those proof-backed corrections, deterministic exact-head CI, the off-repo operator-source reconciliation run, live Cloudflare verification, and finite physical-iPhone certification.

Current certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-03.md`.

Vision ingestion remains an approved but non-blocking track for the named completion release. Provider-adapter expansion remains non-blocking and must not leapfrog the approved sequence.

## Roadmap discipline

1. This is the only active roadmap on `main`.
2. Existing runtime milestone order may not be reordered without operator approval.
3. Anything that enlarges the definition of the completion release must be proposed before it becomes release scope.
4. Correctness, lifecycle identity, provenance, confidence, offline safety, backup/import parity, and certification outrank new live sources or convenience features.
5. Vision ingestion is approved inside Milestone 5, but successful model extraction is not required to freeze the named completion release.
6. Provider adapters may not leapfrog the sequence `normalized contract → manual/email → vision → provider adapters`.
7. Green tests do not overrule current-source evidence of an untested correctness defect.
8. A newly proved defect that violates an existing release invariant is remediation of existing scope, not feature expansion.

## Current source state

- Current certification-state authority: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-03.md`.
- Execution tracker: GitHub Issue #119. It is not a second roadmap.
- `docs/OPERATOR_TRUTH.md`, `docs/EVIDENCE_PROVENANCE.md`, and `docs/OPEN_QUESTIONS.md` are durable Gate-0 sources.
- `docs/V24_1_CONFIDENCE_EVIDENCE_SPEC.md` governs Confidence + Evidence behavior.
- `docs/V24_2_LOAD_LIFECYCLE_SPEC.md` governs lifecycle identity/state.
- `docs/NORMALIZED_EVIDENCE_DURABILITY_CONTRACT.md` governs normalized-evidence persistence/backup/export/import semantics.
- `docs/VISION_LOAD_INGEST_CONTRACT.md` governs the non-blocking vision track.
- `docs/V24_ROADMAP.md` is retired.
- The Unified Decision Engine in `app.js` remains the sole client authority for verdict, grade, economics, and canonical bid range.
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
- Loaded, deadhead/empty, and post-delivery reposition mileage remain separate facts.
- Provider account access must not be confused with API authorization.
- New source semantics must be defined before they influence canonical intelligence.

## Current completion blockers — 2026-09-03

The older pre-M1/M3–M6 source-defect lists are historical; Issue #119 Batch A/B work repaired them and the 2026-09-02 certification state closed them. The active blockers are now the following proof-backed items and final evidence gates:

### Core correctness correction before the next candidate

- North-American market lookup must reject blank/whitespace/underspecified strings before fuzzy matching; missing/ambiguous locations may not create favorable corridor evidence.
- Missing deadhead must remain UNKNOWN in **every production intake**, especially Quick Evaluate, trip-draft/parser/inbox paths; explicit numeric `0` must remain distinguishable from missing.
- The Midwest overlay must be advisory/evidence-only. It may not own a competing grade, verdict, Floor/Win/Ask, `TAKE_IF_LIVE`, or canonical bid range.
- Service-worker subresource handling must be finite/query-safe and must never return the HTML app shell for failed JavaScript/static-asset requests.
- Export/portability payload construction must exclude credentials, backup tokens, app-lock secrets, and device-local lockout state from actual local/cloud exports and checksum inputs. Plain SHA-256 is an integrity/corruption check, not authenticated tamper proof.
- True Profit may not be asserted when operating cost per mile is unavailable; fixed-cost calculations require a defensible mileage denominator and provenance.
- Vehicle-fit behavior must honor the operator-confirmed **121-inch usable cargo length** unless an explicit operator override with provenance is present.
- Gary, Indiana must remain Tier 1 as part of the active Chicago/Gary belt doctrine. Canonical/mirror geography must be brought into parity with the active Level X+ authority; source-verified Census representative coordinates have been supplied to the core lane.
- Trip-store `emptyMiles` zero coercion must be proved safe-by-construction or remediated if any production/import/restore path can turn unknown deadhead into stored numeric `0`. Historical calibration/True RPM may not consume a fabricated zero as verified deadhead.

### Automated/release gate

- The next behavioral candidate must advance governed app/PWA/service-worker identity atomically to at least v24.0.4; DB remains v15 and Worker remains v13 unless their source semantics actually change.
- Full Playwright/Chromium suite must be green on the exact candidate SHA with negative controls for the new regressions.
- CI server startup must be deterministic on a cold runner. The current floating `npx http-server` startup path timed out twice before any spec ran on PR #140 and is a tooling-gate defect; red required CI is not to be bypassed.
- Lane/path/lock checks, static Cloudflare parity, Worker build, backup/export/import integrity, canonical UNKNOWN fixtures, and rollback reference must all be green/current on the exact candidate.

### Evidence gates that remain outside source-only completion

- Real operator historical source bundle rerun remains off-repo and operator-only because the private source files are not committed. Only non-sensitive reconciliation results belong in the public repository.
- Live production Pages/Worker parity, `/health`, auth-boundary, `/evaluate`, `/extract`, and backup/delta/restore smokes must be observed against the exact final SHA.
- Finite physical-iPhone checks in `FIELD_TEST_CHECKLIST.md` must pass on the exact final SHA. Prior evidence that the installed PWA was still v23.7.0 remains a real A1 failure until safely re-tested.
- A later certification-state file may change HOLD only after the proof above exists.

A blocker leaves this list only after exact-current-source review and the applicable regression/full-suite/evidence gate are green.

## Completion release definition

FreightLogic reaches the named completion release when the cargo-van decision product is coherent, safe, durable, and certifiable end to end.

Required:

- one canonical decision authority;
- Midwest Stack v11 / Level X+ money, geography, taxonomy, MPG fallback, cargo-fit, and UNKNOWN-vs-zero integrity;
- categorical confidence/evidence on material inputs without a second decision engine;
- stable load lifecycle identity across opportunity, execution, and settlement;
- durable normalized opportunity evidence with working production manual/email-compatible intake;
- historical import with provenance and correct lifecycle/calibration denominators;
- green deterministic automated regression suite on the exact release SHA;
- backup/full-delta/restore/import/export integrity parity without secret leakage;
- iPhone/offline field certification;
- live Cloudflare Pages/Worker parity and authority-boundary verification;
- named frozen release marker and executable rollback point.

Not required to freeze the completion release: successful vision-model extraction, 123Loadboard/Direct Freight partner approval, provider booking, or provider-adapter expansion, provided the required provider-independent M5 foundation is complete and stable.

## Milestone 1 — Doctrine and money-integrity certification

Priority: CRITICAL.

Implementation status: **IMPLEMENTED; bounded current-source parity corrections are open before final certification.**

Required outcomes remain the regression contract:

- Cincinnati, Toledo, and Gary/Chicago-Gary belt Tier-1 doctrine agree across canonical geography and mirrors.
- Level X+ grade bands: A `>=1.75`, B `1.60–1.74`, C `1.50–1.59`, D `1.40–1.49`, E `1.25–1.39`; ordinary reject `<1.25` outside active DZ.
- F20/DZ absolute floor exactly `0.90`.
- Blank/null/non-finite operational mileage/revenue stay UNKNOWN, never zero.
- Canonical economics/grade/authority become unavailable/provisional when required facts are unknown.
- Mileage provenance distinguishes `VERIFIED | ESTIMATED | UNKNOWN` and keeps loaded/deadhead/displayed/reposition miles distinct.
- Approved approximately `17.5 MPG` fallback remains subordinate to an explicit user MPG setting.
- The operator-confirmed 121-inch usable cargo length is the default fit boundary unless an explicit operator override with provenance exists.
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

Implementation status: **IMPLEMENTED; final exact-candidate re-certification remains open.**

Required behavior:

- evidence normalization is deterministic and source-aware;
- confidence remains categorical `HIGH | MEDIUM | LOW`, never a fake win percentage;
- confidence is descriptive only and cannot alter verdict, grade, True RPM, or canonical bid authority;
- failed/unavailable sources remain unavailable/LOW rather than becoming zero/no-risk;
- Worker may explain client-owned labels but may not replace them or require fabricated canonical facts;
- source provenance is write-point/observation based rather than inferred from unrelated source-health state;
- successful zero observations remain distinguishable from no observation/failure;
- actual lane/broker/vehicle evidence reaches the confidence path;
- persisted evaluations retain a compact secret-free confidence/evidence snapshot while old entries remain readable.

Certification requires exact-current integration tests plus final app/PWA/Worker generation parity.

## Milestone 4 — v24.2 Load Lifecycle

Priority: HIGH.

Implementation status: **IMPLEMENTED; final exact-candidate re-certification remains open.**

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

Implementation status: **5A DURABLE NORMALIZATION + 5B PRODUCTION MANUAL/EMAIL-COMPATIBLE INTAKE IMPLEMENTED; 5C/5D NON-BLOCKING.**

Approved order:

**5A normalized contract → 5B manual/email → 5C vision → 5D provider adapters**

### 5A — Normalized opportunity contract

Required and implemented foundation:

- one provider-independent normalized shape for manual, email/historical, future vision, and future authorized adapters;
- provenance distinguishes source type/name, platform, broker/carrier/company where actually known, timestamps/evidence references, price semantic, mileage semantic, health/confidence, and confirmation state;
- provider evidence remains structurally separate from canonical carrier revenue unless semantics/operator confirmation authorize promotion;
- unknown remains unknown;
- external ID alone is not identity;
- normalized evidence is durable and auditably linked, not merely returned transiently from a helper;
- displayed-total mileage, loaded mileage, deadhead mileage, post-delivery reposition mileage, and map estimates occupy semantically distinct durable fields/evidence.

### 5B — Manual/email-compatible intake

A real production caller is implemented and was covered by the Issue #119 Batch A work. Final certification still requires on-device proof that the shipped path persists provenance/semantics across reload and preserves UNKNOWN-vs-zero behavior.

### 5C — Vision

Approved track, **not a completion-release blocker**. Governed by `docs/VISION_LOAD_INGEST_CONTRACT.md`.

When implemented: schema-constrained extraction → deterministic validation → editable draft → explicit operator confirmation → normalized durable intake. No geocoding/hidden route math/bid/verdict/lifecycle inference by the model; no client-side model secret; no delayed overwrite of operator-confirmed data.

### 5D — Provider adapters

Non-blocking. Warp quote evidence retains `SHIPPER_BOOKABLE_PRICE`. 123Loadboard and Direct Freight require verified integration/partner authorization and exact field/data-use semantics. DAT RateView remains dormant unless explicitly re-authorized.

## Milestone 6 — Historical import + Personal Intelligence calibration

Priority: MEDIUM-HIGH.

Implementation status: **RECONCILIATION MACHINERY IMPLEMENTED; PRIVATE REAL-BUNDLE RERUN REMAINS OPERATOR-ONLY.**

Inputs remain operator-verified durable source files/evidence; missing row facts may not be reconstructed from AI memory.

Implemented/regression rules remain:

- completed/order history dedups only by an appropriate stable identity proven to represent the same shipment;
- quote observations never dedup solely by quote ID;
- later operator-confirmed corrections outrank lower-authority prior values;
- merged material fields retain auditable provenance;
- source `Carrier` is not guessed into canonical broker identity;
- source-displayed mileage/RPM stays semantically distinct from canonical loaded/deadhead/True RPM;
- quote observations are not completed loads without award/completion evidence;
- EXPIRED, LOST, CANCELLED, DRY RUN, live-quote, and other status classes remain distinct;
- unknown/secondary statuses cannot manufacture award evidence;
- import fingerprints are bounded, deterministic, collision-resistant, and idempotent;
- source timestamps retain clock precision and recency uses source observation time rather than import/mutation time;
- DZ-EXIT remains a separate cohort;
- ordinary win rate uses `WON / (WON + LOST)`;
- unknown RPM is excluded, not zero;
- winning range remains unavailable below the defensible sample floor;
- recency/sample weighting is deterministic and inspectable.

Raw operator financial/history source CSVs remain outside the public repository unless explicitly authorized. CI uses synthetic fixtures. The final real-bundle rerun must be performed against the operator's private source bundle and only non-sensitive reconciliation results recorded publicly.

## Milestone 7 — Completion release certification

Priority: CRITICAL FINAL GATE.

Status: **NOT COMPLETE.**

Automated release-candidate gate:

- full Playwright/Chromium suite green and deterministic on the exact release SHA;
- lane/path/lock checks green;
- release/app/SW/manifest/Worker/CSP generation parity green;
- full + delta backup/restore green;
- local export/import and integrity checks green for every protected data class and secret exclusion;
- representative Level X+, cargo-fit, market-lookup, and UNKNOWN/unavailable fixtures green;
- no open proof-backed M1–M6 blocker from the certification-state document.

Field/deployment gate:

- iPhone Safari one-handed decision journey including Quick Evaluate blank-vs-zero deadhead behavior;
- offline install/reload/update behavior;
- production M5B intake durability;
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
1. **M1 doctrine/money integrity — IMPLEMENTED; close the bounded v24.0.4 parity/UNKNOWN/cargo-fit corrections and regressions.**
2. **M2 expense/fuel concurrency — IMPLEMENTED; keep regressions green.**
3. **M3 Confidence + Evidence — IMPLEMENTED; exact final-candidate recertification required.**
4. **M4 lifecycle — IMPLEMENTED; exact final-candidate recertification required.**
5. **M5A durable normalization + M5B production intake — IMPLEMENTED; physical durability proof pending. Vision/provider adapters remain non-blocking.**
6. **M6 historical-import/calibration machinery — IMPLEMENTED; private real operator bundle rerun pending.**
7. **M7 corrected candidate automated + live + physical certification — pending.**
8. **Freeze completion release only after every release blocker is closed and a later certification-state record explicitly supersedes HOLD.**

Do not invert this order merely to add more live sources. New data is useful only when canonical math, lifecycle identity, provenance, confidence, ingestion durability, and certification are trustworthy.
