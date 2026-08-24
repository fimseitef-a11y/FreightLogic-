# FreightLogic — Claude Code Completion Audit Handoff

**Prepared:** 2026-08-24  
**Purpose:** Re-entry authority for Claude Code to audit the *current* FreightLogic project, reconcile recent ChatGPT/user decisions with repository reality, and produce a recommended plan to finish FreightLogic without losing prior work or creating parallel systems.

## 0. First instruction to Claude Code

Do **not** assume the older `/.agents/CLAUDE_PROMPT.md` snapshot is current. It was written before subsequent merges/PR work and before the latest freight-source/API decisions.

Before changing application code:

1. Read current `main` completely enough to understand the present architecture and release state.
2. Read `/AGENTS.md`, `/.agents/LANES.md`, `/.agents/AUDIT_TRIAGE.md`, this handoff, and current `CLAUDE.md`.
3. Read live `/.agents/STATUS.md`, `/.agents/TEST_LEDGER.md`, `/.agents/locks/`, and `/.agents/inbox/` from `agent-coordination`.
4. Inspect every open FreightLogic PR and branch that could overlap current work.
5. Establish a fresh exact-SHA baseline and run the full test suite before proposing runtime changes.
6. Audit the new Midwest Stack v11 / Freight Calculator Level X+ requirements against the actual current code.
7. Audit all external/live-data integrations and candidate APIs listed below.
8. Produce a **single prioritized completion plan** identifying:
   - what is already complete;
   - what is partially complete;
   - what is stale/duplicated/conflicting;
   - what must be fixed before release;
   - what can be deferred until after a stable FreightLogic completion release;
   - exact sequencing, dependencies, test gates, and rollback boundaries.
9. **Stop for owner approval of the completion plan before beginning a broad implementation round.** Small read-only verification/audit work is authorized; broad runtime refactors are not implicitly authorized by this handoff.

The goal is not to add more ideas. The goal is to identify the shortest safe path to a coherent, finished FreightLogic.

---

## 1. Repository truth at handoff time

Current `main` at preparation time:

`201cc450c6ecf4492d4ed715f5caa2a736bd89a5`

Latest commit message:

`Add DAT RateView client module for live cargo van / expedite freight rates`

Important recent state:

- FreightLogic v24.0.0 Unified Decision Engine is already on `main` and is intended to be the **sole deterministic owner** of verdict, grade, economics, and canonical bid range.
- The UI/CSS extraction has already landed. `styles.css` is now the real presentation seam and is GPT-owned under current `/.agents/LANES.md`.
- `app.js` remains SHARED/serialized and core runtime behavior is Claude-owned unless ownership is changed deliberately.
- `midwest-stack-authority.js` is supposed to be advisory/adapter-only, not a competing decision authority.
- Existing live-source health plumbing already covers EIA, NWS, FMCSA, and CBP.
- Cloudflare Worker already provides encrypted backup plus OpenAI-backed `/evaluate` and `/extract` paths.
- Current public release markers on `main` are still v24.0.0.

### Open PRs that must be reconciled into the completion audit

At handoff time:

- **PR #87 — `v24.1.0 — Confidence + Evidence`** remains open. Its stated branch result is 147 passed / 0 failed across 22 specs, but it must be reconciled against *current* main before relying on that result.
- **PR #89 — `[gpt] v24.2 load lifecycle implementation contract`** remains open and is docs-only. It defines the next lifecycle/data-contract milestone and requires Claude review before runtime work.

Do not discard either PR merely because a newer handoff exists. Audit whether each should be merged, revised, superseded, or closed.

### Current test/audit history

Prior v24.0 release evidence recorded 119 passed / 0 failed across 19 specs. Historical audit triage recorded:

- formal findings: 18 FIXED, 2 SUPERSEDED, 1 OPEN;
- residual implementation-risk follow-up: `R-TOCTOU-EXPENSE-FUEL`;
- residual revalidation gaps: real iOS field resilience, full long-running E2E journeys, usability under field load, live Worker/invite behavior, exhaustive XSS/import source-to-sink coverage, exhaustive F20 activation matrix.

Those counts were produced on an earlier SHA. Treat them as evidence, **not current certification**. Re-run/re-audit current main.

---

## 2. Product/business authority — newest user decisions

FreightLogic is a cargo-van expedite PWA built around the operator's real freight workflow. The business north-star remains:

`True RPM = Revenue / (Loaded Miles + Legitimate Deadhead Miles)`

The product must remain driver-first, iPhone-first, offline-first, and evidence-aware.

### Operator profile / current operating facts to preserve as configurable profile data

- Vehicle class: Ford Transit T250 cargo van.
- Usable cargo length confirmed by real-world rejection: **121 in hard usable limit** in the current setup.
- No pallet jack.
- Loaded MPG operating baseline commonly used: about **17.5 MPG**.
- Current total operating-cost working baseline used in freight decisions: about **$0.66/mile** unless newer settings/data override it.
- Home operating anchor: Oak Creek, WI / Milwaukee–Chicago corridor.
- Weekend policy is now explicitly **CRITICAL / RECOVERY**: Saturdays and Sundays historically produce very few wins, so the system should prioritize productive repositioning and Monday position. Lower all-in RPM can be justified when the move covers repositioning cost and materially improves Sunday/Monday position. Do not apply weekday floors mechanically to weekend recovery decisions.

These are operator profile/settings facts, not a reason to hardcode a commercial product for every user.

---

## 3. Midwest Stack v11 + Freight Calculator Level X+ — new canonical package

A clean authority package was prepared on 2026-08-24. It intentionally excludes superseded historical source files and contains only:

1. `MIDWEST_STACK_V11_CANONICAL_MASTER_AUTHORITY_2026-06-24.md`
2. `FREIGHT_CALCULATOR_LEVEL_X_PLUS_MASTER_OVERRIDE_2026-08-19.txt`

The clean package states that earlier v8/v7/v6/v5/core/Keeper/rate-card/compression/legacy calculator authorities are historical only.

### Authority order to respect

1. Newer explicit operator instruction / user-confirmed correction.
2. Any newer verified Midwest Stack canonical authority after v11.
3. Midwest Stack v11 canonical authority.
4. Freight Calculator Level X+ implementation/assurance rules.
5. Older sources are historical only.

### Known parity drift already identified against current FreightLogic

Claude must independently verify and expand this list:

- Current `midwest-stack-config.json` is still stamped from the older May authority generation.
- Current runtime overlay places **Cincinnati** and **Toledo** in Tier 2, while v11/Level X+ require:
  - Columbus / Cincinnati = Tier 1
  - Detroit / Toledo = Tier 1
- Runtime overlay currently exposes a `DEAD_ZONE.floor` of **0.91** while v11/Level X+ define the formal absolute F20/DZ floor as **0.90**.
- The overlay's numeric coercion path can convert missing inputs to `0`; Level X+ explicitly requires:
  - blank numeric operational facts = `UNKNOWN`, not zero;
  - unknown deadhead must never become zero to manufacture a precise True RPM;
  - unknown loaded/deadhead mileage should produce unavailable/provisional economics rather than false precision.
- Level X+ requires explicit mileage-source status (`VERIFIED`, `ESTIMATED`, `UNKNOWN`) and separation of:
  - loaded miles;
  - deadhead/empty miles;
  - displayed platform mileage;
  - post-delivery reposition miles.
- Level X+ requires hard validation before economics and includes exact regression boundaries for grades, deadhead bands, F20, geography, invalid inputs, and unknown fields.

### Architectural interpretation

Do **not** rebuild a second Freight Calculator engine beside v24.

Recommended direction to audit:

- Midwest Stack v11 = business doctrine.
- Level X+ = implementation/certification contract.
- `app.js` v24 Unified Decision Engine = executable canonical authority.
- `midwest-stack-authority.js` = adapter/evidence presentation only.
- live market sources = evidence inputs with provenance/health/freshness; they may influence recommendations through the canonical path but may not silently rewrite doctrine.

The key task is a **v11 + Level X+ parity/certification pass over FreightLogic**, not importing old calculator HTML.

---

## 4. Freight history and market-learning data from recent chats

The user has supplied and verified a substantial historical dataset through screenshots and master CSV blocks.

Important handling rules:

- Treat the August 24 operator-confirmed historical load/order values as operator-verified unless the user later corrects them.
- Deduplicate by Order ID.
- Preserve later user-confirmed status corrections.
- Preserve source-displayed mileage separately from inferred/estimated road mileage.
- Dispatch platform is not automatically the carrier/company; preserve platform separately from carrier/company identity.
- Quote-board observations are **not completed loads** unless later awarded/confirmed.

Recent project-level counts/context include:

- historical master from Nov 2025 through May 27, 2026: 91 unique orders;
- June–Aug extension: 34 additional orders plus 1 quote in a prior reconciliation;
- a separate quote-board intelligence batch: 56 unique quote IDs, with 37 fully visible origin→destination observations and 19 partial/cut-off observations.

These data are valuable for v24.2 lifecycle and v24.3 Personal Intelligence calibration, but do not silently embed chat-derived records into source code. Audit the correct import/data-migration path and preserve provenance.

---

## 5. External market/source policy — current decisions

This section is critical because recent conversations changed the intended data-source hierarchy.

### 5.1 Warp — preferred real cargo-van rate signal

Current policy:

- Warp is the preferred candidate for a **real/bookable cargo-van price signal**.
- Target integration discussed: a van quote endpoint such as `/api/v1/van/quote`, subject to actual approved docs/credentials.
- Sandbox/live credentials or partner approval must be treated separately from having a normal account.
- Warp quote values are **shipper-side bookable/all-inclusive prices**, not guaranteed carrier payout.
- Therefore Warp must be modeled as `SHIPPER_BOOKABLE_PRICE` evidence, not as direct carrier-pay truth.

Recent manual/bookable examples captured in project discussion:

- Milwaukee area → Detroit: **$575.67**
- Detroit → Columbus: **$364.38**
- Columbus → Chicago: **$519.47**
- Chicago → Grand Rapids: **$335.14**
- Indianapolis → Detroit: **$468.41**

Use those as observations/evidence only, not permanent static rate tables.

### 5.2 123Loadboard — free account exists; API access is separate

Current policy:

- A free 123Loadboard account exists.
- Free board/account access is **not** the same as API/partner access.
- Prior conversation indicated separate API access/contracting and an approximately **$200** fee; this was paused while authority/MC-DOT work is pending.
- Cargo-van (`CV`) postings can be useful carrier-side market evidence if the API/terms actually permit the intended use.
- Claude should verify current API eligibility, pricing, rate limits, data fields, retention/commercial-use terms, and whether the available data is posted carrier pay vs another price concept before designing an integration.

### 5.3 Direct Freight — free account exists; API/partner terms unresolved

Current policy:

- A free Direct Freight account exists.
- Direct Freight is a candidate source for cargo-van/`CRG` posted carrier-pay observations.
- Prior research indicated potentially useful fields such as posted pay, miles/deadhead, dimensions, posting age, and market totals, but partner token/pricing/limits/subscription/commercial retention terms remain unresolved.
- Do not treat the free website account as API authorization.
- Verify exact current partner/API terms before implementation.

### 5.4 Dispatch platform data

The user's current operating workflow uses **Dispatch Lane**; older repository/docs and historical discussion also contain `DispatchLand`/Sylectus terminology. Audit and normalize platform naming so product logic does not conflate:

- dispatch/load-board platform;
- broker;
- carrier/company;
- source of a quote/offer.

Carrier-side truth should come from awarded/completed user loads and explicit posted/target/accepted amounts with source provenance.

### 5.5 DAT RateView — file exists on main, but do NOT make it cargo-van authority

`dat-rateview.js` was added directly to `main` in commit `201cc450...`.

Current project decision superseding that commit's optimistic purpose statement:

- DAT RateView is **not authoritative for cargo-van expedite pricing**.
- Generic `VAN`/dry-van analytics must not be presented as cargo-van winning-rate truth.
- `dat-rateview.js` is **frozen/dormant on main** unless the owner later explicitly re-authorizes its role.
- The current module contains placeholder/gated endpoint assumptions and should not be wired into production simply because the file exists.

Claude should audit whether the cleanest completion state is to leave it explicitly dormant/quarantined/documented, or otherwise isolate it so it cannot accidentally influence canonical cargo-van recommendations. Do not delete or repurpose it without owner approval.

### 5.6 Existing live sources already in FreightLogic

Current runtime already has source-health plumbing for:

- **EIA** fuel price data;
- **NWS** weather/route alerts;
- **FMCSA** carrier lookup;
- **CBP** border wait data.

Preserve one shared source-health vocabulary and integrate any future Warp/123/Direct source into that same provenance/health/freshness architecture rather than inventing parallel registries.

### 5.7 Cloudflare + OpenAI

Current Cloudflare Worker already supports:

- encrypted backup/restore;
- user/admin token model;
- `/evaluate` AI explanation/review;
- `/extract` structured load-text extraction;
- delta backup paths.

Current architecture rule remains: AI may explain/challenge/summarize but **must not own or recalculate the canonical verdict/grade/True RPM/bid range**.

Live deployment parity remains a required certification step; source-side green tests are not proof that deployed Pages/Worker bindings, secrets, auth, rate limits, or health endpoints are correct.

### 5.8 Email/Gmail ingestion — useful pre-API bridge, not yet FreightLogic runtime

The user wants load alerts to flow into FreightLogic automatically even before every load-board API is approved.

Important distinction:

- A Gmail connection available to ChatGPT is not automatically a credential or runtime integration FreightLogic can use.
- FreightLogic itself would need a proper Gmail API/OAuth, forwarding mailbox/parser, or another approved ingestion service.
- Email alert ingestion is a viable bridge for 123Loadboard/Direct Freight/dispatch alerts **if permitted by the providers' terms**.
- Parsed email alerts should enter the same normalized opportunity/lifecycle schema with source provenance and explicit confidence.

Audit this as a candidate v24.2/v24.6 ingestion path, not as a hidden shortcut around provider API terms.

### 5.9 Bank/expense integrations

The user also wants eventual bank/transaction import/linking for expenses. This is useful but should not block finishing core FreightLogic freight intelligence unless Claude finds a critical dependency.

Treat direct bank linking as a separate security/consent/integration milestone. Do not add banking credentials or provider secrets to client storage.

---

## 6. What is already substantially complete

Claude should verify rather than reimplement these areas:

- offline-first PWA shell and service worker;
- IndexedDB business data model and legacy migration;
- cloud backup/restore architecture;
- expense/fuel/trip bookkeeping;
- tax export and mileage-rate handling;
- GPS trip tracking and resilience repairs;
- Unified Load Intake / Smart Load Inbox;
- positioning engine and post-delivery brief;
- vehicle maintenance tracker;
- setup wizard/operator settings;
- post-trip lane/broker review;
- earnings/money dashboard;
- v24 Unified Decision Engine and authority boundary tests;
- source-health substrate for existing live APIs;
- extracted `styles.css` presentation seam;
- multi-agent lock/ownership protocol.

The completion effort should reuse these instead of creating replacement systems.

---

## 7. Known incomplete / unverified / potentially stale areas

Claude's audit should explicitly disposition each item:

1. Fresh full-suite baseline on exact current main after the latest direct-to-main DAT commit.
2. Open PR #87 reconciliation and decision: merge/revise/supersede.
3. Open PR #89 contract review and decision.
4. Midwest Stack v11 + Level X+ parity/certification gaps.
5. Unknown-vs-zero operational-input integrity across the entire canonical evaluator/intake path.
6. Cincinnati/Toledo Tier 1 geography parity.
7. Exact $0.90 F20 floor and full F20 gate matrix.
8. `R-TOCTOU-EXPENSE-FUEL` optimistic concurrency gap.
9. Real iPhone/iOS Safari field resilience and one-handed workflow validation.
10. Full long-running E2E journey validation.
11. Live Cloudflare Pages/Worker parity and real auth/invite behavior.
12. Exhaustive import/XSS source-to-sink revalidation as features grew.
13. Freight source taxonomy and provenance model for carrier pay vs shipper price vs estimate.
14. Warp integration path/approval/credentials and source-health adapter.
15. 123Loadboard API feasibility/terms; free account must not be mistaken for API access.
16. Direct Freight API feasibility/terms; free account must not be mistaken for API access.
17. Email-alert ingestion design for pre-API automation.
18. Historical load/quote data import into lifecycle/personal-intelligence without losing provenance.
19. Current docs drift (`CLAUDE.md` still contains some pre/post CSS-extraction descriptions that may no longer match current physical structure).
20. Release/version/deployment discipline after any v24.1+ merge.

---

## 8. Requested completion-plan shape

Claude's recommended plan should not be an unbounded roadmap. It should define a finite route to a **FreightLogic Completion Release**.

At minimum, classify work into these buckets:

### A. Must fix before completion release

Correctness, money math, authority/doctrine parity, data corruption/loss risk, security, broken runtime paths, false precision, deployment mismatch, and anything that could make a driver accept/reject a load from bad data.

### B. Must integrate before completion release

Only capabilities required for the product to function coherently as the intended cargo-van decision system. Prefer adapters/interfaces when external API approval is pending.

### C. Validate before completion release

Full automated suite, exact-money/Level-X+ certification tests, iPhone field checks, offline install/update, backup/restore, Cloudflare live parity, and representative real-load decision fixtures.

### D. Defer after completion release

Nice-to-have integrations or expansion that do not justify delaying a stable product, such as bank linking or unsupported third-party APIs when credentials/terms are not ready.

For every proposed milestone include:

- exact files/paths affected;
- owner lane/lock requirements;
- dependency on PR #87/#89 or new work;
- migration/version implications;
- regression tests required;
- deploy/field verification required;
- rollback point;
- explicit definition of done.

---

## 9. Strong recommended sequencing for Claude to evaluate

This is a hypothesis to audit, not a command to blindly implement:

1. **Re-entry audit + fresh baseline** on current main and open PRs.
2. **Repository/process cleanup**: reconcile stale docs/PR state and isolate dormant DAT behavior without changing cargo-van authority.
3. **Midwest Stack v11 + Level X+ certification parity** in the canonical decision/intake path, including unknown-input handling and regression matrix.
4. **Close remaining money/data-integrity risks**, especially expense/fuel TOCTOU if still present.
5. **Disposition/land v24.1 Confidence + Evidence** so new sources carry provenance/health/freshness correctly.
6. **Land/implement v24.2 lifecycle** so seen/quoted/bid/won/lost/expired/cancelled/execution/settlement data have one stable identity and can absorb historical + new alert sources.
7. **Automated freight-source ingestion adapters**: first normalize email/manual intake; then Warp/123/Direct adapters as credentials/terms permit.
8. **Personal Intelligence calibration** using operator-verified historical loads and quote observations, keeping DZ outcomes separate from normal-market calibration.
9. **Field/release certification**: iPhone, offline, backup/restore, deployment parity, live Worker, real sample decisions, rollback drill.
10. **Freeze a completion release** before moving to broader v24.4/v24.5/v25 expansion.

Claude should challenge this order where repository evidence supports a better sequence, but the final recommendation must stay finite and completion-oriented.

---

## 10. Non-negotiable anti-regression rules

- Do not create a second verdict/bid engine.
- Do not let external APIs directly override canonical decision authority.
- Do not present shipper price as carrier pay.
- Do not present generic dry-van/DAT `VAN` analytics as cargo-van winning-rate truth.
- Do not convert unknown mileage/deadhead/handling into zero.
- Do not fabricate live data when a source is unavailable.
- Do not weaken protective floors because confidence is low/stale.
- Do not infer broker identity from ambiguous customer fields.
- Do not treat EXPIRED or CANCELLED as ordinary LOST.
- Do not include DZ-EXIT outcomes in normal-market bid calibration.
- Do not store external API, bank, admin, or AI secrets in unsafe client persistence.
- Do not weaken/remove tests to make a red baseline green.
- Do not mix broad refactoring with audit repairs.
- Do not duplicate existing FreightLogic capabilities under new names.

---

## 11. Deliverable requested from Claude Code

After the audit, return a concise but source-backed report with:

1. **Current state:** exact main SHA, open PRs, test state, deployment state.
2. **What is already finished and should be left alone.**
3. **Confirmed defects/drift/gaps**, ranked Critical / High / Medium / Low.
4. **Midwest Stack v11 + Level X+ parity matrix**: requirement → current implementation → gap → recommended action → test.
5. **API/source matrix**: source → price semantic → current access → API status → implementation status → source-health/provenance needs → blocker.
6. **Completion plan** with a finite number of milestones and explicit definition of done.
7. **Defer list** so FreightLogic can actually reach a stable completion release instead of continuously expanding.
8. **Owner approval checkpoint** before broad implementation begins.

This handoff is intended to preserve the latest project decisions across ChatGPT/Claude sessions. When facts conflict, verify current source and apply the authority order above rather than silently choosing an older document.