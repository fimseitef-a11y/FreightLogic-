# FreightLogic Visual Redesign Authority — v24.5 Working Brief

**Status:** Approved visual direction. **Gates 1–4 were completed and operator-cleared; future sessions re-verify only facts that may have changed and must not restart the completed gate audit.**

**Working label:** `v24.5` is a planning label, not an authorized release-number bump. The actual release generation must follow the repository's current release-generation rules at integration time.

**Repository-native visual reference:** `FreightLogic_UI_Reference.html`

**Operator-approved original reference:** the 10-screen FreightLogic dark/gold iPhone mockup supplied by the operator. The HTML reference is a repository-safe structural reconstruction for agents to inspect in a browser. If the original image is available in the working session, use it for pixel-level visual comparison.

**Baseline snapshot when this brief was created:** `main` at `ef2de47ccddd8064c6918ab51cd80edb0e78c167` (v24.0.14 source candidate). This is only a timestamped baseline. Gate 1 must re-read the actual HEAD and deployed production before any implementation begins.

**Current-authority supersession — 2026-09-18:** the baseline and the Gate 1–4 report in §13 are historical snapshots, not current deployment authority. Observed production at this checkpoint is **app/PWA v24.0.19 / IndexedDB DB16 / backup/API Worker v20**; issues **#221, #224, #240, and #244 are closed completed**. The exact current `main` SHA is intentionally **not pinned here**: read it from GitHub and use the current superseding certification-state document plus fresh live-parity/CI evidence. **Voice Load was deliberately removed by operator decision in v24.0.17**; do not reintroduce Voice/SpeechRecognition because older passages in this brief predate that decision. Physical iPhone A1–A12 remain a separate real-device evidence gate. M6 Gate C structural replay has run, but that does not waive final-candidate adoption/conflict review.

---

## 1. Purpose and authority

This work is a **visual/interaction redesign of the existing FreightLogic product**, not a rewrite of its decision engine, data model, security model, or freight doctrine.

When sources conflict, use this order:

1. **Current exact-source invariants, tests, data-integrity/security contracts, and canonical business logic.** Existing canonical economics and safety behavior are not weakened to match a mockup.
2. **This brief** for redesign scope, information architecture, interaction intent, and visual hierarchy.
3. **The visual reference** for composition, density, styling, card hierarchy, and overall feel.

The reference is **not a feature inventory**. A visual element that implies a capability FreightLogic does not actually have must not be faked. Preserve existing capabilities that the mockup does not show unless the operator explicitly approves their removal.

### Non-negotiable product invariants

- `app.js` remains the sole deterministic owner of canonical load verdict, grade, True RPM/economics, and canonical bid range unless the existing architecture explicitly says otherwise.
- Unknown deadhead stays **UNKNOWN**. It is never silently converted to `0` for a prettier card.
- Existing IndexedDB records, trip history, expenses, fuel, receipts, market history, imports/exports, and protected evidence survive the redesign.
- No sample values from the reference become production defaults or business logic.
- No second evaluator, second load schema, second market engine, or parallel intake pipeline is created just for the new UI.
- Existing zero-token invite/claim onboarding and credential rules are preserved. The redesign may reskin that flow; it must not replace it with a password/token shortcut.
- Offline-first behavior and service-worker integrity remain release gates.
- No feature is deleted solely because the 10-screen mockup omits it.
- Voice Load/SpeechRecognition is intentionally removed by operator decision (2026-09-17, v24.0.17). Do not restore it during the redesign. Preserve the intake capabilities actually present in current source.

---

## 2. Implementation ownership and concurrency

For the implementation phase, use **one writer** for runtime redesign changes. Other agents may audit, compare, and review, but they should not concurrently edit the same UI/runtime branch.

Recommended roles:

- **Claude Code — sole implementation writer** for the redesign branch once the gates below are approved.
- **ChatGPT/GPT — read-only verifier/reviewer** during Claude's implementation: architecture reconciliation, reference comparison, economics/data-integrity review, post-commit delta review.
- **Optional adversarial reviewer** — bounded, read-only diff review after a screen lands. Do not add a third concurrent writer.

All repository lane ownership, lock protocol, commit-prefix rules, and release gates in `AGENTS.md` and `.agents/LANES.md` remain in force. If a required path is locked by another in-flight task, the redesign waits or works only on non-conflicting read-only gates.

---

## 3. Mandatory pre-code gates

**Do not write redesign UI code until Gates 1–4 are complete, reported, and approved.**

### Gate 1 — Exact-source and production reconciliation

Record, separately:

- current `main` SHA;
- source `APP_VERSION`;
- source `DB_VERSION`;
- source backup/API Worker version;
- currently deployed app version;
- currently deployed service-worker/cache generation;
- currently deployed backup/API Worker version.

Do **not** assume source equals deployed production.

At brief creation, repo documentation said the v24.0.14 / DB16 / Worker v19 source candidate was newer than the then-observed v24.0.12 / DB15 / Worker v17 production deployment. Treat that as historical context only; verify again at execution time.

### Gate 2 — Open-risk reconciliation, not audit resurrection

Read the exact current versions of:

- `CLAUDE.md`
- `AUDIT_REPORT.md`
- `RECON_24_0_2.md`
- `FIELD_TEST_CHECKLIST.md`
- current certification/parity documents
- current tests and release-generation tooling

Produce only findings that are **actually open, regressed, or unverifiable against the exact current HEAD**.

Do not blanket-reopen older audit findings that their own evidence marks fixed. If a previously fixed issue is believed to have returned, show exact current-source or runtime evidence of the regression.

### Gate 3 — Complete surface inventory and destination map

Inventory **every current driver-visible and owner/admin-visible surface**: route, tab, modal, sheet, drawer, panel, wizard, quick action, tile, diagnostics surface, and entry point.

For each surface, deliver:

`current surface → proposed new home → action (keep / merge / move / reskin / operator-approval-required-to-remove)`

At minimum reconcile these known capabilities rather than assuming the 10-screen reference is exhaustive:

- Today/Home command center
- Loads / Smart Load Inbox
- Unified Load Intake (the photo/screenshot/OCR and paste paths actually available in current source; Voice is retired)
- Evaluate / OMEGA / canonical freight evaluation
- Midwest Stack / Dead Zone Exit / Freight Score / market evidence
- Trips / trip lifecycle / unpaid state
- Money / Expenses / Fuel / Receivables / AR aging
- Market Intel, lane intelligence, broker intelligence, reload/positioning surfaces
- Opportunity Intake and evidence/lifecycle surfaces
- Maintenance tracker
- Tax Season / Schedule C / per diem / export surfaces
- Diagnostics
- Setup wizard / vehicle profile / operating-cost settings
- Data import/export/backup/recovery
- zero-token owner/driver onboarding and admin management
- post-trip lane/broker review
- navigation handoff
- More / secondary tools

The output should make it impossible for a working feature to become unreachable because a nav bar was replaced.

### Gate 4 — Navigation/DOM compatibility plan

The approved visual target uses five primary destinations:

**Today · Loads · ⚡ · Trips · Money**

The center **⚡** must reuse the existing canonical intake/evaluation path rather than create a parallel feature. **Current production routes it to Evaluate/`#omega`; that is the current behavior, not a mandate that the final redesign can never change the entry point.** If the redesign makes the center action intake-first, it must call the existing Load Intake/evaluator path and preserve one canonical pipeline. Expose only capabilities actually present in current source: **Photo/Screenshot/OCR where available · Paste**. **Voice is intentionally retired and must not return.**

Before coding, inspect `index.html`, `modern-shell.js`, `app.js`, and the current router/ID bindings. Deliver one of these plans:

- **Plan A — preserve existing canonical IDs/routes** and re-label/re-style/recompose around them. Preferred when feasible.
- **Plan B — controlled migration** with an explicit `ID_MAP.md` / route map and every call/reference site accounted for, landing as a structural commit with the regression suite green before visual changes continue.

Do not discover route/ID migration halfway through the redesign.

---

## 4. Design system

The redesign should feel like a premium driver command center: dark, dense, calm, fast to scan, and usable one-handed.

### Core visual tokens

| Token | Intent |
|---|---|
| App background | near-black |
| Card/surface | charcoal / graphite |
| Border | subtle low-contrast edge |
| Primary accent | warm amber/gold |
| Positive | green |
| Warning / destructive | red |
| Primary text | white / warm off-white |
| Secondary text | muted gray |

Use one centralized token layer in `styles.css` rather than one-off hex values per screen.

### Layout and interaction

- 4/8 px spacing rhythm.
- Card radii approximately 12–16 px.
- Thin borders; restrained shadows; no decorative clutter.
- No gratuitous gradients or illustrations.
- Numeric hierarchy is dominant: rate, miles, True RPM, revenue, expenses, deadlines.
- Primary touch targets should target **48×48 CSS px** where practical and must never regress below the current **44×44** accessibility baseline.
- System/iOS-safe sans-serif typography. Avoid font choices that create network dependence.
- Color never carries status alone; pair it with text/iconography.
- Respect safe-area insets and installed-PWA viewport behavior.

### Information hierarchy

A driver should be able to answer these in seconds:

1. What am I doing now?
2. Is this load economically acceptable?
3. What is my next move?
4. How is the week going?
5. What money is outstanding?

---

## 5. Primary navigation

Target primary nav:

**Today · Loads · ⚡ · Trips · Money**

- Selected state: amber/gold plus label/icon state.
- Center ⚡ is visually emphasized but remains a single access point into **existing Unified Load Intake**.
- Market Intel and other secondary tools remain reachable through an intentional secondary structure (for example More, contextual links, or a deliberate screen destination established by Gate 3). They must not become orphaned.
- Do not create a second router in `modern-shell.js` or elsewhere. Reuse the canonical router/state.

---

## 6. Screen targets

These describe visual/interaction targets. They do not authorize new business logic.

### 6.1 Today / Home

Header:
- FreightLogic brand
- profile/owner control
- greeting / current position context when actually available
- compact, timestamped weather only if the existing weather contract has valid data
- backup state must describe the real local/cloud state; never show a generic "Synced" badge that implies a backend state the app did not verify

Primary cards, ordered:

1. **Active Trip** — lane, status, all miles when known, revenue, True RPM when available, delivery deadline, progress, `View Trip`.
2. **Next Move** — existing positioning recommendation with confidence/source freshness. If no confident recommendation exists, show the honest neutral/unknown state.
3. **This Week** — progress to weekly target, gross, expenses, net/True RPM metrics from the same canonical source used on Money.

Goal: current work, weekly economics, next action without hunting through tiles.

### 6.2 Loads

Controls:
- search
- filter
- states such as New / Saved / Won / Passed / Market only if those states exist or Gate 3 maps them honestly

Load card:
- freshness/source timestamp
- origin → destination
- loaded miles
- deadhead miles, explicitly UNKNOWN when missing
- all miles only when derivable
- grade/verdict from canonical engine only
- rate
- True/all-mile RPM only when available
- pickup deadline / feasibility signal when available
- `Pass` and `Evaluate`

Bad economics should be obvious without hiding the numbers that caused them.

### 6.3 Load Detail

Show:
- status/freshness
- lane
- loaded/deadhead/all miles with provenance/unknown semantics preserved
- rate / True RPM / canonical grade
- pickup and delivery timing
- compact lane/route summary
- analysis/evidence bullets from existing canonical/advisory sources
- hard warnings first

**Do not introduce map tiles as a redesign dependency.** If the current product has no offline-safe map contract, use a lane/highway summary and navigation handoff.

Actions: `Pass` · `Evaluate`.

### 6.4 Evaluate Load

This is the primary canonical evaluation presentation.

Editable inputs should reuse existing inputs and semantics, including optional advanced facts.

Primary result card:
- verdict/action language
- canonical grade
- True RPM / estimated economics only when available
- canonical bid range when not suppressed
- unknown/missing facts clearly named

Reasoning:
- destination/market context
- deadhead quality
- rate vs floor
- reload/positioning context
- feasibility/safety/risk factors
- evidence freshness/confidence where the existing engine supports it

Actions may include `Save Load` / `Add as Trip` based on current behavior.

The UI **renders** the engine. It does not recalculate a competing answer.

### 6.5 Trips

Tabs/states should reconcile with actual trip/payment semantics; target presentation:

- Active
- Completed
- Unpaid / receivables-facing view when that state is real

Active card:
- lane
- lifecycle timeline
- deadline
- loaded/deadhead/all miles with UNKNOWN discipline
- revenue
- True RPM only when supported by complete facts
- `Navigate`
- delivery/status action

Navigation is a device handoff/deep link, not a new in-app turn-by-turn map.

### 6.6 Money

Target tabs:
- Overview
- Expenses
- Fuel
- Receivables

Gate 3 assigns Tax/Per Diem/Schedule C and other finance tools without losing reachability.

Overview:
- weekly net/gross/expenses
- True RPM/efficiency metrics only from canonical calculations
- receivables total and aging/overdue entry point
- concise trend visualization when sufficient data exists
- quick actions: Add Expense / Fuel / Receipt as supported

**Today and Money must read the same canonical weekly totals.**

### 6.7 Market Intel

Show current position/market only when known.

Ranked nearby-market/positioning information should include:
- distance
- strength/role
- evidence age/source
- historical/personal signal when available

Recommendation:
- HOLD / WAIT / REPOSITION / HUNT or the existing canonical vocabulary
- confidence
- concise reason

Never fabricate live conditions. Cached information must be visibly timestamped/stale-aware.

### 6.8 Settings

Organize, do not duplicate:
- Driver/Profile
- Vehicle / cargo limits / MPG / payload facts consumed by calculations
- Operating costs
- Strategy / floors / weekly target
- Notifications / alerts
- Data, backup, import/export/recovery
- Appearance
- Privacy/security
- Owner/driver administration using the **existing zero-token invite/claim design**
- About / version / diagnostics entry as mapped by Gate 3

Do not expose raw tokens just to make onboarding visually simple.

### 6.9 Add Expense

Fast, one-handed form:
- large amount
- category grid
- date
- optional notes/receipt
- prominent Save

Use this form as the interaction-quality benchmark for other mobile forms.

### 6.10 Navigation handoff

The visual mockup shows a full map, but the redesign must not invent a network-map subsystem.

Use a compact handoff sheet/panel with:
- origin
- destination
- distance / known route summary
- navigation provider action

Then deep-link to the device navigation provider using the existing navigation behavior.

---

## 7. Empty, loading, stale, and degraded states

Both fresh installs and long-lived installs with substantial historical data are first-class.

Required honest states include:

- no active trip
- no week data
- no loads / no saved loads
- no completed/unpaid trips
- no expenses/fuel/receivables
- no market data
- market/weather source stale or unavailable
- deadhead unknown
- economics unavailable because material facts are missing
- backup configured but paused / credential unavailable
- offline mode

Do not use skeletons that imply data is definitely arriving when no fetch is in progress.

---

## 8. Explicitly out of scope unless separately approved

- Rewriting the canonical economics/scoring engine
- Changing floors, grade thresholds, DZ doctrine, bid doctrine, or unknown-data semantics
- New map-tile or turn-by-turn subsystem
- New account/cloud backend invented only for the redesign
- Duplicate screenshot parser / duplicate AI evaluator
- Reintroducing Voice/SpeechRecognition after the operator-approved v24.0.17 removal
- Removing existing secondary tools because the mockup does not show them
- Dispatch/dispatcher expansion unless separately authorized
- Destructive schema cleanup or historical-data migration for aesthetic reasons

If the design appears to require one of these, report the dependency as a blocker or operator decision.

---

## 9. Build sequence after Gates 1–4 are approved

1. Establish exact approved baseline and branch.
2. Resolve or formally defer only genuinely open blockers from Gate 2.
3. Land the navigation/ID structural decision with regression coverage before visual restyling if structural work is needed.
4. Centralize design tokens and reusable card/control primitives in the existing presentation seam (`styles.css`) where possible.
5. Implement **Today** and verify against reference plus real data/empty data.
6. Implement **Add Expense** as the form-pattern benchmark.
7. Implement one primary surface at a time: Loads → Load Detail → Evaluate → Trips → Money → Market Intel → Settings → Navigation handoff.
8. Integrate secondary surfaces from the Gate 3 map; no orphan routes.
9. Complete empty/degraded states.
10. Run the full current acceptance/certification stack and physical iPhone verification required by the exact candidate.
11. Apply the release-generation/version bump only according to current repository rules; do not assume `24.5` merely because this brief uses that working label.

Prefer one coherent screen/surface per commit. Do not batch the entire UI into a single unreviewable change.

---

## 10. Acceptance criteria

The redesign is not complete until all of these are true for the exact candidate:

1. Current full regression suite is green with no weakened/skipped assertions.
2. Release-generation and service-worker parity gates are green for the selected release generation.
3. Existing data upgrades with zero unintended record loss or semantic coercion.
4. No new console/runtime/service-worker errors.
5. Existing imports, exports, trips, expenses, fuel, receipts, market/evidence history, and protected recovery paths still work.
6. Every surface from Gate 3 remains intentionally reachable.
7. Unknown deadhead and incomplete economics remain visibly unknown/unavailable where required.
8. Today and Money agree on canonical weekly figures.
9. Unified Load Intake still supports the currently-authorized photo/screenshot/OCR and paste paths after the redesign; retired Voice/SpeechRecognition paths do not return.
10. Owner/driver onboarding still follows the current zero-token invite/claim security contract.
11. The major screens use one coherent token system, spacing rhythm, type scale, card language, and interaction pattern.
12. Core operational numbers are legible at a glance without unnecessary scrolling.
13. Mobile widths and safe-area behavior pass the repo's current visual/layout gates.
14. Physical installed-PWA testing on the operator's iPhone passes the exact current field checklist before the release is called certified.
15. Side-by-side visual review against the approved reference shows no unexplained major hierarchy/layout drift. Any deliberate deviation is documented with the product constraint that required it.

---

## 11. Historical first-gate task — completed; do not restart

This was the original start task and produced the §13 report. It is retained as the reconciliation template, **not** as a command to repeat the audit whenever a new session resumes. On Proceed/Continue/Resume, refresh only facts that may have changed and continue from the current implementation checkpoint:

> Read the project instructions, `UI_BRIEF_V24.5.md`, and `FreightLogic_UI_Reference.html`. Work against the exact current `main` HEAD and record its SHA. Re-verify only what may have changed since the last completed Gate 1–4 report; do not restart a completed audit. Reconcile the center ⚡ against exact current behavior (currently Evaluate/`#omega`) and the approved reference; whichever entry behavior is chosen must reuse the existing Load Intake/evaluation pipeline, not create a second one, and must not reintroduce retired Voice/SpeechRecognition. Identify any statement in the brief or reference that exact current source makes stale, unsupported, or capability-removing, then continue the already-approved redesign workflow under the single-writer/lane rules unless a genuine blocker is found.

That was the original start line. The §13 report was reviewed and the operator repeatedly approved continuation; do not stop for duplicate approval unless a new material conflict, unsafe/destructive action, unavailable authorization, or physical user-only gate requires it.

---

## 12. Review discipline during implementation

After each implemented surface:

- Claude reports exact files changed and how it verified the screen.
- A read-only reviewer compares the result against the reference and this brief.
- The reviewer checks that business logic was **consumed**, not duplicated.
- Any unexpected data/logic defect discovered during UI work is reported separately; do not hide a behavior fix inside a styling commit.
- Only then move to the next surface.

The goal is not "make it look modern." The goal is **make the existing FreightLogic intelligence feel like the approved driver command center without losing truth, safety, history, or reachability.**

---

## 13. Pre-code Gate 1–4 reconciliation — 2026-09-16 / 2026-09-17 UTC

> **Historical snapshot:** this report records the state observed when the redesign gates were first completed. It is retained for provenance and is superseded for current deployment/release facts by the 2026-09-18 current-authority note near the top of this brief. Do not treat the v24.0.14/Worker v19 facts below as current.

This is the report required by §3 and §11. It is a **read-only exact-source reconciliation**; it does not authorize a second runtime writer and it does not claim that the post-v24.5 physical/M6 certification has run.

### Gate 1 — exact source and deployed production: PASS, with one documentation-drift note

Execution baseline: current `main` **`fd84f1190feedc9817230cc915425efd0785e603`**. The commits after the runtime candidate are documentation/coordination work; the shipped runtime generation on `main` remains:

- source app/PWA generation: **24.0.14**;
- IndexedDB schema: **16**;
- source service worker/cache generation: **24.0.14**, cache `freightlogic-24.0.14`;
- source backup/API Worker: **v19**;
- deployed app: **24.0.14**;
- deployed service worker/cache: **24.0.14 / `freightlogic-24.0.14`**;
- deployed backup/API Worker: **v19**.

The production observation of record is live all-asset parity run **`35087770010`**, `workflow_dispatch` on `main` @ **`8f90725`**, whose expected block is app/SW 24.0.14 and Worker 19 and whose verdict was PASS. `service-worker.js` on current `main` still declares `SW_VERSION = '24.0.14'`; `cloud-backup-worker.js` still declares Worker v19. `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-16.md` names DB16 and the same deployed generations.

One file on `main` is stale as documentation: the Project Overview in `CLAUDE.md` still says v24.0.14 is source-only and production is 24.0.12/DB15/Worker17. That prose is contradicted by the current certification authority and live observation above; it is **not** evidence of runtime drift. An in-flight Claude branch contains the correction and a source-only 24.0.15 repair candidate, but 24.0.15 is not on `main` and is not deployed as of this report.

### Gate 2 — current open-risk reconciliation: PASS

Older fixed findings stay closed. The redesign must not reopen them or mix behavior changes into visual commits. Current actionable/open state is:

- Every automatable/live-origin release gate recorded for the deployed 24.0.14/DB16/Worker19 generation is treated according to the current certification authority; no old v24.0.2 audit item is promoted back to OPEN merely because it appears in historical prose.
- **A1–A12 physical-iPhone evidence and M6 private-history reconciliation remain open but are deliberately deferred by operator decision to the final post-v24.5 candidate.** `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` is authoritative for schedule. 24.0.14 is not the certification candidate, and a partial device run against it is not useful evidence for the redesign release.
- M6 remains blocked only on the authentic five raw 2026-08-27 files. The import/reconciliation instrument remains committed; reconstructing the files from summaries is prohibited.
- Credentials originating under superseded Worker v7 remain a **security-hygiene rotation/revocation concern**, not a reason to redesign credential semantics. Worker v19 prevents the old plaintext exposure and cleans reachable residue, but visual work must not expose or persist raw tokens.
- The in-flight Claude 24.0.15 source candidate addresses the current V-1/V-2 audit findings and the `tripRow` UNKNOWN-deadhead presentation residue. Those are runtime/core repairs owned by the sole implementation writer; this redesign report does not duplicate them or hide them inside CSS.
- `FIELD_TEST_CHECKLIST.md` on `main` was stale at 24.0.12/DB15/Worker17 and read like a live test queue. The GPT documentation follow-up paired with this report updates its authority/runtime header and adds the explicit deferral pointer without closing any A-row.

### Gate 3 — complete surface-to-destination inventory: PASS

The reference is not exhaustive. The following map is the preservation contract for implementation.

| Current surface / entry point | Current owner/renderer or service | Sensitivity | Proposed home | Action |
|---|---|---|---|---|
| `#home` Today command center, active trip/positioning/weekly KPIs/recent trips | `renderHome()`, trip tracking, positioning, Money card, IndexedDB/settings | financial + GPS + operational | **Today** | keep + reskin |
| `#loads` Smart Load Inbox | `renderLoadsView()` / `#loadInboxCard`, opportunity/evidence stores | decision-adjacent + provenance | **Loads** | keep + reskin |
| Unified Load Intake | `openLoadIntake()`, `#btnLoadIntake`, `#btnLoadsIntake`; photo/screenshot/paste/voice feeds existing parser/evaluator | decision/data intake | **center action / Loads / Evaluate context** | keep one pipeline; move access only |
| `#omega` canonical evaluator / OMEGA | `renderOmega()`, canonical `app.js` decision/economics, advisory Midwest evidence | **decision-critical** | **Evaluate / center context** | keep + reskin; never recalculate |
| Midwest Stack / DZ / market evidence / bid tiers | canonical evaluator + `midwest-stack-authority.js` advisory paths | decision-critical/advisory | Evaluate + Market Intel | keep; contextual reskin |
| `#trips` trip list/search/filter | `renderTrips(true)`, DB16 `tripRecords`, lifecycle/evidence | financial + operational | **Trips** | keep + reskin |
| Trip add/edit/detail + lifecycle editor | `openTripWizard()`, `openLifecycleEditor()`, receipts, status/payment writers | financial + data integrity | Trips | keep + reskin |
| Trip GPS session / navigation handoff | trip tracking + `openTripNavigation()` / device navigation | **GPS/safety** | Trips / active trip | keep behavior; reskin handoff only |
| Post-trip lane/broker review | `openPostTripReview()` | historical intelligence | Trips completion context | keep + reskin |
| `#money` receivables / AR aging | `renderAR()`, unpaid/payment semantics | **financial** | **Money → Receivables** | keep + merge presentation |
| Home Money dashboard / earnings trends | `renderMoneyCard()` and existing trend/chart surfaces | **financial** | Money → Overview; compact mirror on Today | merge presentation, same calculations |
| `#expenses` + expense form/receipt paths | `renderExpenses()`, `openExpenseForm()`, receipt manager/camera | financial + blobs | Money → Expenses / More | keep + reskin |
| `#fuel` + fuel form | `renderFuel()`, `openFuelForm()` | financial/operating cost | Money → Fuel / More | keep + reskin |
| Settings / Insights | `#insights`, `renderInsights()`, vehicle profile, costs, planning speed, integrations, tax method | decision + financial configuration | **More → Settings** | keep + reorganize/reskin |
| zero-token cloud/owner admin and driver claim | Cloud Backup settings, admin panel, `openClaimWizard()`, Worker v19 | **security/credentials** | More → Settings → Backup/Admin | keep security contract; reskin only |
| backup reconnect / encrypted backup/restore | `openCloudReconnect()`, local encrypted state + Worker v19 | **security/data recovery** | More → Export & Backup / Settings | keep + reskin |
| Setup wizard | `openSetupWizard()` | vehicle/cost configuration | first-run / Settings | keep + reskin |
| More primary tools | `renderMore()` → Money/AR, Expenses, Fuel, Monthly Costs, Documents, Export & Backup, Market Intel, Settings | mixed | header **More** entry | keep all reachable |
| More advanced tools | Tax & Reports, Import Data, CPA Package, Tax Season Export, Security Lock, Storage Health, Diagnostics | financial/security/recovery | More → Advanced | keep all reachable; reskin |
| `#intel` Market Intel hub | `renderIntel()` | operational intelligence | More → Market Intel | keep + reskin |
| Weekly Reports / Rate Trends | `openWeeklyReports()`, `openRateTrends()` | financial/historical | Market Intel / More | keep + reskin |
| Reload Scoring / Chain Analysis / Weekly Strategy / Seasonal Intel | existing Intel actions | strategic/advisory | Market Intel | keep + reskin |
| Cost-Per-Day | `openCostPerDay()` | financial | Money or Market Intel context | keep; no formula change |
| Counter-Offer Memory | `openCounterOfferMemory()` | broker history | Market Intel | keep + reskin |
| Rate Tiers / Bid Calc + Market Board | existing Intel actions / OMEGA advisory tools | decision-adjacent | Market Intel / Evaluate context | keep + reskin |
| Maintenance tracker | `openMaintenanceTracker()` + Today alert | vehicle operations | More / Today alert | keep + reskin |
| Opportunity Intake | `openOpportunityIntake()` + lifecycle/evidence | provenance-sensitive | Loads / Market Intel / More | keep one evidence path; reskin |
| Broker scorecard/notes + lane breakdown | `openBrokerScorecard()`, `openBrokerNotes()`, `openLaneBreakdown()` | historical intelligence | Market Intel / contextual modal | keep + reskin |
| Load Compare / Quick Evaluate | `openLoadCompare()`, `openQuickEvalModal()` / `openQuickEvalFlow()` | decision-critical presentation | Evaluate / contextual quick action | keep; must consume canonical engine |
| Universal Import | `openUniversalImport()` | data integrity | More → Import Data | keep + reskin |
| Documents / receipts | `openDocumentVault()`, receipt manager/camera | blob/data | More → Documents / Trips | keep + reskin |
| CPA/Tax Season/Schedule C/per-diem exports | `openCPAPackage()`, `openTaxSeasonExport()` and tax views | **financial/tax** | Money / More → Tax & Reports | keep + reskin; no tax-rule changes |
| Security Lock | `openSecurityLockModal()` | **security** | More → Advanced | keep + reskin |
| Diagnostics / storage health | `openDiagnosticsPanel()` + storage tools | release/data integrity | More → Advanced | keep + reskin |
| Generic modal/toast/sheets and quick-add | `openModal()`, quick-add, forms | mixed | contextual | keep IDs/handlers; reskin primitive |

No item above is authorized for deletion. Anything omitted from the visual reference remains reachable through its current route/context or the More hierarchy until the operator explicitly approves removal.

### Gate 4 — navigation/DOM/ID compatibility: Plan A, with one bounded runtime decision

**Plan A is selected. No schema migration and no wholesale route/ID migration are justified.** The current canonical router already exposes `home`, `loads`, `omega`, `trips`, `money`, `expenses`, `fuel`, `insights`, `intel`, and `more`. `modern-shell.js` already adapts the primary shell to **Today / Loads / Evaluate / Trips / Money**, preserves those canonical hashes, and adds a header `More` button that routes to the existing `#more` surface. That means the redesign can preserve canonical view IDs and the existing `app.js` router rather than inventing an `ID_MAP.md` migration.

Two constraints are now explicit:

1. **Center ⚡ mismatch.** Current source makes the center control `href="#omega"`; it opens the canonical Evaluate route. Unified Load Intake is the existing `openLoadIntake()` flow exposed by `#btnLoadIntake` / `#btnLoadsIntake`. Therefore the brief's earlier sentence that the center ⚡ *is already* Unified Load Intake is stronger than current source. Implementation must **reuse `openLoadIntake()`** if the operator wants a direct center-intake action; it may not create a second parser, route, or evaluator. Directly rewiring that control is a SHARED/runtime edit and belongs to the sole implementation writer under the lock protocol. A CSS-only GPT change must not fake the behavior.
2. **Presentation CSS is split today.** `styles.css` is the durable presentation seam, but `modern-shell.js` currently injects a sizeable `REFERENCE_UI_CSS` block at runtime. The final redesign should converge on one token system in `styles.css` and avoid two independently drifting style authorities. Removing/moving the injected block is a SHARED-file change, so that consolidation belongs to the sole runtime writer, not a parallel GPT edit.

State/data plan: **no migration**. Preserve DB16, `tripRecords`, settings, receipts/documents, normalized evidence, backup identity and all existing IDs/handlers. Visual work does not clear site data, rebuild IndexedDB, or rewrite records. Before final candidate certification, retain a protected export/backup where the existing product supports it; this is a safety practice, not a prerequisite for a non-migrating CSS change.

Rollback plan: fix forward for runtime releases. A presentation-only commit can be reverted at the stylesheet/adapter level without touching DB16. If any shipped runtime byte changes, the sole runtime writer must advance the governed release generation and service-worker/cache markers under the existing release-generation tests; `v24.5` is not itself permission to choose that number.

### Gate conclusion / approval state

**Gates 1–4 are complete for the baseline above.** The operator has repeatedly instructed the project to proceed, which clears the report/approval checkpoint for continuing the redesign workflow. That does **not** authorize concurrent writers: Claude remains the sole runtime implementation writer described in §2, and GPT's continuing role is the GPT-owned `styles.css` seam plus read-only architecture/reference review unless the lane/lock protocol is explicitly changed.

The physical iPhone A1–A12 and M6 gates are intentionally **not run now**. Per `docs/CERTIFICATION_DEFERRAL_2026-09-16.md`, they run once against the final post-redesign candidate after the field checklist is re-verified against the new shell.
