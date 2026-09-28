# FreightLogic Product UX / IA Gap Audit v1

**Audit date:** 2026-09-28  
**Repository:** `fimseitef-a11y/FreightLogic-`  
**Stable main audited:** `776d47d3f7f848586bd0b181dab06545c50166f0` — app/PWA 24.0.47, DB16, Worker30  
**Forward candidate also inspected:** PR #413 head `46226021ff8f01be5ca1270498e1714d57bde07d` — app/PWA 24.0.48, DB16, Worker30  
**Product authority:** Airtable coordination `FL-ENG-20260927-PRODUCT-SPEC-V1-VOICE-CONSOLIDATED-01`

This is a structure-and-flow audit, not a new feature authorization. It preserves deterministic freight economics, UNKNOWN-deadhead handling, lifecycle provenance, offline behavior, existing data, security boundaries, and the manual/device gates. PR #413 remains a separate unmerged release candidate.

## Executive conclusion

FreightLogic does not need a ground-up rewrite. The application already contains most of the required operating capabilities; the main remaining product problem is **surface ownership**: too many features live in overlapping places, and several high-value capabilities are technically reachable but not organized around the driver's current job.

The highest-value simplification is to make the product read as one workflow:

**Today → Loads → Load decision → Active Trip → History / Money**

Everything else should support that workflow rather than compete with it.

The current implementation already has:
- a five-item primary shell (Today, Loads, Evaluate, Trips, Money) plus More;
- canonical load evaluation and two-output bidding;
- load intake from text/screenshots;
- explicit opportunity/execution/settlement lifecycle authority;
- trip history and documents;
- Money / AR;
- expenses, fuel and maintenance;
- weekly reports, tax/export tools and market intelligence;
- local-first persistence plus encrypted cloud backup;
- notifications / Shortcuts plumbing.

The product gap is therefore primarily **consolidation, hierarchy, and missing workflow surfaces**, not missing calculation logic.

## 1. Current screen / function inventory

| Current surface | Verified current job | Classification | Product action |
|---|---|---:|---|
| **Today / Home** | Dashboard, quick actions, recent trips, “What’s Next,” weekly KPIs/report, trip GPS tracking, money card, positioning, alerts, quick evaluate | **CHANGE** | Keep Today, but make exactly one dominant action stateful: **Review/Scan Loads** when idle; **Current Load** when an active execution exists. Move secondary analytics lower and remove competing primary CTAs. |
| **Loads** | Paste/type intake, parse a load offer, edit parsed facts, hand off to canonical Evaluate | **CHANGE** | Promote into the decision inbox. Preserve intake, then add compact load/opportunity cards and decision state. Loads becomes the primary pre-award work surface. |
| **Evaluate** | Canonical evaluator, vehicle-fit/timing/economics, decision output, two-output bid, weekly metrics; hidden Rate Tiers and Market Board subpanels | **CHANGE** | Preserve canonical evaluator and route compatibility, but treat it as the **decision engine/detail step** rather than a parallel work universe. Remove/relocate unrelated weekly/market subpanels from the main decision flow. |
| **Trips** | Search/filter history, trip cards, lifecycle chips, edit/receipts/docs/paid/lifecycle actions | **CHANGE** | Make this clearly **History**. Do not make the historical list also serve as the active execution screen. Preserve filters, receipts, documents, settlement and evidence. |
| **Trip Tracking on Today** | GPS start/resume/degraded-state/stop-and-save | **CHANGE** | Preserve tracking engine. Move live execution context into a dedicated **Current Load / Active Trip** surface; Today should summarize and link to it. |
| **Money** | Live receivables / unpaid and aging | **KEEP / CHANGE** | Keep as primary Money surface. Pull only finance-relevant summaries from Settings; do not duplicate AR navigation in multiple directories. |
| **Expenses** | Dedicated business-expense log/import/export/add flow | **CHANGE** | Consolidate with Fuel and Maintenance under one **Costs / Expenses** concept while retaining typed records and source semantics. |
| **Fuel** | Dedicated fill-up log/import/export/add flow | **CHANGE** | Keep fuel-specific fields and MPG logic, but expose it as one Add-cost subtype rather than a separate top-level conceptual destination. |
| **Maintenance tracker** | Schedule, due alerts, service history; service log also writes an Expense | **KEEP / CHANGE** | Preserve behavior. Surface under Costs / Vehicle instead of hiding behind Settings/More modal access. |
| **Settings** | Driver display, vehicle/cost model, planning, Canada/dead-zone, API keys, cloud backup, notifications/Shortcuts, privacy/data, storage/recovery, AR link, tax quick view, accountant export | **CHANGE** | Settings is overloaded. Keep configuration/security/privacy/sync here; move reports/tax outputs and operational money views out. Use progressive “Advanced” disclosure for specialist inputs. |
| **Market Intel** | Overview/Lanes/Reloads/Brokers/Tools plus rate/chain/seasonal/counter-offer tools | **KEEP / CHANGE** | Keep as a secondary intelligence workspace. It should consume verified history and explain evidence; it should not compete with Loads for immediate decisions. |
| **More** | Directory grouped into Work & Records, Money, Business & Tax, Data & Backup, App | **CHANGE** | Keep as a directory, but remove duplicate destinations once Reports and Costs have clear homes. “More” should contain infrequent tools, not daily workflow. |
| **Weekly Reports / tax / CPA exports** | Weekly P&L generation/history/share; tax quick view; accountant/CPA exports | **CHANGE** | Create a coherent **Reports** destination. Keep accountant/tax exports as subtools; do not bury reporting inside Settings. |
| **Cloud Backup** | Token + session passphrase, client-side AES-GCM, device ID, sync/restore; current cloud backup worker | **KEEP now / DEFER architecture** | Preserve proven backup behavior. Product-spec target of first-class per-user FreightLogic accounts/canonical cloud store is a later architecture program; do not disguise current backup as that target. |
| **Notifications & Shortcuts** | Web Push + Shortcuts review flows | **KEEP** | Keep under Settings/Notifications and surface only actionable alert controls. |
| **Opportunity / lifecycle authority** | Opportunity: SEEN/QUOTED/BID/WON/LOST/EXPIRED/CANCELLED/DEACTIVATED; execution and settlement axes | **KEEP / CHANGE UI** | Preserve data model exactly. Present driver-simple labels/statuses in Loads/Details/History without collapsing distinct evidence states. |
| **Onboarding wizard** | 5 steps: home, vehicle, weekly/fuel costs, monthly costs, operating preferences; can skip | **CHANGE** | Reduce first-run to account/profile + carrier + vehicle identity/limits. Move monthly costs and detailed operating preferences to guided post-onboarding setup. |
| **Vehicle profile / fit** | Vehicle year/make settings, manually stored dimensions/payload profile and canonical fit checks | **CHANGE / ADD** | Add Year/Make/Model/Trim identity, authoritative standard-spec autofill when available, and explicit **STANDARD SPEC vs USER OPERATING LIMIT** provenance/override UI. Preserve current operator limits. |
| **Private multi-user account model** | Current cloud module is backup-token/device based, despite historical “Simplified Multi-User” naming | **ADD / DEFER** | The product-spec account/canonical per-user cloud model is not the current backup UX. Design separately; do not destabilize current local-first release while finishing the app. |
| **Driver Voice Mode / bank feeds / Apple-pay-adjacent** | Not part of current finishing scope | **DEFER** | Explicitly out of this release program. |

## 2. Navigation diagnosis

### What is already good
The modern shell has a constrained five-item primary navigation and no longer exposes every tool as a tab. The current primary routes are Today, Loads, Evaluate, Trips and Money, with More reachable separately. This is materially better than the older flat tool model.

### Remaining overlap
1. **Loads and Evaluate overlap.** Loads parses and forwards; Evaluate is where the actual decision lives. For the driver these are one pre-award workflow, not two unrelated destinations.
2. **Trips mixes history and execution semantics.** Live GPS tracking lives on Today while historical lifecycle edits live in Trips. The product needs a recognizable Current Load / Active Trip state.
3. **Costs are split three ways.** Expense, Fuel and Maintenance are separate interaction islands even though the operator thinks “log a cost/service.”
4. **Reports are fragmented.** Weekly P&L, Tax Quick View, accountant export, CPA Package and Tax Season Export are spread across Home, Settings, Intel/More and modal tools.
5. **Settings is doing operational work.** It contains reports, AR navigation and tax output in addition to configuration, sync, notifications, privacy, storage and diagnostics.
6. **More still mirrors other surfaces.** Money/AR, Expenses, Fuel, Tax & Reports and Settings are duplicated as directory tiles.

### Target hierarchy

Primary driver workflow:
- **Today**
- **Loads**
- **Current Load** (contextual; may occupy/replace the center action when active)
- **History**
- **Money**

Secondary directory:
- **Costs**
- **Reports**
- **Market Intel**
- **Documents**
- **Settings**

The canonical evaluator remains fully intact behind Loads / Load Details. Existing deep links to `#omega` remain compatible until a deliberate migration says otherwise.

## 3. Product-spec gap matrix

### Onboarding — CHANGE
Current onboarding is too long for first use and still lacks the target identity model. It asks for monthly fixed costs before the user has reached the core workflow, while Year is optional and Make/Model is a single free-text field.

Target:
- user/account identity when the future account layer is authorized;
- carrier / operating profile;
- Year, Make, Model, Trim;
- initial home base and minimum operating limits;
- defer cost tuning and region strategy to guided follow-up.

### Vehicle — CHANGE + ADD
Keep current fit checks and operator-specific cargo measurements. Add a provenance layer:
- **Standard spec** from a trusted vehicle-data source when available;
- **User operating limit** as a separate value;
- material divergence requires confirmation;
- never overwrite an operator limit silently.

### Home — CHANGE
Current Home contains many useful cards, but the product spec calls for one dominant next action. Home should branch:
- idle: **Review / Scan Loads**
- won/not-started or active execution: **Current Load**
- secondary: Today metrics, urgent money/maintenance/alert items.

### Loads — CHANGE + ADD
Current Loads is primarily intake/parser. It needs a durable decision inbox built from verified opportunities/bids:
- lane;
- pickup/delivery;
- loaded miles;
- deadhead / all-in miles;
- rate;
- True RPM;
- weight / fit;
- grade;
- warning;
- lifecycle state.

Actions: Open, Pursue/Bid, Pass/close when evidence supports that state. Preserve UNKNOWN, and never manufacture a loss from a deactivation/expiry/no-response.

### Load Details / Intelligence Card — CHANGE
The evaluator already owns the hard calculations and has the two-output bidding method. Repackage the output in decision order:
1. Grade + plain-language verdict/why;
2. rate / loaded / deadhead / all-in / True RPM;
3. vehicle fit + timing hard gates;
4. destination/market evidence;
5. **Baseline / Cost-Protected Bid**;
6. **Recommended Market Bid** with named evidence;
7. contribution/all-in profit context;
8. confidence/provenance separate from grade.

### Bid lifecycle — KEEP model / CHANGE presentation
The underlying three-axis lifecycle is stronger than a single status. Keep it. Add a driver-facing pre-award timeline that maps without losing semantics. Do not invent a generic “no response” state unless source evidence supports it; absence remains absence.

### Active Trip — ADD surface / KEEP engine
Current GPS tracking is robust but embedded on Today. A dedicated execution surface should show only:
- pickup → delivery;
- appointments;
- addresses/contact/reference/notes;
- En Route / Arrived / Loaded / Delivered controls mapped to canonical lifecycle;
- BOL/document/photo attachments;
- final rate;
- tracking health and stop/save.

No bidding/market clutter after award.

### History — CHANGE
Rename/reframe Trips as History once Active Trip has its own surface. Preserve:
- filters/search;
- lifecycle;
- loaded/deadhead/all miles;
- rate/True RPM;
- cost/profit;
- receipts/docs;
- paid/settlement;
- operator corrections and evidence.

### Costs / Expenses / Maintenance — CHANGE
Create one Add Cost entry point with typed subflows:
- fuel;
- DEF;
- oil change;
- repair;
- tires;
- tolls;
- parking;
- insurance;
- other.

Maintenance service can continue writing a typed Expense record, but the driver should not have to discover a separate tracker to log ordinary service.

### Settings / Sync / Privacy — CHANGE
Settings should own configuration only:
- vehicle/carrier;
- load/scan preferences;
- economics inputs;
- sync/backup;
- notifications;
- privacy/security;
- advanced diagnostics/provider settings.

Move reporting/tax output away from Settings.

### Reports — ADD destination / KEEP engines
Unify the existing weekly report, tax view, CPA package and tax-season export into a Reports surface. Premium dashboard targets:
- weekly revenue;
- loaded/deadhead/all miles;
- True RPM;
- cost/mile;
- contribution and all-in profit estimate;
- lane/carrier/bid performance;
- daily revenue/profit trends.

### Alerts — KEEP / CHANGE hierarchy
Keep current push/local alert capability and maintenance/AR signals. Prioritize:
1. safety/execution;
2. trip appointment/status;
3. money/AR;
4. maintenance;
5. business/strategy.
Everything else should be optional.

### Data / account architecture — DEFER from current UI cleanup
Current app is local-first with encrypted cloud backup and restore. Do not remove that. The future spec wants a FreightLogic-managed per-user canonical cloud store with offline cache and optional Google Drive backup. That is an architectural migration, not an IA cleanup, and must have its own data-loss/privacy/migration gate.

## 4. KEEP / CHANGE / ADD / REMOVE / DEFER summary

### KEEP
- deterministic evaluator and canonical economics;
- two-output bidding authority;
- vehicle-fit and pickup-feasibility hard gates;
- explicit UNKNOWN deadhead semantics;
- three-axis lifecycle/provenance;
- IndexedDB/offline/PWA behavior;
- encrypted backup/restore;
- documents/receipts;
- AR authority;
- Market Intel evidence tools;
- weekly report computation;
- maintenance schedule engine;
- Web Push / Shortcuts contracts;
- accessibility and field-certification boundaries.

### CHANGE
- Home hierarchy;
- Loads from intake-only toward a durable decision inbox;
- Evaluate placement/presentation;
- Trips → History role;
- costs navigation;
- Settings scope;
- Reports placement;
- More deduplication;
- onboarding length;
- vehicle identity/provenance UI;
- alert priority.

### ADD
- Current Load / Active Trip surface;
- coherent Reports destination;
- unified Add Cost flow;
- durable Loads decision cards/details built from existing opportunity/lifecycle evidence;
- vehicle standard-spec vs operator-limit provenance UI;
- acceptance/regression coverage for the consolidated workflow.

### REMOVE
Remove **duplicate navigation/entry points**, not capability:
- tax/report output from Settings once Reports exists;
- duplicate daily Money/Expense/Fuel destinations from More once their canonical homes are obvious;
- weekly/market utility panels from the immediate Evaluate decision flow once they have a clear secondary home;
- persistent Home CTAs that compete with the single current next action.

No historical data, economics rules, lifecycle states, evidence fields or recovery paths are candidates for deletion in this program.

### DEFER
- Driver Voice Mode;
- bank feeds;
- Apple Pay-adjacent work;
- paid native-iOS track;
- new external-board lock-in;
- first-class account/canonical-cloud migration until separately designed and migration-tested;
- shared cross-user intelligence until privacy/legal/aggregation contracts are ready.

## 5. Acceptance-test plan

These are behavior contracts for the implementation slices; exact file ownership/lock rules still apply.

### UXIA-01 — Primary navigation
At iPhone width, the primary shell exposes no more than five driver workflow destinations. Secondary tools are reachable in no more than two deliberate taps. No existing supported deep link becomes a dead route.

### UXIA-02 — Stateful Today
Given no active/won execution, Today has one dominant **Review/Scan Loads** action. Given an awarded/in-progress load, Today has one dominant **Current Load** action. Secondary cards cannot visually outrank it.

### UXIA-03 — Loads intake + inbox
Text/screenshot/manual intake lands in Loads, preserves UNKNOWN deadhead, and produces a reviewable opportunity/decision card without writing a completed trip or fabricated award.

### UXIA-04 — Load details authority
Every decision card’s grade, True RPM, hard-gate warning, baseline bid, recommended market bid and profit context comes from canonical authority. UI code does not recalculate independent floors/grades.

### UXIA-05 — Bid evidence lifecycle
BID/WON/LOST/EXPIRED/CANCELLED/DEACTIVATED remain distinct. Closing a card cannot silently turn no-response/deactivation/expiry into LOST.

### UXIA-06 — Active Trip isolation
A won/in-progress load opens a dedicated execution surface. Bidding controls are absent. Execution transitions map to canonical lifecycle and the Delivered transition is operator-explicit.

### UXIA-07 — History integrity
History excludes pending/review-only evidence from completed-performance claims. Unknown deadhead stays UNKNOWN. Search/filter empty state is contextual, not first-use onboarding.

### UXIA-08 — Unified costs
One Add Cost entry point can create Fuel, Maintenance and general Expense records without changing their typed underlying stores/fields. Maintenance logging still participates in expense totals exactly once.

### UXIA-09 — Settings scope
Settings contains configuration/sync/privacy/security/advanced controls. Operational reports and tax output are reachable through Reports instead of requiring users to know they are in Settings.

### UXIA-10 — Reports parity
The new Reports destination reproduces weekly P&L, mileage/RPM, tax/accountant export and trend values from existing canonical report functions without duplicate calculations.

### UXIA-11 — Vehicle provenance
Standard spec and user operating limit render as distinct labeled sources. User limits are never overwritten silently. Material divergence requires explicit confirmation and persists provenance.

### UXIA-12 — Offline-first
Today, Loads review of locally held evidence, Active Trip state, History, Costs and Settings remain usable under the established offline contract. New navigation must not introduce a cloud dependency for core work.

### UXIA-13 — Backup/recovery
Existing backup export/restore and cloud-backup tests remain green after IA changes. A UI rename/move cannot make recovery controls unreachable.

### UXIA-14 — Accessibility / driver readability
New primary controls retain accessible names, keyboard semantics where applicable, >=44px coarse-pointer targets, and existing text-size / Glance-mode contracts.

### UXIA-15 — Manual device boundary
Headless CI may validate structure/logic but cannot certify physical iPhone A1–A14 or PushWard real-device behavior.

## 6. Recommended implementation order

### Slice A — IA shell and ownership, no economics rewrite
- make Today’s dominant action stateful;
- add a dedicated Current Load / Active Trip route backed by existing lifecycle/tracking data;
- relabel/reframe Trips as History in visible UI while preserving `#trips` compatibility;
- move Reports out of Settings into one coherent destination;
- deduplicate More entries after canonical destinations exist.

### Slice B — Loads as decision inbox
- preserve current intake;
- materialize compact opportunity/bid cards from existing verified opportunity/lifecycle stores;
- add Load Details presentation that projects canonical evaluator output;
- wire Pursue/Pass/award transitions without weakening lifecycle evidence.

### Slice C — Costs consolidation
- add unified Add Cost chooser;
- preserve fuel/expense/maintenance typed records;
- reduce daily navigation to one costs concept while keeping deep-link compatibility.

### Slice D — Onboarding / vehicle provenance
- shorten first run;
- add explicit carrier/vehicle identity fields;
- design standard-spec provider abstraction;
- add standard-vs-user-limit provenance and confirmation rules.
External vehicle-data integration must be separately authorized/verified before it can become an authority.

### Slice E — Account/cloud architecture
Separate architecture and migration project only after the finishing slices above are stable. It must protect existing local and backup data and cannot silently replace the current recovery path.

## 7. Release and safety boundaries

- PR #413 is the current 24.0.48 runtime candidate and remains unmerged until its separate integration/production gate is authorized.
- This audit does not mark #226 physical iPhone certification or #380 PushWard/key rotation complete.
- No Driver Voice Mode, bank integration, native Apple expansion, credentials, security policy or shared-PC action is authorized by this document.
- No UI cleanup may rewrite canonical freight economics or turn unknown evidence into zero/known state.
- Runtime changes that touch `app.js`, `index.html`, `modern-shell.js`, service worker or other SHARED paths must follow the live lock protocol and required full-suite/release gates.

## 8. Next executable task

After PR #413 integration is explicitly authorized and main is refreshed, take **Slice A only** as a bounded implementation task. Start red-first with UXIA-01/02/06/09/10/14, acquire the exact SHARED-path locks required, preserve deep-link compatibility, run the full suite on every `app.js` change, and stop before production delivery unless separately authorized.
