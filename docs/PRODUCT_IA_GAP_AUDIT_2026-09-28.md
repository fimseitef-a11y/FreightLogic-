# FreightLogic Product IA / UX Gap Audit — 2026-09-28

## Status

- **Audit type:** read-only product-structure audit against the current FreightLogic product north star.
- **Audited runtime candidate:** PR #413 head `46226021ff8f01be5ca1270498e1714d57bde07d`, App/PWA 24.0.48, DB16, Worker30.
- **Production/main at audit start:** `776d47d3f7f848586bd0b181dab06545c50166f0`, App/PWA 24.0.47, DB16, Worker30.
- **Scope:** screen/function inventory, information architecture, workflow duplication, missing product surfaces, preservation constraints, and acceptance-test plan.
- **Not authorized by this audit:** merge/deploy PR #413, physical A1-A14 certification, PushWard/key changes, Agent activation, shared-PC work, Driver Voice Mode, bank/Apple Pay integrations, or freight-doctrine changes.

## Executive result

FreightLogic is not missing its core decision, data-integrity, offline, import, economics, or historical capabilities. The dominant product gap is **information architecture**.

The current app exposes a large amount of mature functionality, but several user jobs are fragmented across the five primary routes, secondary routes, More, Settings, and modal tools. That makes the app feel more complex than the capability itself.

The highest-value work is therefore:

1. make each screen own one primary job;
2. remove duplicate ways to reach the same job;
3. turn Loads into the canonical work queue;
4. make a load detail/decision surface the canonical place for grade, True RPM, bid guidance, fit, timing, and confidence;
5. add an execution-only Active Trip surface;
6. separate completed History from active work;
7. consolidate Expenses + Fuel + Maintenance behind one Add flow while preserving distinct data types;
8. move reporting out of Settings into a dedicated Reports experience;
9. reduce Settings to actual configuration, sync, privacy, and advanced controls;
10. preserve every existing deterministic authority, UNKNOWN-state safeguard, offline behavior, security boundary, and regression gate.

This is a **restructure / simplify** program, not a rewrite.

---

## Current screen / function inventory

### Primary shell today

`modern-shell.js` currently defines five primary routes:

- **Today** — `#home`
- **Loads** — `#loads`
- **Evaluate** — `#omega`
- **Trips** — `#trips`
- **Money** — `#money`

Secondary routed surfaces are:

- **Expenses** — `#expenses`
- **Fuel** — `#fuel`
- **Settings** — `#insights`
- **Market Intel** — `#intel`
- **More** — `#more`

The legacy aliases `today → home` and `evaluate → omega` remain.

### Today

Current responsibilities include:

- daily / weekly gross, spend, net and True RPM;
- driver-position context;
- next-move / positioning guidance;
- active GPS trip tracking card;
- maintenance alert;
- quick Trip / Fuel / Expense actions;
- money / receivable summary;
- smart insight;
- weekly report / chart;
- reload prompt;
- overdue alert;
- recent trips;
- performance / OMEGA cards;
- cloud-backup paused banner and backup nudges.

**Finding:** useful command-center data is present, but Today owns too many secondary jobs. It needs one dominant next action and a much tighter secondary hierarchy.

### Loads

Current responsibilities include:

- unified Load Intake entry point;
- paste-and-score Smart Load Inbox;
- parser confidence / edit-review;
- recent pasted offers;
- handoff into the canonical evaluator.

**Finding:** the current Loads surface is still primarily an intake surface, not yet the driver's compact decision queue. It does not currently behave like a list of normalized decision cards with persistent Pursue / Pass state.

### Evaluate / OMEGA

Current responsibilities include:

- manual evaluator;
- origin / destination / loaded / deadhead / revenue inputs;
- dimensions / weight and van-fit gate;
- pickup feasibility;
- canonical True RPM / economics / grade;
- strategic-floor controls;
- two-output bid guidance;
- saved bid history;
- OMEGA tier analysis;
- market observation logging;
- reposition signal;
- market board tooling.

**Finding:** this route contains multiple distinct jobs: load details, decisioning, bid guidance, market logging, and advanced market tools. The deterministic engine is strong; the screen boundary is too broad.

### Trips

Current responsibilities include:

- create trip;
- search;
- All / Unpaid / This Week / This Month filters;
- date / paid-state filters;
- JSON / CSV export;
- import;
- active and historical trip rows;
- trip lifecycle editing;
- receipt/document functions;
- navigation;
- GPS trip tracking integration;
- post-delivery review;
- delete / undo protections.

**Finding:** active execution and completed history are mixed in the same conceptual surface. The data model already distinguishes lifecycle stages well enough to separate these experiences.

### Money

Current responsibilities include:

- receivables / AR aging;
- unpaid list;
- links to Expenses, Fuel, Reports & Settings;
- overdue-payment authority.

**Finding:** this is a valid secondary business-management surface, but it competes for permanent bottom-nav priority with operational work.

### Expenses

Current responsibilities include:

- add expense;
- search;
- list;
- pagination;
- JSON / CSV export;
- import;
- receipt attachment / management paths.

### Fuel

Current responsibilities include:

- add fill-up;
- list;
- pagination;
- CSV export;
- import;
- fuel-cost / MPG data that feeds economics.

### Maintenance

Current maintenance capability exists as a modal tracker, not a primary route. It supports:

- named service items;
- service intervals in **days**;
- last service date / cost / notes;
- due / warning / overdue status;
- custom service items;
- service logging.

**Gap:** there is no odometer-based due model in the current tracker. The target calls for next-due tracking by mileage and/or time.

### Settings

The Settings route currently contains or exposes:

- weekly summary metrics;
- display text size / Glance Mode;
- vehicle / van dimensions / payload;
- home location;
- operating arrangement / settlement basis;
- operating-cost inputs;
- weekly goal and recurring monthly costs;
- Canada / data-service settings;
- cloud backup / restore;
- invite / claim;
- notifications / Shortcuts;
- security lock;
- diagnostics;
- storage health;
- import / export;
- privacy / local reset;
- maintenance;
- tax quick view;
- accountant export.

**Finding:** Settings is the single largest IA overload. Several items here are not settings at all: reports, tax summaries, accountant exports, storage tools, maintenance, and operational weekly metrics.

### Market Intel

The existing intelligence route has tabs for:

- Overview;
- Lanes;
- Reloads;
- Brokers;
- Tools.

It already contains weekly market statistics, lane history, reload information, broker intelligence, and advanced tools.

**Finding:** the capability is worth keeping, but it should be an advanced intelligence destination rather than a required step in the normal load-decision flow.

### More

Current grouped categories are:

- Work & Records;
- Money;
- Business & Tax;
- Data & Backup;
- App.

Current tiles include Market Intel, Documents, Money/AR, Expenses, Fuel, Monthly Costs, Tax & Reports, CPA Package, Tax Season Export, Export & Backup, Import Data, Storage Health, Settings, Security Lock, and Diagnostics.

**Finding:** grouping is improved versus a flat menu, but the route still exposes multiple overlapping entry points to Settings, reporting, backup, import/export, money, and business tools.

---

## Current onboarding inventory

The first-run wizard is currently five steps:

1. Home base.
2. Vehicle type, year, combined Make / Model, MPG.
3. Weekly revenue goal and fuel cost.
4. Monthly fixed expenses plus estimated monthly miles.
5. Operating-region preference and optional payload limit.

The wizard can be skipped and it does not run when migrated data already exists.

### Onboarding classification

**CHANGE**

The target onboarding should become materially lighter:

- user/account identity and operating profile;
- carrier / company context;
- vehicle **Year → Make → Model → Trim**;
- authoritative standard vehicle specs when available;
- explicit user operating-limit override when different;
- defer weekly goals, monthly costs, tax/reporting choices, and advanced market preferences until after the driver reaches the product.

Do not force accounting/tax knowledge during first-run.

---

## Product-area gap matrix

| Product area | Current state | Classification | Required direction |
|---|---|---|---|
| Navigation / IA | Five primary routes plus multiple secondary routes and modal tool hubs | **CHANGE** | One clear job per surface; reduce route duplication and hidden modal destinations |
| Onboarding | Five-step setup including costs and operating preferences | **CHANGE** | Minimal account/operating profile + Y/M/M/T vehicle setup; move costs/goals later |
| Vehicle profile | Vehicle class, year, combined make/model, MPG, van dimensions/payload, user-entered limits | **CHANGE + ADD** | Separate standard spec from user operating limit; authoritative source + provenance; explicit override confirmation |
| Today / Home | Rich command center with many cards and nudges | **KEEP + CHANGE** | Keep useful KPIs/positioning but enforce one dominant next action based on active-trip state |
| Loads | Intake + paste-and-score workflow | **CHANGE** | Become normalized decision queue with compact cards and persistent Open / Pursue / Pass actions |
| Load details | Mostly embedded in Evaluate | **ADD as distinct product surface** | Decision-critical facts first; Why; fit; timing; destination; bid guidance; economics; confidence |
| Evaluator engine | Mature canonical economics / UNKNOWN / fit / timing logic | **KEEP** | Reuse unchanged behind new surfaces |
| Bid guidance | Two-output bid logic and bid history exist | **KEEP + CHANGE** | Present as System/Baseline + Recommended Market bid in the load-detail flow; preserve lifecycle/outcome |
| Bid lifecycle | WON/LOST/EXPIRED/DEACTIVATED/etc. model exists | **KEEP + CHANGE** | Driver-facing Pending / Won / Lost / Expired / No response / Counter flow tied to a load |
| Active Trip | Tracking exists, but no dedicated execution-only route | **ADD** | Current Load / Active Trip screen with pickup→delivery, statuses, addresses, docs, notes, navigation, final rate |
| Trips / History | Searchable list mixes operational and historical concerns | **CHANGE** | Completed/bid History separated from active execution; preserve imports/exports/filters |
| Expenses | Dedicated route + receipts | **KEEP + CHANGE** | Keep data model; unify Add flow with Fuel / Maintenance / Other |
| Fuel | Dedicated route + economics integration | **KEEP + CHANGE** | Preserve distinct records/calculations; enter through common Add flow |
| Maintenance | Modal, time-interval based | **CHANGE + ADD** | Move to Expenses/Maintenance area; add mileage/time next-due model and optional receipt/photo |
| Money / AR | Strong receivable aging and payment authority | **KEEP** | Secondary business surface; likely not a permanent operational nav slot |
| Settings | Very broad configuration/report/data hub | **CHANGE** | Restrict to vehicle/carrier, preferences, economics, sync/backup, notifications, privacy, advanced |
| Sync / backup | Local-first plus invite/token/passphrase cloud backup | **KEEP now / ADD later** | Preserve current backup; next architecture track is managed per-user canonical cloud sync + offline cache |
| Reports | Weekly charts, tax views, exports and trends exist across several locations | **ADD + CONSOLIDATE** | Dedicated premium Reports dashboard with revenue, miles, True RPM, cost/mile, profit, lane/carrier/bid performance |
| Alerts | Today banners + overdue/maintenance + Web Push | **CHANGE** | One prioritized alert model with load/trip/vehicle/business categories and per-category controls |
| Intelligence | Strong Market Intel route + evaluator evidence | **KEEP + CHANGE** | Advanced route remains; normal load decision gets compact Intelligence card with grade ≠ confidence |
| Privacy / security | Strong local-first, self-only CSP, secret exclusions, PIN, diagnostics, export/import safeguards | **KEEP** | Preserve; add clear per-user cloud/privacy contract before shared intelligence ships |
| Offline / PWA | Core architectural strength | **KEEP** | Non-negotiable through every restructure |
| Driver Voice Mode | Backlog only | **DEFER** | Do not start during IA completion |
| Bank / financial feeds | Not current product | **DEFER** | Later optional integration only |
| Apple Pay-adjacent automation | Not current product | **DEFER** | Later optional integration only |

---

## Highest-value duplication / overlap findings

### 1. Loads vs Evaluate

A driver currently captures a load in Loads, then is sent into Evaluate. Evaluate also exposes its own screenshot intake and manual input.

**Direction:** Loads should own the work queue and intake. Opening a load should open its detail/decision surface. The user should not need to understand that a separate "Evaluate" product exists.

The evaluator engine remains canonical; only the navigation contract changes.

### 2. Trips vs active trip execution

Trips currently owns creation, active/incomplete rows, completed history, unpaid status, imports/exports, and post-delivery review.

**Direction:** split the experience, not the data:

- Active Trip = execution only.
- History = completed / bid / historical records.
- Money = receivable/payment view.

### 3. Money / Expenses / Fuel / Monthly Costs / tax reports

These are connected financially but currently exist across multiple routes, More tiles, and Settings.

**Direction:** keep distinct record semantics, but expose one obvious business-management hierarchy:

- Money / AR
- Expenses & Maintenance
- Reports
- Settings → Costs only for assumptions/configuration

### 4. Settings vs Reports vs Data tools

Settings currently owns configuration, reports, tax, accountant export, storage health, cloud backup, notifications, diagnostics, maintenance, and reset/recovery.

**Direction:** remove non-settings work from Settings. Settings should configure behavior; it should not be the place where the driver performs reporting, maintenance, or routine data-entry jobs.

### 5. Today overload

Today currently surfaces many independent cards.

**Direction:** use a strict hierarchy:

1. dominant next action;
2. active/current-load card when applicable;
3. compact Today summary;
4. only urgent/actionable alerts;
5. secondary insights below.

---

## Recommended target IA for the next implementation phase

This is a recommendation for the implementation plan, not an authorization to change runtime yet.

### Bottom navigation

A five-slot operational shell can be simplified around:

1. **Home**
2. **Loads**
3. **Trip** — contextual Current Trip when active
4. **History**
5. **More**

Evaluate becomes a load-detail action instead of a permanent primary tab.

Money, Reports, Expenses/Maintenance, Intelligence, Documents, Settings and advanced tools remain reachable from Home/More or contextual links.

If product review retains Money as a primary tab, Active Trip still needs a first-class contextual entry and Evaluate should still stop being a separate product concept.

### Home

No active trip:

- primary: **Scan / Review Loads**
- secondary: compact Today metrics + alerts

Active trip:

- primary: **Current Load**
- secondary: next appointment / route / status + compact Today metrics

### Loads

Each card should show:

- lane;
- pickup / delivery timing;
- loaded miles;
- deadhead / all-in miles;
- rate;
- True RPM;
- weight / fit warning;
- grade;
- critical warnings;
- state: New / Pursuing / Pending / Counter / Won / Lost / Expired / Passed.

Actions: **Open · Pursue · Pass**.

### Load Detail / Decision

Order:

1. lane + timing + fit;
2. rate / all miles / True RPM / grade;
3. critical warnings;
4. plain-language Why;
5. System/Baseline bid;
6. Recommended Market bid;
7. cost / contribution / all-in profit context;
8. confidence and provenance;
9. Pursue / Pass / custom bid.

Confidence must never be presented as grade.

### Active Trip

Execution only:

- pickup → delivery;
- appointments;
- origin / destination;
- addresses / contacts / references;
- En Route / Arrived / Loaded / Delivered;
- navigation;
- BOL / photos / documents;
- notes;
- final rate;
- trip tracking status.

No bid-market clutter.

### History

Private per-user history with:

- completed trips;
- bid outcomes;
- carrier / broker;
- vehicle;
- loaded / deadhead / all miles;
- rate;
- True RPM;
- cost / profit estimates;
- attachments;
- useful filters and export.

### Expenses & Maintenance

One Add chooser:

- Fuel
- DEF
- Oil change
- Repair
- Tires
- Tolls
- Parking
- Insurance
- Other

Each record type keeps its own schema/authority.

Maintenance adds:

- current odometer or service mileage when known;
- next due mileage;
- next due date;
- optional receipt/photo;
- service notes.

### Reports

Dedicated premium visual dashboard:

- weekly revenue;
- loaded / deadhead / all miles;
- True RPM;
- cost per mile;
- contribution;
- all-in profit estimate;
- daily trend chart;
- lane performance;
- carrier/broker performance;
- bid outcome performance;
- accountant/tax exports as secondary actions.

### Settings

Keep only:

- account / carrier profile;
- vehicle profile;
- scan / load preferences;
- cost assumptions;
- sync / backup;
- notifications;
- privacy;
- display / accessibility;
- advanced settings / diagnostics.

---

## Acceptance-test plan

These tests are the contract for any later runtime restructuring. Existing deterministic/business tests remain mandatory.

### IA / navigation

**IA-01 — one primary job per route**  
Each primary route has one named job and does not duplicate another primary route's core action.

**IA-02 — no orphaned capability**  
Every currently shipped More/Settings/Intel capability remains reachable after regrouping or is explicitly removed by a documented product decision.

**IA-03 — primary navigation consistency**  
Bottom navigation, route title, URL/hash, selected state, back behavior and Home Screen launch remain consistent on iPhone widths.

### Onboarding / vehicle

**ONB-01 — minimal first-run path**  
A new user can reach usable Home without entering monthly expenses, tax method, weekly target, bank data, or advanced market preferences.

**ONB-02 — vehicle identity**  
Year, Make, Model and Trim are separate durable facts when supplied.

**VEH-01 — standard spec provenance**  
An auto-filled standard payload/dimension value records its authoritative source/version and is visibly labeled Standard Spec.

**VEH-02 — operating-limit override**  
A user limit above or below standard is shown beside the standard value, requires explicit confirmation, stores an override marker, and remains editable.

**VEH-03 — no silent legal/manufacturer inference**  
A user operating preference never silently replaces manufacturer/legal ratings in provenance or display.

### Home

**HOME-01 — no active trip**  
Exactly one dominant operational CTA is Scan/Review Loads.

**HOME-02 — active trip**  
Exactly one dominant operational CTA is Current Load; load execution status is immediately visible.

**HOME-03 — alert budget**  
Only actionable/urgent alerts can appear above the compact Today summary; low-priority nudges do not stack into a wall of cards.

### Loads / decision / bids

**LOAD-01 — compact card contract**  
Every normalized load card exposes the required lane, timing, miles, rate, True RPM, weight/fit, grade and warning facts without opening details.

**LOAD-02 — UNKNOWN preservation**  
Missing deadhead, rate, timing or fit facts remain visibly UNKNOWN and never become zero or PASS.

**LOAD-03 — queue actions**  
Open, Pursue and Pass are distinct, persistent, reversible where appropriate, and do not silently create a completed trip.

**DETAIL-01 — canonical decision authority**  
Load Detail reads grade, True RPM, fit, timing, economics and bid guidance from the existing canonical decision layer; no second calculator is introduced.

**DETAIL-02 — confidence is separate**  
Grade/outcome and evidence confidence are visually and programmatically distinct.

**BID-01 — two-output contract**  
Baseline/Cost-Protected and Recommended Market bids remain separately labeled and preserve their existing authority/provenance.

**BID-02 — lifecycle**  
Pending, Won, Lost, Expired, No Response and Counter cannot be collapsed into one generic state; Won does not imply Delivered.

### Active Trip / History

**TRIP-01 — execution-only surface**  
Active Trip exposes execution fields/actions and contains no market-bid analysis clutter.

**TRIP-02 — lifecycle guard**  
Scheduled dates never make a newly booked trip Delivered; post-delivery learning only starts after explicit delivered state.

**TRIP-03 — document retention**  
BOL/photos/receipts/notes remain attached to the same stable trip identity across close/reopen/offline/reconnect.

**HIST-01 — active vs history separation**  
Active work is not presented as completed history; completed/bid history remains searchable/filterable/exportable.

### Expenses / maintenance

**EXP-01 — one Add chooser**  
The user can start Fuel, DEF, Oil Change, Repair, Tires, Tolls, Parking, Insurance or Other from one Add flow.

**EXP-02 — record semantics preserved**  
Consolidating entry points does not collapse fuel, expense and maintenance stores/semantics into one ambiguous record type.

**MAINT-01 — mileage/time due**  
A maintenance item may be due by mileage, time, or both; UNKNOWN odometer remains UNKNOWN.

**MAINT-02 — attachment path**  
Receipt/photo attachment is optional and works for fuel, expense and maintenance/service records.

### Settings / sync / privacy

**SET-01 — settings-only contract**  
Reports, routine maintenance logging and routine expense entry are not hidden inside Settings.

**SYNC-01 — current backup preserved**  
Existing local/offline data and current backup/export/recovery paths remain functional during IA changes.

**SYNC-02 — future managed account boundary**  
Before managed per-user cloud sync ships, canonical server identity, local cache, offline mutation, conflict, restore and device-change behavior have explicit tests; Google Drive/secondary export is not canonical storage.

**PRIV-01 — no secret export**  
Bearer tokens, shortcut keys, PIN data, passphrases and admin credentials are absent from backup/export/certification payloads.

**PRIV-02 — cross-user isolation**  
No raw user record is exposed to another user; any shared intelligence requires de-identified/aggregated data and a separately reviewed privacy contract.

### Reports / alerts / intelligence

**REP-01 — dedicated report surface**  
Weekly revenue, miles, True RPM, cost/mile, contribution/all-in profit, lane/carrier/bid performance and trend charts are reachable without entering Settings.

**REP-02 — economics labels**  
Contribution and all-in profit remain separately labeled and do not silently substitute for one another.

**ALERT-01 — categorized controls**  
Load, trip, vehicle/maintenance and business/payment alerts have distinct enablement/control states.

**ALERT-02 — priority**  
Critical operational alerts outrank informational reminders; duplicate alerts from Home, push and More do not compete simultaneously.

**INTEL-01 — decision card**  
The load-detail intelligence card exposes grade, Why, bid outputs, economics, confidence and provenance without reimplementing canonical economics.

### PWA / accessibility / regression safety

**PWA-01 — offline core**  
Home, Loads queue, Load Detail, Active Trip, History and local Add flows work after priming and while offline.

**PWA-02 — update safety**  
A service-worker/app-generation update does not erase IndexedDB data or strand the installed PWA on mixed generations.

**A11Y-01 — iPhone layout**  
Standard/Large/Extra Large and Glance Mode keep primary actions reachable without horizontal overflow or clipped primary content.

**REG-01 — existing suite preserved**  
Every restructuring PR that touches `app.js` or other core runtime paths runs the full registered suite. No existing assertion is weakened/quarantined to make IA work green.

**REG-02 — manual evidence stays manual**  
No browser/headless result auto-certifies physical A1-A14 or the PushWard real-device gate.

---

## Preserve exactly

The IA work must preserve these existing strengths:

- canonical True RPM / grade / bid / cost authority;
- UNKNOWN vs explicit zero semantics;
- van-fit hard gates;
- pickup-feasibility safety behavior;
- bid/outcome lifecycle distinctions;
- post-delivery learning only from legitimate delivered evidence;
- operator corrections outranking weak extraction;
- local/offline durability;
- IndexedDB migration safety;
- service-worker generation integrity;
- backup/export/restore and checksum protections;
- credential/secret exclusion;
- CSP self-only executable-code boundary;
- XSS and CSV-formula-injection defenses;
- field-certification runner semantics;
- current Web Push / Shortcuts safety rules;
- current historical M6 certification unless importer/reconciliation semantics change.

---

## Remove or consolidate at the presentation layer

These are presentation/IA candidates, not data-deletion instructions:

- remove **Evaluate** as a separate product concept once Load Detail owns evaluation;
- remove duplicate intake entry points after Loads owns intake;
- move report/tax execution out of Settings;
- move routine Maintenance out of Settings;
- consolidate repeated Export / Import entry points under one Data / Backup location while keeping contextual exports where useful;
- reduce Today cards that duplicate data already visible in dedicated surfaces;
- avoid separate surfaces showing the same weekly progress or same position conclusion.

Do **not** delete underlying data, stores, calculations, history, or exports merely because a duplicate entry point is removed.

---

## Deferred scope

Do not mix these into the IA completion:

- Driver Voice Mode;
- bank transaction feeds;
- Apple Pay-adjacent automation;
- additional optional backup providers;
- paid/native Apple Developer track;
- AI Agent activation or model authority over canonical freight economics;
- permanent changes to freight doctrine, rates, cost constants or market classifications.

---

## Safe implementation sequence after this audit

1. **Freeze candidate identity** after the currently gated PR #413 delivery decision; do not restructure against an untracked moving runtime.
2. **Navigation contract first:** decide final five primary jobs and add red-first IA tests.
3. **Pure regrouping before new capability:** move/relink existing surfaces without changing economics or storage semantics.
4. **Loads → Load Detail:** make intake/queue/detail the canonical decision flow while reusing the evaluator.
5. **Active Trip / History split:** reuse existing lifecycle/tracking/data, add the missing dedicated execution surface.
6. **Expenses/Maintenance consolidation:** unify entry UX, then add mileage-based maintenance as a separately tested data extension.
7. **Reports extraction:** move existing reports/charts out of Settings before adding richer visual reporting.
8. **Settings cleanup:** leave only configuration, sync, privacy, notifications, accessibility and advanced diagnostics.
9. **Full exact-head suite after every core-runtime change.**
10. **Production/live parity and physical iPhone A1-A14 remain separate evidence gates.**

## Audit conclusion

The app should not gain another major feature before this structure is simplified.

The highest-return next implementation is a controlled IA refactor that **reuses the current engines and data**, reduces route overlap, and makes FreightLogic feel like one coherent driver workflow instead of a collection of powerful tools.
