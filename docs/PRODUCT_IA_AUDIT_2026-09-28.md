# FreightLogic v24.0.48 Product / IA Gap Audit

**Audit date:** 2026-09-28  
**Runtime inspected:** PR #413 candidate head `46226021ff8f01be5ca1270498e1714d57bde07d`  
**Production main at audit start:** `776d47d3f7f848586bd0b181dab06545c50166f0` (App/PWA 24.0.47, DB16, Worker30)  
**Candidate:** App/PWA 24.0.48, DB16, Worker30  
**Audit-only artifact:** no runtime, economics, storage, Worker, service-worker, or release byte is changed by this document.

## Executive finding

FreightLogic already contains most of the hard capabilities the operator needs. The main remaining product problem is **information architecture and concentration of responsibilities**, not missing algorithms.

The current candidate has five primary routes — Today, Loads, Evaluate, Trips, Money — plus More. Underneath those routes, the app exposes a large feature set: load intake, deterministic evaluation, trip lifecycle, AR, expenses, fuel, maintenance, cloud backup, Web Push/Shortcuts, market intelligence, reporting, tax/export, diagnostics, privacy/storage, vehicle settings and more.

The usability gap is that several surfaces still own multiple jobs at once:

- **Today** combines command actions, sync state, KPI dashboard, unpaid/backup/reflection actions, trip tracking, money, positioning, maintenance, fuel nudges, reports, alerts and recent trips.
- **Evaluate** combines intake, canonical evaluation, OMEGA tier tools, market-board tools and historical lane data.
- **Trips** is both new-trip entry, trip lifecycle editing and historical browsing/export.
- **Settings** includes settings, sync/backup, notifications, storage/recovery, privacy, tax/accountant reporting and a weekly summary.
- **More** duplicates entry points for Money, Expenses, Fuel, Reports, Export/Backup and Settings.

The target should therefore be a **single-purpose screen model** that keeps the existing deterministic engines and evidence model but presents them through fewer, clearer driver flows.

## Classification matrix

| Area | Current verified state | Classification | Required product direction |
|---|---|---|---|
| Navigation / IA | Bottom nav: Today, Loads, Evaluate, Trips, Money. More exposes grouped secondary destinations. | **CHANGE** | Keep a simple bottom nav, but assign one primary job per route. Eliminate duplicated canonical destinations and ambiguous “where do I do this?” paths. |
| Onboarding | Five-step wizard asks home base, vehicle type/year/make/MPG, weekly goal/fuel, monthly fixed costs, operating preferences. | **CHANGE + ADD** | Make onboarding minimal: account/profile, operating/carrier context, Year → Make → Model → Trim. Do not require fixed-cost or tax-accounting choices to enter the app. Add authoritative vehicle-spec lookup when available. |
| Vehicle profile | Van dimensions/payload/MPG are editable and vehicle profiles exist. | **KEEP + ADD** | Preserve current fit gate and editable profile. Add explicit **STANDARD SPEC vs USER OPERATING LIMIT**, provenance, override marker and confirmation whenever user limits differ materially above or below standard. |
| Today / Home | Rich dashboard with command strip, KPIs, actions, trip tracking, money, positioning, maintenance, weekly report, alerts and recent trips. | **CHANGE** | One dominant next action. No active trip → Scan/Review Loads. Active trip → Current Load. Keep a compact Today summary; move reports/settings/history tools out of the primary decision surface. |
| Loads | Dedicated route exists, but the main experience is Paste & Score / intake rather than a durable compact load queue. | **CHANGE + ADD** | Make Loads a decision queue. Cards show lane, pickup/delivery timing, loaded/deadhead/all-in miles, rate, True RPM, weight, grade and warnings. Primary actions: Open / Pursue / Pass. Preserve screenshot/paste/type intake as acquisition methods. |
| Load details / decision | Canonical evaluator is mature and preserves UNKNOWN semantics, fit gates, True RPM and cost authority. Evaluate also hosts OMEGA and market-board tools. | **KEEP core + CHANGE presentation** | Keep one canonical evaluator. Put decision-critical numbers first, then plain-language Why, fit/timing, destination/market context, system bid, realistic market range, cost/profit context and confidence. Keep confidence separate from grade. Move specialist OMEGA/board tools behind secondary access. |
| Bid lifecycle | Bid history and explicit lifecycle states exist; outcome semantics distinguish WON, DELIVERED, PAID, EXPIRED, DEACTIVATED, etc. | **KEEP + ADD UI** | Make Pending / Won / Lost / Expired / No response / Counter first-class user states. Preserve submitted bid, counters and awarded rate for learning. Never infer outcome from dates or price. |
| Active trip | Execution status exists and trip tracking is rendered on Home; trip wizard carries operational stage. | **ADD dedicated surface** | Create an execution-only Current Load/Active Trip surface: pickup → delivery, appointments, addresses, contacts, references, notes, En Route / Arrived / Loaded / Delivered, BOL/docs/photos and final rate. No bidding clutter here. |
| Trips / History | Trips route supports add/edit, lifecycle, search, paid filters, date filters, import/export and history. | **CHANGE** | Separate **operational active trip** from **history**. History remains private and searchable with lane/date/carrier/vehicle, loaded/deadhead/all miles, rate, True RPM, costs/profit, attachments and bid/load outcomes. |
| Expenses / Fuel / Maintenance | Expenses and Fuel are separate routes/forms. Maintenance is a modal schedule based mainly on day intervals; receipt infrastructure exists elsewhere. | **CHANGE + ADD** | Use one simple Add flow for fuel, DEF, oil, repair, tires, tolls, parking, insurance and other expenses. Optional photo/receipt attachment. Maintenance should support next due by mileage and/or time, odometer, notes and attachment. |
| Money / AR | AR aging and unpaid authority are explicit and now fail closed against review-required/payment-unknown imports. | **KEEP core + CHANGE IA** | Preserve receivable authority and payment semantics. Keep AR reachable, but do not use Money as a catch-all navigation hub for unrelated settings/reports. |
| Settings / Sync | One large Settings surface owns vehicle, costs, Canada/data settings, display, cloud backup, Web Push/Shortcuts, privacy, storage, tax and accountant export. | **CHANGE** | Settings should own preferences/configuration only: vehicle/carrier profiles, load preferences, costs, sync/backup, notifications, privacy, advanced. Reports/tax output belong in Reports; AR belongs in Money; operational alerts belong in Alerts. |
| Cloud / accounts | Current system supports invite/claim, token/passphrase backup, local IndexedDB/offline behavior and privacy controls. | **KEEP now + DEFER architecture** | Preserve current verified backup and offline behavior. Long-term canonical target remains authenticated FreightLogic-managed per-user cloud data with automatic sync + local cache. Google Drive/secondary export remains optional, not the canonical DB. This architecture is a separate later project, not part of the IA cleanup. |
| Reports | Weekly report card, earnings trends, tax views, CPA/accountant exports and charts exist in several locations. | **CHANGE / CONSOLIDATE** | Create one premium Reports surface: weekly revenue, miles, True RPM, cost/mile, profit estimate, lane/carrier/bid performance and clear trend charts. Move existing report features here rather than duplicating them. |
| Alerts | Today has Alerts & Actions; overdue payment, maintenance, positioning/trend alerts and Web Push exist. | **ADD consolidated surface/model** | One prioritized optional alert model covering load, trip, vehicle and business alerts. Keep notification permission user-initiated and preserve iOS/Web Push constraints. |
| Market Intelligence | Market Intel already has Overview/Lanes/Reloads/Brokers/Tools and substantial historical intelligence. | **KEEP + CHANGE entry hierarchy** | Keep specialist intelligence, but make it secondary to the driver decision flow. The load detail screen should consume a concise Intelligence card rather than forcing the driver into specialist tools for a routine decision. |
| More | Grouped tiles expose many capabilities but duplicate several primary destinations. | **REMOVE duplicate entries + KEEP utilities** | More should be a utility drawer, not a second home screen. Remove duplicate primary-navigation destinations once their canonical homes are clear; keep low-frequency tools such as Documents, Diagnostics, Security and advanced data utilities. |
| Privacy / evidence | Offline-first IndexedDB, secret-exclusion rules, backup integrity, UNKNOWN preservation and canonical-economics tests are extensive. | **KEEP** | These are non-negotiable constraints for every UI change. No UX simplification may invent zeroes, expose secrets, weaken evidence provenance or create a second calculation authority. |
| Driver Voice Mode / bank feeds / Apple-Pay-adjacent automation | Roadmap ideas only. | **DEFER** | Do not start during current app-finish / IA cleanup work. |

## Remove vs preserve

“REMOVE” in this audit means **remove duplicate UI ownership or navigation**, not delete the underlying capability or its stored data.

Examples:

- Do not delete Expenses, Fuel or AR logic; consolidate how the driver reaches and adds those records.
- Do not delete OMEGA/Market Board; move specialist tools behind the decision flow instead of making Evaluate perform several unrelated jobs.
- Do not delete weekly/tax reports; consolidate them into Reports.
- Do not delete backup/export/diagnostics; keep them as low-frequency settings/utilities.
- Do not delete canonical economics, bid logic, fit gates, lifecycle states, evidence provenance or UNKNOWN semantics.

## Acceptance-test plan

### IA-01 — one primary job per surface
For every driver-facing route, the test must identify exactly one primary job and exactly one visually dominant action. A routine flow must not require choosing between duplicate destinations that perform the same job.

### IA-02 — primary navigation integrity
The bottom navigation remains reachable at supported iPhone widths/text sizes. Every primary tab opens the matching visible surface, the header title agrees with the route, and More does not duplicate the same canonical destination as a competing primary entry.

### ONB-01 — minimal onboarding
A new user can finish onboarding without entering monthly fixed expenses, tax method, per diem, Canada settings, API settings, cloud credentials or other advanced configuration.

### ONB-02 — vehicle identity
Onboarding captures Year, Make, Model and Trim (or explicitly allows “not listed / manual”). Reliable standard specs, when available, are shown as sourced defaults rather than operator-entered facts.

### VEH-01 — standard vs operating limit
Vehicle settings display standard specification separately from the user operating limit. A materially different user limit requires explicit confirmation and leaves a durable override marker. The standard spec is never silently rewritten.

### HOME-01 — no-active-trip priority
With no active trip, Home’s dominant action is Scan/Review Loads. KPI/report/maintenance/AR content cannot visually outrank that next action.

### HOME-02 — active-trip priority
With one active trip, Home’s dominant card is Current Load and opens the execution surface directly.

### LOAD-01 — decision card completeness
A load card shows origin/destination, pickup/delivery timing, loaded miles, deadhead/all-in miles, rate, True RPM, weight, grade and warnings when known. Unknown deadhead remains visibly UNKNOWN/blank and is never converted to zero.

### LOAD-02 — load actions
Each actionable load exposes Open / Pursue / Pass without saving an outcome merely by opening the card. Pursue preserves the proposed/submitted bid; Pass records only an explicit user action.

### DEC-01 — single calculation authority
Load details consume the existing canonical evaluator for True RPM, grade, fit, cost/profit and bid logic. No card or specialist tool may re-derive conflicting economics.

### DEC-02 — decision hierarchy
The first viewport prioritizes rate, True RPM, all miles, grade/verdict, fit/timing warnings and next action. “Why” and market context are plain language. Confidence is displayed independently from grade.

### BID-01 — lifecycle fidelity
Pending, Won, Lost, Expired, No response, Counter, Deactivated/Withdrawn, Delivered and Paid remain semantically distinct. Dates alone cannot promote a load.

### TRIP-01 — execution-only active trip
The Active Trip surface contains pickup/delivery execution information and status controls but no bidding/market-board controls.

### HIST-01 — history completeness
History can filter/search private records and show lane, dates, carrier/broker, vehicle, loaded/deadhead/all miles, rate, True RPM, cost/profit context, attachments and explicit outcome.

### EXP-01 — unified add
One Add flow can create fuel, DEF, oil, repair, tires, tolls, parking, insurance and other expenses. The selected type controls only relevant fields.

### EXP-02 — receipt optionality
Receipt/photo attachment is optional, works for fuel/expense/maintenance records, and never blocks save when omitted.

### MNT-01 — mileage/time due
Maintenance supports mileage-based, time-based or combined due logic. Odometer remains operator evidence and cannot be invented from unrelated trip miles.

### SET-01 — settings scope
Settings contains configuration only. Reports, AR history and routine operational execution do not live inside the Settings hierarchy.

### SYNC-01 — current backup safety
Existing backup/restore/invite/claim behavior keeps secret-exclusion, fail-closed conflict handling, local offline access and current A12 certification semantics intact during IA changes.

### REP-01 — consolidated reports
One Reports surface exposes weekly revenue, miles, True RPM, cost/mile and profit estimate plus at least one readable trend chart. Existing export/tax/accountant functions remain reachable without being duplicated across unrelated screens.

### ALT-01 — consolidated alerts
Operational/business alerts expose priority and opt-in state. Notification permission is requested only from an explicit user action, preserving current Web Push contract.

### INT-01 — concise intelligence card
Load details show grade, plain-language reason, system/baseline bid, realistic market range, cost/profit context and confidence where evidence supports each field. Unknown market evidence is shown as unavailable, not fabricated.

### PRIV-01 — privacy/evidence invariants
No new UI path exposes backup/admin/Shortcut secrets, raw cross-user data or private M6 rows. Unknowns remain unknown. Operator corrections outrank weaker inference. Existing CSV formula-injection and XSS protections remain intact.

### REG-01 — full regression gate
Any `app.js` change requires the full suite. Release-generation/service-worker/storage changes keep their current exact-head gates. Physical-iPhone rows in #226 and PushWard evidence in #380 remain manual and cannot be auto-certified by browser CI.

## Recommended implementation order

1. **Navigation ownership cleanup:** define canonical homes and remove duplicate top-level entry points without changing data or economics.
2. **Home simplification:** one dominant action based on active-trip state; compact summary only.
3. **Loads → decision queue:** preserve all current intake methods, add durable decision-card presentation and explicit Pursue/Pass lifecycle.
4. **Active Trip vs History split:** reuse existing trip/lifecycle data; move execution out of historical browsing.
5. **Expenses/Fuel/Maintenance consolidation:** one Add flow; add mileage/time maintenance and optional attachments.
6. **Settings / Reports / Alerts separation:** move existing functions; do not rewrite them.
7. **Onboarding + vehicle standard/override model:** requires a separate authoritative vehicle-data-source decision and therefore comes after the pure IA moves.
8. **Long-term account/cloud architecture:** separate project after current app-finish work; preserve offline-first behavior and current backup paths until then.

## Explicitly not part of this audit implementation

- Driver Voice Mode.
- Bank feeds or Apple-Pay-adjacent transaction automation.
- New paid Apple Developer / native Swift work.
- Replacing canonical deterministic economics with AI.
- A single-provider dependency for load acquisition.
- Cross-user raw-data exposure.
- Tax/legal advice.
- Production merge/deploy of PR #413.
- Closing #226 or #380 without their required manual evidence.

## Current technical gate at audit completion

PR #413 head `46226021ff8f01be5ca1270498e1714d57bde07d` was reverified before this audit:

- Tests run `36366310489` / job `108753324302`: PASS.
- Lanes run `36366310500`: PASS.
- CodeQL run `36366310506` / job `108753324485`: PASS.
- Branch is 26 commits ahead / 0 behind main.
- PR remains open, mergeable, ready-for-review, unmerged and production-dark.
- `app.js` coordination lock from AIAG-TASK-0016 was released after exact owner/token verification.

This audit therefore begins from a clean repository ownership state while preserving the separate production and physical-device gates.
