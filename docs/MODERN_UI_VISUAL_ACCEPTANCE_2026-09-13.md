# FreightLogic Modern UI — Visual Acceptance Contract

Date: 2026-09-13
Last reconciled: 2026-09-14
Owner: GPT presentation lane
Current runtime candidate: `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` / FreightLogic **v24.0.9**
Status: **SOURCE REPAIRS PRESENT; SIX-WIDTH BROWSER GEOMETRY + PHYSICAL IPHONE EVIDENCE STILL OPEN**

## Purpose

This is the visual/interaction finish line for the operator-approved FreightLogic redesign. It does not authorize a second freight engine, new storage model, fake market data, or a rewrite of canonical logic. Claude owns structural/runtime source and test harnesses; GPT owns the presentation seam and visual acceptance contract.

The product goal is simple even when the underlying calculations are sophisticated:

> Open FreightLogic → immediately understand the situation → evaluate a load in seconds → know whether to take it → know what to do next → know what the operation is actually earning.

The five-surface structural pass is already merged. This document now distinguishes three evidence classes that must not be conflated:

1. **source/style invariants** that can be read or regression-tested from the candidate;
2. **browser geometry** that can be measured deterministically at the six release widths;
3. **physical iPhone/PWA behavior** that requires the actual device and must not be inferred from desktop Chromium.

## 1. Primary navigation

The finished five-tab primary navigation is:

1. **Today**
2. **Loads**
3. **Evaluate** — centered primary action
4. **Trips**
5. **Money**

Acceptance:

- every tab opens the content its label promises; do not cosmetically rename an unrelated route;
- the active tab is obvious without relying on color alone where practical;
- Evaluate remains the strongest visual action without overwhelming the other destinations;
- Settings/admin/data tools are not a sixth persistent bottom tab;
- Market/Intel is contextual from Today/Loads rather than occupying a primary bottom slot;
- bottom navigation respects the iPhone home-indicator safe area in Safari and installed-PWA modes;
- every bottom-tab interactive hit target is at least 44×44 CSS px.

## 2. Today

Today answers **“What should I do next?”**, not “what data does the app contain?”

Priority order:

1. active trip / current tracking state, when present;
2. Next Move / positioning recommendation;
3. This Week financial progress;
4. alerts/actions that actually require attention;
5. compact recent trips.

Acceptance:

- one primary decision/action is visually dominant at a time;
- no duplicate weekly/net/AR status pills compete with the Today content in the global header;
- financial values shown here come from the same canonical values/functions used in Money;
- no decorative dashboard card exists only to repeat another number;
- recent trips remain scannable without forcing large cards for every row.

## 3. Loads

Loads is a real destination backed by the existing normalized opportunity/inbox pipeline.

A load row/card should expose, when actually known:

- origin → destination;
- age/urgency;
- loaded miles;
- deadhead and/or all miles with semantics preserved;
- rate/revenue semantic that is actually available;
- True RPM only when canonically calculable;
- grade/decision only when canonically available;
- pickup timing;
- weight/pieces when known.

Acceptance:

- a driver can understand the important economics in roughly two seconds;
- UNKNOWN stays visually unknown; it never renders as `0`, `$0`, `0 mi`, `F`, or `REJECT` merely to fill the card;
- rate labels do not turn shipper/bookable prices or operator bids into carrier revenue;
- one obvious control opens/evaluates the load;
- filters represent real source states only;
- cards do not become dense mini dashboards with nested cards inside cards.

## 4. Evaluate

Default input order:

1. Rate / revenue
2. Loaded miles
3. Deadhead
4. Origin/destination when useful

Everything else belongs behind progressive disclosure unless it must block a physically unsafe/unreachable load before economics. v24.0.9 adds the optional pickup-cutoff / operator planning-speed feasibility gate; it must remain visually secondary when inapplicable and obvious when it blocks an impossible pickup.

Result hierarchy:

1. grade + decision;
2. True RPM;
3. target bid/range when canonical engine provides it;
4. “Why this grade” evidence, including material risks/counter-evidence;
5. deeper economics.

Acceptance:

- answer appears before implementation detail;
- no second UI-side grade/RPM/bid calculation is introduced;
- unknown deadhead still blocks false precision;
- no planning-speed default is invented;
- van-fit or unreachable-pickup failure remains visible before profitable-looking economics;
- required numeric controls use mobile-friendly input modes and do not trigger iOS page zoom;
- primary action remains reachable above the software keyboard where practical;
- advanced disclosure preserves entered values when opened/closed.

## 5. Trips

Trips owns **state of work**, not state of cash.

Acceptance:

- active work is visually distinct from completed history;
- unpaid state may be exposed as a lifecycle signal, but receivables/accounting depth belongs in Money;
- rows are compact and route-first;
- destructive actions are spatially separated from routine actions;
- lifecycle labels reflect real implemented states only;
- reopening/back navigation should not unnecessarily discard search/filter context.

## 6. Money

Money is the financial home for:

- weekly gross;
- expenses;
- net;
- True RPM / net-per-mile metrics already canonically supported;
- fuel;
- receivables / Money Owed;
- overdue amounts when actually known.

Acceptance:

- tabs/subnavigation clearly separate Overview, Expenses, Fuel, and Receivables when structural source supports them;
- currency and mileage use tabular numerals;
- totals reconcile to the existing canonical calculations, not CSS/UI replicas;
- unpaid/overdue states are easy to scan;
- quick-add actions are thumb reachable without crowding the screen.

## 7. Settings

Settings should read like a coherent mobile settings surface rather than a miscellaneous dashboard.

Target groups:

- Vehicle
- Operating Costs
- Strategy / Trip Planning
- Notifications
- Data & Backup
- Appearance
- Privacy / App Lock
- About / Diagnostics

Acceptance:

- existing control IDs/handlers are preserved where practical;
- the optional Trip Planning average speed is understandable as an operator setting, has no invented default, and can be cleared back to inapplicable;
- advanced/dangerous operations use progressive disclosure;
- destructive data actions are isolated and clearly labelled;
- normal settings rows do not use emoji as the primary icon system in the final polish if a consistent icon treatment is available.

## 8. Global visual language

The design direction is a modern native driver/fintech app, not a web dashboard compressed onto an iPhone.

Required:

- dark charcoal/black surface system with FreightLogic amber used selectively for primary actions and state;
- system/iPhone typography for ordinary UI;
- monospace/tabular treatment for money, RPM, and mileage where useful;
- edge-to-edge breathing room and fewer simultaneous boxes;
- no unnecessary card-inside-card layering;
- restrained borders, glow, gradients, uppercase labels, and pills;
- professional iconography; avoid a mixed emoji/icon vocabulary as the final state;
- photography, if used at all, is optional/contextual and must not consume repeated vertical space on Loads/Evaluate/Money;
- do not ship the accidental generated-mockup tagline “Different Drivers A Brighter Tomorrow™”.

## 9. iPhone / PWA hard requirements

These are release-quality checks, not aesthetic preferences.

- `viewport-fit=cover` remains intact;
- top chrome respects `env(safe-area-inset-top)`;
- fixed bottom UI respects `env(safe-area-inset-bottom)`;
- minimum touch target: **44×44 CSS px** for interactive controls on coarse pointers;
- text inputs are **16px or larger** on iPhone to prevent focus zoom;
- no horizontal page scroll at **320, 375, 390, 393, 430, and 440 CSS-px** widths;
- modal/bottom-sheet content remains reachable with the software keyboard open;
- fixed navigation and toasts/banners do not overlap each other or the home indicator;
- installed-PWA and Safari layouts both remain usable;
- long route, broker, city, and money strings truncate/wrap without forcing viewport overflow.

### v24.0.9 source observations already confirmed

The three source defects called out in the original v24.0.7 draft are no longer open source defects:

- **mobile form size:** the v5 `input, select, textarea` override resolves to `font-size: 16px` with a 52px minimum height;
- **theme target:** the `max-width: 480px` rule sets `.theme-btn` to **44×44px minimum**;
- **reduced motion:** a broad `prefers-reduced-motion: reduce` rule constrains global animation/transition durations and explicitly disables named FAB/spinner animation; the later navigation-specific rule is additive, not the only reduced-motion handling;
- **tertiary contrast:** current v5 tokens are approximately **5.27:1** for dark `--text-tertiary #8585a5` on dark `--surface-1 #0f1216`, and **6.19:1** for light `#5f5f78` on light `#ffffff`, above the 4.5:1 target for normal text.

These are **source observations, not a six-width PASS**. Rendered geometry still has to prove there is no horizontal page overflow, undersized primary navigation target, or long-string/modal containment failure at each release width. Safe-area, software-keyboard, Safari, and installed-PWA behavior remain physical-device evidence.

## 10. Accessibility

Acceptance:

- keyboard focus is always visible;
- focus indication is not color-only and is not clipped by overflow where practical;
- text/background contrast remains legible in both dark and light themes;
- status must not depend on red/green alone; labels/icons/text carry meaning too;
- controls with icon-only presentation retain an accessible name in markup;
- disabled state is visually distinct from enabled state;
- `prefers-reduced-motion: reduce` is respected;
- screen-reader-only labels remain available where visual labels are intentionally compact;
- zoom is not disabled in the viewport meta.

## 11. Interaction quality

- use bottom sheets/modals for short mobile tasks rather than desktop-style centered dialogs where existing architecture allows;
- one sticky/obvious primary CTA per task screen;
- destructive controls require clear intent and do not sit adjacent to the main positive action without separation;
- pressed/selected/loading/disabled/error states are visually distinct;
- empty states explain the next useful action;
- loading state does not rearrange the entire screen unexpectedly;
- filters/search preserve context when practical;
- no interaction should require precision tapping while driving/staged roadside use is the expected context.

## 12. Current verification procedure

The structural and presentation source is already integrated into the v24.0.9 runtime candidate. Completion now proceeds as evidence gathering, not another redesign pass:

1. keep runtime candidate `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` frozen unless an actual defect requires repair;
2. run the machine-verifiable six-width browser geometry gate at 320/375/390/393/430/440, dark/light, across Today/Loads/Evaluate/Trips/Money;
3. fail on page-level horizontal overflow, undersized primary interactive targets, <16px mobile inputs, or representative long-string/modal overflow rather than weakening the assertion;
4. keep iOS safe areas, software keyboard, Safari, and installed-PWA behavior in `FIELD_TEST_CHECKLIST.md` A1-A10;
5. run the repository full suite after any test/runtime/presentation repair and preserve exact-SHA evidence;
6. do not certify production or physical iPhone from source/browser evidence alone.

A request for a Claude-owned Playwright six-width geometry gate was staged at `/.agents/inbox/gpt-to-claude-six-width-layout-gate-2026-09-14.md` because `tests/` is Claude-owned.

## 13. Final visual PASS definition

The browser-layout portion is PASS only when all six widths are observed without page overflow or target/form geometry violations in the required themes/surfaces. The physical-device portion is PASS only after the same candidate succeeds in Safari and installed-PWA checks on the iPhone, including safe areas and keyboard behavior.

The overall visual pass is complete only when the app can be used one-handed on a current iPhone without feeling like a developer dashboard: the next decision is obvious, primary data is readable at a glance, forms do not fight the keyboard, navigation is predictable, and complexity is revealed only when needed.

Visual polish must never change freight truth. If presentation and canonical data disagree, canonical data wins and the UI is corrected.
