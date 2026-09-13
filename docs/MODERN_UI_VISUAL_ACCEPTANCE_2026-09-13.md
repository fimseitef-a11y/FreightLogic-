# FreightLogic Modern UI — Visual Acceptance Contract

Date: 2026-09-13
Owner: GPT presentation lane
Applies after: Claude structural pass requested in `/.agents/inbox/gpt-to-claude-modern-ui-structural-pass-2026-09-13.md`
Current source baseline when written: `95a13d8af8b535115ae13a09d345a46beacad876` / FreightLogic v24.0.7

## Purpose

This is the visual/interaction finish line for the operator-approved FreightLogic redesign. It does not authorize a second freight engine, new storage model, fake market data, or a rewrite of canonical logic. Claude owns the structural/source pass; GPT owns the presentation seam and final visual reconciliation.

The product goal is simple even when the underlying calculations are sophisticated:

> Open FreightLogic → immediately understand the situation → evaluate a load in seconds → know whether to take it → know what to do next → know what the operation is actually earning.

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
- every bottom-tab hit target is at least 44×44 CSS px.

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

Everything else belongs behind progressive disclosure unless it must block a physically unsafe load before economics.

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
- van-fit failure remains visible before profitable-looking economics;
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
- Strategy
- Notifications
- Data & Backup
- Appearance
- Privacy / App Lock
- About / Diagnostics

Acceptance:

- existing control IDs/handlers are preserved where practical;
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
- no horizontal page scroll at 320, 375, 390, 393, 430, and 440 CSS-px widths;
- modal/bottom-sheet content remains reachable with the software keyboard open;
- fixed navigation and toasts/banners do not overlap each other or the home indicator;
- installed-PWA and Safari layouts both remain usable;
- long route, broker, city, and money strings truncate/wrap without forcing viewport overflow.

### Current CSS observations to re-check after structural integration

At the v24.0.7 baseline, the presentation seam already provides 16px inputs, safe-area-aware app/header/bottom spacing, focus-visible rules, a floating nav, and system typography. Three items deserve explicit post-structure verification:

- the `@media (max-width: 480px)` theme button currently resolves to **40×40**, below the 44×44 target;
- the final reduced-motion override is narrow, so verify all decorative/stagger/spinner motion is appropriately disabled or simplified under `prefers-reduced-motion: reduce` without disabling functional progress indicators;
- the current v4 `--text-tertiary` token is too faint for the 10–12px labels that use it: against `--surface-1`, the effective contrast is approximately **3.88:1 in dark mode** and **2.93:1 in light mode**, below the 4.5:1 target for normal/small text. Increase final tertiary-label contrast rather than relying on the larger primary/secondary text tokens to carry accessibility.

Do not fix any of these by weakening behavior or hiding state.

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

## 12. Post-Claude GPT reconciliation procedure

When Claude returns its structural PR:

1. review changed paths and exact source head before touching CSS;
2. confirm real Today/Loads/Evaluate/Trips/Money routing, not label-only remapping;
3. run/inspect the full suite result from that exact structural head;
4. rebase a GPT presentation branch on the structural source;
5. patch only presentation selectors needed for the new DOM;
6. verify the widths and interaction states in sections 1–11;
7. run the repository full suite again on the integrated presentation PR;
8. do not certify production or physical iPhone until the same source candidate is deployed.

## 13. Final visual PASS definition

The visual pass is complete only when the app can be used one-handed on a current iPhone without feeling like a developer dashboard: the next decision is obvious, primary data is readable at a glance, forms do not fight the keyboard, navigation is predictable, and complexity is revealed only when needed.

Visual polish must never change freight truth. If presentation and canonical data disagree, canonical data wins and the UI is corrected.
