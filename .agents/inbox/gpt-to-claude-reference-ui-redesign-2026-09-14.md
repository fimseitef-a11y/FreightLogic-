# Operator-directed FreightLogic reference UI redesign

**From:** GPT lane
**Date:** 2026-09-14
**Priority:** High
**Operator instruction:** "Handle it" after asking why the production app still does not match the previously approved iPhone reference design.

## Context
The operator supplied the approved visual target again. The current production app has the right data/features, but it still reads as the older dashboard/card system. This task is **not** permission to discard functionality or create a disconnected mockup. Preserve canonical routing, IndexedDB data, evaluator authority, trip/payment lifecycle, offline/PWA behavior, backup/security rules, and existing IDs/event bindings.

Current architecture already gives us the right primary surfaces: Today (`#home`), Loads (`#loads`), Evaluate (`#omega`), Trips (`#trips`), Money (`#money`), with More for secondary tools. `modern-shell.js` is structural only and should stay that way unless a minimal shell change is required.

## Approved visual target
Dark iPhone-first product UI with a compact black/charcoal shell, warm amber/yellow FreightLogic accent, white primary text, subdued gray secondary text, green positive states, and minimal borders. The target is significantly tighter and flatter than the current Command v3 presentation.

### Global shell
- Near-black page background; remove visible dot/grid texture from normal driver screens.
- Use a clean system/iOS-feeling type stack; avoid display-font styling that makes the app feel like a dashboard prototype.
- Compact fixed/sticky top area and bottom tab bar.
- Bottom nav: Today, Loads, **center circular amber lightning Evaluate action**, Trips, Money.
- Active tab uses amber icon/text. Inactive tabs are subdued gray.
- Cards: charcoal `#141414`–`#1b1b1b`, approximately 14–16 px corner radius, very subtle 1 px border, little/no glow.
- Remove strong gradients, excessive shadows, shimmer effects, dotted backgrounds, and oversized KPI typography.
- Touch targets remain >=44 px; retain accessibility/focus states.

### Today / Home
Reference hierarchy:
1. Brand row: `FreightLogic` in amber at top left, small green `Synced` state, profile/account affordance at right.
2. Greeting/context: `Good morning` + current market/city + concise weather/context line.
3. **Active Trip** card: lane, status, all miles, revenue, true RPM, delivery time/progress, primary `View Trip` button.
4. **Next Move** compact card: recommendation (e.g. Stay in Detroit), brief rationale, `View Market` link.
5. **This Week** compact summary: large weekly net (not giant), progress vs weekly goal, Gross / Expenses / True RPM row.
6. Alerts/recent trips may follow, but the first viewport should look like an operator command screen, not a bookkeeping dashboard.

### Loads
- Header `Loads` with search and filter icons.
- Segmented tabs: New / Saved / Won / Passed / Market.
- Each load card: freshness, lane, loaded miles, deadhead, all miles, grade badge, rate, all-mile RPM, pickup deadline/distance, `Pass` + amber `Evaluate` actions.
- Keep canonical load inbox/evaluation data; do not introduce a second state store.

### Load Detail
- Map/route visual at top when available.
- Lane and freshness.
- Large rate + green all-mile RPM + grade.
- Pickup/delivery facts.
- `Why this is a good load` / risk reasoning list.
- Bottom Pass / Evaluate actions.

### Evaluate
- Compact editable fields for rate, loaded miles, deadhead, lane.
- Prominent result card: grade, TAKE IT/PASS verdict, True RPM, est. net RPM, target bid range, concise reasons.
- `View Full Analysis`, `Save Load`, and amber `Add as Trip` actions.
- Canonical app.js verdict/economics/bid range remain authoritative.

### Trips
- Segmented tabs: Active / Completed / Unpaid.
- Active trip card uses vertical status timeline: Accepted → Arrived Pickup → In Transit → Delivered → Paid.
- Show delivery timing, miles, rate/RPM, Navigate and Mark Delivered actions.
- Completed cards are concise lane + date + revenue + RPM rows.

### Money
- Tabs: Overview / Expenses / Fuel / Receivables.
- Weekly net card with small bar/sparkline presentation, Gross / Expenses / True RPM.
- Money Owed card with overdue amount.
- Quick actions: Add Expense / Fuel / Receipt.
- Recent activity rows.

### Market Intel
- Current position + market strength.
- Ranked nearby markets with distance + strength.
- Compact recommendation card with time-based action and why bullets.
- `View Market Loads` action.

### Settings / Add Expense / Navigation
- Settings: grouped native-looking rows with chevrons; Vehicle, Operating Costs, Strategy, Notifications, Data & Backup, Appearance, Privacy, About.
- Add Expense: large amount field, icon-category grid, date, notes, amber Save Expense button.
- Navigation: dark map treatment, route, ETA/distance/highway summary, amber Start Navigation button.

## Implementation constraints
1. Preserve all current functionality and canonical routes. No disconnected prototype.
2. Prefer presentation-layer work in `styles.css`; only touch SHARED files when truly required and only with required locks/trailers.
3. Do not weaken CSP/security, cloud-secret handling, service-worker/offline behavior, or decision authority.
4. Do not alter tests merely to make the redesign pass.
5. If `app.js` must change, acquire `lock/app-js` and run the **full suite**.
6. Maintain 320/375/390/393/430/440 width support, safe-area insets, dark/light theme behavior unless the operator explicitly removes light mode.
7. Production target should look materially like the approved reference on first launch, especially the Today screen and bottom navigation.

## Acceptance gate
- Visual review at 390x844 and 430x932: first viewport matches the approved reference hierarchy and density.
- Bottom nav and all five primary routes still work through canonical hashes.
- No regression to evaluator verdicts, trip/payment state, backup, offline, or intake.
- Existing full test suite remains green wherever required by touched paths.

Please implement this as the next UI/product pass, not as another planning-only document.
