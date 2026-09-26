# GPT → Claude: modern UI structural pass

Date: 2026-09-13
Operator authorization: **PROCEED** — user explicitly approved the full modern FreightLogic redesign and subsequently instructed GPT to handle everything possible in one sweep.
Current main baseline after the GPT sweep: `03c97b64af354fa83fcb15881b320bfdfbf1e20a` / app v24.0.7.
GPT presentation PR **#164 is MERGED**. Squash commit: `666e3044fe60f34f2e2e1807c396f639cd1077d5`.
Claude deploy-path repair PR **#163 is also MERGED**. Squash commit: `03c97b64af354fa83fcb15881b320bfdfbf1e20a`.

## What is already on main

PR #164 was intentionally presentation-only and touched **only `styles.css`**. It added the native visual layer: system typography, calmer surface ramp, updated FreightLogic amber, flatter hierarchy, tabular numerals, modern controls/cards, cleaner evaluator styling, and floating bottom-navigation treatment. Lane guard and the full Playwright suite were green before merge.

Do **not** recreate that CSS work in core. Start the structural pass from current `main`, where the CSS is already integrated, and leave presentation conflicts in `styles.css` to GPT.

PR #163 removed the stale Worker-v14 literals that blocked Worker-v15 deployment preflight. That source/deploy-path defect is closed on main; do not reimplement it.

## Structural source work requested from Claude lane

The operator approved the target experience below. These items require Claude-owned/shared source paths (`app.js`, `index.html`, service worker/version surfaces as applicable), so GPT is reporting them rather than patching core.

### 1. Final primary navigation

Target bottom tabs, left → right:

1. **Today**
2. **Loads**
3. **Evaluate** (center action)
4. **Trips**
5. **Money**

Current routes are Home / Trips / Omega / Intel / More. Do not fake the target by merely renaming unrelated destinations. Build real routing/view ownership so each tab opens the intended content.

Settings/admin/support tools should move behind a top-right Settings entry or an in-app Settings surface reachable outside the five primary tabs. Market/Intel remains accessible contextually from Loads/Today and may retain a secondary route if useful.

### 2. Dedicated Loads surface

The existing Smart Load Inbox currently lives in the Omega/Evaluate area through `renderLoadInbox()` and `#loadInboxCard`.

Create a real **Loads** view without duplicating load state or introducing a second evaluation engine. Reuse the canonical inbox/data pipeline.

Desired information architecture:
- newest actionable loads first;
- load card shows route, age, loaded miles, deadhead, all miles, rate, True RPM, grade, pickup timing, weight when known;
- one obvious tap target to open/detail/evaluate;
- filters only for states that actually exist in source (do not invent persistence semantics just to match a mockup);
- market/repositioning context available as a secondary Loads/Market path if existing data supports it.

### 3. Today order = operational priority

Reorder Home/Today around what the driver should do next:

1. Active trip/tracking if present (`#homeTripTrackCard` and related current hooks).
2. Next Move / positioning (`#homePositioningCard`, `#homeNextMoveBox`, current canonical positioning output).
3. This Week (`#homeKPICard`) — keep one canonical financial definition; do not create parallel computed values.
4. Alerts/actions that require attention.
5. Recent trips — compact, maximum useful rows before See All.

Keep existing stable IDs wherever possible. Do not break selector/runtime references for cosmetic restructuring.

### 4. Evaluate = answer first, advanced details second

Keep the canonical decision engine and existing evaluator inputs (`#mwRevenue`, `#mwLoadedMi`, `#mwDeadMi`). Default screen should lead with the required inputs and then the verdict. Advanced fields stay under progressive disclosure.

Do not create a second grade/RPM calculation in UI code. True RPM remains canonical all-mile logic.

Target result hierarchy:
- grade + decision;
- True RPM;
- target bid/range when canonical engine provides it;
- **Why this grade** evidence, including risks/counter-evidence where available;
- deeper economics below.

### 5. Trips owns state of work

Trips should emphasize active/completed/unpaid lifecycle/work state without becoming a second financial dashboard. Preserve existing trip source and IDs/data contracts. If lifecycle states required by the desired UI are not implemented, expose only real states and do not fabricate them.

### 6. Money owns state of cash

Consolidate the user-facing financial navigation so Money is the obvious home for:
- overview/net/gross/expenses/True RPM as already canonically defined;
- Expenses;
- Fuel;
- Receivables / Money Owed.

This may reuse existing `view-money`, `view-expenses`, `view-fuel`, and Insights data rather than rewriting calculations. Goal is information architecture, not a new accounting engine.

Anything that appears on both Today and Money must come from the same canonical value/function.

### 7. Settings leaves Insights

Vehicle/cost/strategy/notification/data-backup/appearance/privacy/about configuration currently buried in Insights/More should become a coherent Settings surface. Preserve control IDs and handlers where practical; this is a shell/layout move, not a settings-model rewrite.

### 8. Shell/PWA details

- Add/confirm `<meta name="color-scheme" content="dark light">` if not already present.
- Preserve `viewport-fit=cover` and safe-area behavior.
- No new CDN/framework/build dependency.
- Keep offline-first behavior.
- If shared shell/service-worker/version surfaces change, bump forward from **v24.0.7**, never regress to stale generation instructions.
- Version/cache parity must remain exact across current canonical locations.

### 9. Non-goals / safety

- No rewrite of freight decision logic.
- No IndexedDB/schema migration for visual work.
- No auth/cloud/security changes bundled into this pass.
- No ID renames for aesthetics.
- No duplicate state stores.
- No fake load/market/lifecycle data just to resemble a mockup.
- No CSS recreation in core; GPT owns `styles.css`.

## Acceptance gate for Claude structural pass

Before handoff back to GPT:

1. Use required shared-path lock(s), including `lock/app-js` for `app.js`.
2. Full `node tests/run-all.mjs` on the exact integrated source head; no selective substitute.
3. Report exact changed paths and exact test count/result.
4. Verify all existing route/view IDs and handlers that moved still function.
5. Verify version parity if any release surface changed.
6. Return the branch/PR number in an inbox note so GPT can review the integrated presentation against merged PR #164 and make CSS-only follow-up adjustments.

## Design intent

FreightLogic should feel like a current native driver/fintech app rather than a web dashboard: fewer simultaneous boxes, stronger typography hierarchy, one primary action per screen, progressive disclosure, thumb-reachable navigation, and the decision/recommendation visible before implementation detail.

The user has already approved this direction. Do not stop for redundant product approval; stop only for a real safety/architecture conflict that requires operator choice.
