# FreightLogic Today Command Center v2 Implementation Plan

**Date:** 2026-09-30
**Task:** FL-TODAY-V2-20260930-01
**Base:** f4df9d6f9f7ae72456dc7cef90f6c9beeb1b402a
**Spec authority:** `docs/PRODUCT_UX_IA_GAP_AUDIT_V1_2026-09-28.md`, current Today integration contracts, and the operator's 2026-09-30 iPhone screenshots/feedback.

## Objective

Turn Today into a calm stateful command center without changing canonical freight economics, lifecycle semantics, UNKNOWN handling, local-first storage, or the remaining physical certification gate.

## Global constraints

- Preserve the canonical workflow: Today → Loads → load decision → Current Load → History/Money.
- Today has one dominant stateful action. Idle favors Review/Scan Loads; active execution favors Current Load/Start Trip as applicable.
- Preserve existing IDs and app handlers wherever practical; implement presentation/route repair at the shell layer.
- Never let transient UI cover the header More/settings control.
- Keep the user's preferred Today financial card prominent; remove or subordinate duplicate money summaries.
- Long market/positioning evidence is progressive disclosure, not primary content.
- Maintenance, fuel staleness, CPA export, and other secondary reminders live in an Attention tier below the daily command/money tier and remain in normal document flow.
- Fuel Update must route to Settings and focus the canonical fuel-price field.
- Do not reopen or repeat issue #380. Do not claim #226 passes.
- Obey SHARED-path locks. The pre-existing `pushward-live-test-ui.lock` covers `app.js`, `index.html`, and `tests/`; this plan does not touch those paths unless that lock is legitimately released/reaped later.

## Task 1 — Establish an executable RED contract outside the blocked test lane

**Files:**
- Create: `scripts/test-today-command-center-v2.mjs`

Write a Node contract test that loads `modern-shell.js` in a minimal VM/DOM harness and asserts the new shell surface is absent at base: exported/observable Today presentation installer, header protection, fuel Update route-to-field behavior, and idempotent home presentation hook. Run it against base and record the expected failure.

**Expected:** non-zero exit for missing Today-v2 behavior.

## Task 2 — Claim the smallest SHARED seam and implement Today-v2 shell behavior

**Files:**
- Modify: `modern-shell.js`
- Modify: `styles.css`

Before touching `modern-shell.js`, claim a verified same-task lock for that path only on `agent-coordination`. Add an idempotent Today presentation adapter that:

1. applies a stable `today-command-v2` class to Today,
2. protects the More/settings action plane,
3. routes `#fuelNudgeCard` to `#view-settings` and focuses/scrolls `#currentFuelPrice`,
4. keeps CPA/export reminders in normal flow,
5. promotes the Today KPI/money card ahead of secondary positioning/maintenance content,
6. visually compacts position/UNKNOWN/maintenance/secondary alerts without altering their underlying semantics or handlers,
7. subordinates duplicate `#homeMoneyCard` content while leaving Money as canonical,
8. preserves bottom navigation and existing deep links,
9. re-applies safely after app-driven DOM updates without duplicate handlers/wrappers.

Run the contract test until GREEN.

**Expected:** zero exit; all Today-v2 contract assertions pass.

## Task 3 — Canonical regression coverage when the existing lock permits

If and only if the old `tests/` lock is legitimately gone or otherwise releasable under protocol, add focused Playwright regressions to `tests/integration/today-ia.spec.mjs` for:

- More/settings remains reachable while transient notifications are present,
- fuel Update lands on/focuses the fuel field,
- CPA reminder does not overlay Recent Trips,
- Today money remains primary and duplicate money is subordinate,
- UNKNOWN retains semantics but long evidence is not primary,
- no regression to one-dominant-action IA.

Observe RED before the corresponding production fix when feasible; if Task 2 has already established the behavior under a standalone RED/GREEN contract, add the canonical browser test and verify GREEN without manufacturing a false RED.

## Task 4 — Full branch verification and review

Run/fetch fresh evidence for the required repository checks at exact PR head, including the full Tests suite (required because `modern-shell.js` is SHARED and the changes interact with Today), Lanes, and CodeQL. Review the complete branch diff against this plan and the product spec. Fix any Critical/Important issue with a focused regression and rerun the full checks.

**Expected:** all required checks green at exact head; no Critical/Important review findings.

## Task 5 — Integrate and verify production

Merge only after required checks are green and repository governance permits it. Verify exact main SHA, production live parity, production service worker/version, and any applicable deploy workflow. Update Airtable Task Control and FreightLogic Engineering Coordination with provenance, evidence, and the remaining gate.

**Expected:** production matches merged main; the only remaining operator/manual completion item is issue #226 real-iPhone A1–A14 certification.

## Review focus

- iPhone safe-area/header collision under transient UI.
- Dynamic re-render idempotency and duplicate click-handler risk.
- Accessibility/keyboard behavior on relocated/compacted controls.
- No semantic change to UNKNOWN or freight economics.
- No hiding of genuinely urgent maintenance information; only hierarchy changes.
- No misleading current-week vs historical-report presentation.
- Light/dark/responsive behavior at existing supported widths.
