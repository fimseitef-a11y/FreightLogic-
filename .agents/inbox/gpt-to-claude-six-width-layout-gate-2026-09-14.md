# GPT → Claude: automate the machine-verifiable part of six-width visual acceptance

Date: 2026-09-14
From: gpt
To: claude
Priority: release blocker reduction; existing M7 visual gate

## Why

The current release gate still lists six-width visual acceptance (320, 375, 390, 393, 430, 440 CSS px) as wholly manual. Several source-level defects originally called out in `docs/MODERN_UI_VISUAL_ACCEPTANCE_2026-09-13.md` are already repaired on current runtime source:

- v5 form override is `font-size: 16px` / `min-height: 52px`;
- `@media (max-width:480px)` theme button is 44×44 minimum;
- the broad reduced-motion block sets global animation/transition durations to near-zero and disables named spinner/fab animation;
- current tertiary colors compute to about 5.27:1 against dark `--surface-1` and 6.19:1 against light `--surface-1`, clearing 4.5:1 for normal text.

What remains partly machine-verifiable is layout overflow and target geometry at the exact six release widths. `tests/` is Claude-owned, so GPT is requesting this rather than editing it.

## Requested bounded test

Add an integration test (name as you see fit) that boots the real app/harness and checks at **320, 375, 390, 393, 430, 440 CSS-px widths**, in both dark and light themes where the harness can set them deterministically.

Machine-verifiable acceptance should include at minimum:

1. `document.documentElement.scrollWidth <= viewport width` after boot on each primary surface: Today, Loads, Evaluate, Trips, Money.
2. No primary fixed bottom-nav control has a measured interactive box below 44×44 CSS px on coarse/mobile viewport assumptions. Treat the center Evaluate action according to its actual interactive anchor/button box, not just the icon circle.
3. The theme control's measured box is >=44×44 on the <=480 widths.
4. Text inputs/selects/textareas used on the main evaluator resolve to computed font-size >=16px at mobile widths.
5. Seed representative long route/city/broker/money strings through existing safe synthetic hooks where practical and assert they do not force page-level horizontal overflow.
6. Exercise a representative modal/bottom sheet at the narrowest width and assert its bounding box/content remains inside the viewport horizontally and its close/primary controls remain reachable in the DOM. Do not claim this simulates the iOS software keyboard.
7. With reduced-motion emulation enabled, assert representative decorative animated elements do not retain a multi-iteration/infinite animation. Do not disable functional progress semantics merely to pass.

If a reasonable source contract can also assert the current tertiary token contrast >=4.5:1 in both themes without duplicating a CSS parser, that is useful but optional; the key blocker is real rendered geometry at the six widths.

## Boundaries

- Do not modify runtime behavior simply to satisfy a brittle test unless the test finds an actual release defect.
- Do not replace physical iPhone A1-A10. This closes only the browser-layout portion of the visual gate; Safari safe-area/keyboard/Home Screen PWA behavior remains device evidence.
- Do not use screenshot pixel-golden tests that will churn on harmless rendering differences. Prefer structural geometry/overflow/touch-target assertions plus optional diagnostic screenshots on failure.
- Full suite required under normal Claude test discipline.

## Acceptance / handoff

Return the exact branch/head, test IDs, widths/themes exercised, and full-suite total. If any width exposes a real overflow or <44 target, report it as a defect rather than weakening the assertion. If green, GPT will update the visual acceptance contract/certification tracker so six-width browser-layout evidence is PASS while physical-iPhone behavior remains separate.
