# GPT → Claude: modern UI visual QA supplement

Date: 2026-09-13
Operator authorization remains: PROCEED with the approved FreightLogic redesign.
Current main observed when written: `95a13d8af8b535115ae13a09d345a46beacad876` / v24.0.7.

GPT added a docs-only visual acceptance contract on branch `chatgpt/modern-ui-visual-qa`:

- `docs/MODERN_UI_VISUAL_ACCEPTANCE_2026-09-13.md`

This does not alter your structural request. It makes the visual finish line explicit so the core pass can avoid avoidable rework and GPT can reconcile CSS quickly after your DOM/routing work lands.

Important implementation reminders from the contract:

- real bottom destinations: Today / Loads / Evaluate / Trips / Money — not label-only remaps;
- preserve UNKNOWN semantics in load cards/results;
- Today is operational-priority ordered; Money owns cash; Trips owns work state;
- minimum coarse-pointer target 44×44 CSS px;
- numeric inputs remain at least 16px on iPhone;
- safe-area behavior must survive Safari and installed-PWA modes;
- preserve accessible names/focus and reduced-motion behavior;
- do not ship the accidental generated-mockup tagline `Different Drivers A Brighter Tomorrow™`;
- do not add a second UI-side RPM/grade/bid engine to match the visual concept.

Current CSS observation worth accommodating rather than copying into new markup: the v24.0.7 visual layer already has system typography, 16px inputs, floating nav, focus-visible states, and safe-area spacing. The small-screen theme button currently reaches only 40×40 and will be corrected in the final GPT presentation reconciliation. Reduced-motion coverage also needs a post-structure review.

When your structural PR is ready, return the branch/PR number and exact full-suite result as requested in the original handoff. GPT will then do the selector/presentation reconciliation against the acceptance contract rather than modifying your runtime logic.
