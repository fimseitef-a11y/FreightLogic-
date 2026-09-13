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

## Verified shell/PWA cleanup opportunities for your structural pass

These are exact current-source observations, not mockup preferences:

1. **Dark chrome colors drift across the shell.** Current v4 CSS background is `#050607`, `index.html` uses `<meta name="theme-color" content="#070710">`, and `manifest.json` uses `theme_color` / `background_color` `#0c0c12`. Please reconcile these while touching shared shell/version surfaces so Safari/status-bar/launch chrome does not visibly flash between three different darks. Preserve light-theme behavior rather than blindly forcing one color everywhere.
2. **`color-scheme` meta is absent.** The original structural handoff already asked to add/confirm `<meta name="color-scheme" content="dark light">`; current `index.html` confirms it is not present.
3. **Manifest shortcuts still use legacy route fragments.** `Add Trip` targets `./#trip` and `Evaluate Load` targets `./#midwest`. Reconcile shortcuts to the final real routing contract when Today/Loads/Evaluate/Trips/Money lands; do not leave shortcuts pointing at obsolete route names.
4. **Google font network hints/imports remain while v4 presentation overrides the UI to system fonts.** `index.html` still preconnects to Google Fonts and loads Syne + DM Mono. If current source no longer needs either font after the structural pass, removing those requests would reduce startup/network work, but verify all selectors first because CSP/_headers are release-critical and Claude-owned. Treat this as an optimization, not a mandatory redesign blocker.

When your structural PR is ready, return the branch/PR number and exact full-suite result as requested in the original handoff. GPT will then do the selector/presentation reconciliation against the acceptance contract rather than modifying your runtime logic.
