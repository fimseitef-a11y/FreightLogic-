# FreightLogic Final Visual Completion Plan

**Date:** 2026-10-02
**Base:** `2907991fa82825e920497e3659ca4086528282ad`
**Spec authority:** `UI_BRIEF_V24.5.md`, `docs/MODERN_UI_VISUAL_ACCEPTANCE_2026-09-13.md`, and the already-landed Issue #417 product-IA slices.
**Objective:** finish every remaining software-side visual/product upgrade that is required before physical iPhone A1–A14 certification, without changing canonical freight economics, lifecycle semantics, storage schema, or UNKNOWN handling.

## Global constraints

- Keep `app.js` untouched unless a failing contract proves a behavior gap cannot be solved in the extracted presentation/shell seams.
- No Voice Load restoration, new map subsystem, new cloud/account architecture, or fabricated market/weather/economics data.
- Preserve all existing deep links and canonical routes.
- `styles.css` remains versionless by design; release generation is advanced only through governed runtime/version files.
- All shared runtime paths are covered by live lock `final-visual-completion.lock` token `8b7e2d4f-5f42-4ee8-9f1f-2d4ca6b90751`.

## Task 1 — RED: final visual acceptance contracts

**Files:**
- `tests/integration/final-visual-completion.spec.mjs` (new)
- `tests/run-all.mjs`

Add failing contracts for:
1. primary labels `Today / Loads / Evaluate / Trips / Money` while preserving canonical hashes;
2. screen titles `Evaluate Load` and `Trips`;
3. no Google-hosted font/runtime dependency in `index.html`;
4. approved dark command palette and flat native presentation tokens;
5. no decorative body grid, hero text gradient, primary-button gradient, or progress shimmer in the final presentation;
6. 48px practical mobile primary targets and emphasized center Evaluate control at 390 CSS px.

Open a draft PR on the RED commit and observe `playwright-suite` fail specifically on these new contracts before production changes.

## Task 2 — GREEN: shell terminology and offline-native typography

**Files:**
- `modern-shell.js`
- `index.html`

Implement only presentation/shell changes:
- `Scan` → `Evaluate` and `History` → `Trips` in primary navigation;
- screen-title map uses `Evaluate Load` and `Trips`;
- retain `scan`/`evaluate` aliases and canonical `#omega`/`#trips` routes;
- remove Google Fonts preconnect/stylesheet links so the already-declared system stack is the only UI font dependency.

Run the focused final-visual spec through CI and confirm these contracts turn green.

## Task 3 — GREEN: complete approved Command visual language

**File:** `styles.css`

Bring the existing presentation seam to the approved repository-native reference without changing DOM data ownership:
- near-black `#050607` background;
- graphite card surfaces `#11171a` / `#151c1f`;
- restrained edge `#2a3134`;
- warm FreightLogic gold `#f3b43f`;
- positive `#52c77a`, destructive `#ff625c`;
- warm off-white primary text `#f5f4ef` and muted `#9ca5a8`;
- card radius ~15px, flat restrained shadows;
- remove decorative grid/gradients/shimmer from normal task UI;
- strengthen route/economics hierarchy, load decision cards, settings rows, and Money/History surfaces using existing selectors only;
- bottom nav mirrors the approved five-surface iPhone hierarchy with an obvious 48px center Evaluate action;
- inputs remain >=16px on iPhone and coarse-pointer actions remain >=44px, targeting 48px where practical;
- preserve light theme, forced-colors, reduced-motion, Driver/Glance and safe-area behavior.

Run final-visual, six-width, modern-shell, Today IA, product-IA A–D, driver-glance and iPhone-manual regressions, then the full suite.

## Task 4 — governed release generation

Advance the source candidate from v24.0.57 to the next repository-valid generation (expected v24.0.58) using the existing release-generation contract. Update only the synchronized version-bearing files required by current tests/tooling. Do not put a version marker in `styles.css`.

Run cache-generation, release-generation-discipline, service-worker, update-handshake, deploy-asset and full-suite gates.

## Task 5 — review, integrate, deploy/parity

- Review the entire branch against the approved brief and reference; no weakening of assertions.
- Require protected PR checks: `playwright-suite`, `path-ownership`, `commit-prefix`, `lock-trailer`, `Analyze JavaScript`.
- Merge only after the exact PR head is green.
- Verify post-merge main and production Live Parity / Production Service Worker gates for the new generation.
- Release the live coordination lock and record exact SHA/version/evidence in Airtable.
- Leave GitHub #226 open until the operator performs physical iPhone A1–A14; that is the only intended remaining gate.

## Review focus

- No canonical grade/RPM/bid arithmetic in presentation code.
- UNKNOWN deadhead never becomes zero.
- Existing deep links remain valid.
- No feature becomes unreachable through the five-surface + More hierarchy.
- No external font/network dependency is added.
- iPhone safe areas, anti-zoom, reduced motion and touch geometry do not regress.
