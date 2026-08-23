# FreightLogic UI seam proposal — CSS-first extraction

Status: PROPOSED + user standing authorization to execute once clean-CI baseline is green.

## Why this seam

The smallest genuinely behavior-preserving presentation seam is the existing inline design system in `index.html`, not a forced split of the 950KB `app.js` IIFE.

`app.js` currently keeps its functional/UI functions inside one closure with extensive shared globals. Extracting JS rendering functions now would require new global/module boundaries and therefore would not be a pure structural move. By contrast, the complete `<style>...</style>` block in `index.html` is already a physical presentation unit with browser-native dependency semantics.

This first seam creates a real GPT-owned presentation path without changing decision/storage/security logic and without inventing a risky JS module architecture.

## Exact source region

Current `index.html`:

- the single top-level `<style>` block in `<head>` beginning with `FREIGHT LOGIC v24.0.0 — DESIGN SYSTEM v3.0 "Command"`;
- move the entire contents of that block byte-for-byte, preserving rule order, whitespace, media queries, keyframes, selectors, and comments;
- do not move HTML markup, inline `style=` attributes, scripts, CSP, fonts, or any JS in this extraction.

## Destination

New file at repository root:

`styles.css`

No build step, preprocessor, bundler, CSS modules, minification, rename pass, or reformatting.

## `index.html` change

Replace only the moved `<style>...</style>` element with:

`<link rel="stylesheet" href="styles.css">`

Place it at the same position in `<head>` after the existing Google Fonts stylesheet so cascade/load ordering stays equivalent.

Do not change CSP. Existing inline `style=` attributes remain, so `style-src 'unsafe-inline'` is still required; removing it is separate security scope.

## Service-worker change

`service-worker.js` must explicitly precache `./styles.css`:

- add `./styles.css` to `CORE`;
- add `./styles.css` to the install-blocking `critical` list because the app shell without its primary stylesheet is not an acceptable first offline install.

No fetch-strategy rewrite is required. The current generic fetch fallback already checks `cache.match(req)` after network failure, and install precache guarantees the CSS is present. Do not opportunistically add `.css` to `isStatic` in this structural extraction because that would change online caching semantics.

No SW/app version bump is required for the structural extraction commit itself: changing the service-worker script bytes triggers browser SW update, and `styles.css` is unversioned/explicitly precached. A normal release bump can happen at the later feature/release gate.

## `app.js` impact

None. Do not edit `app.js` in this extraction.

This is intentional: it creates a safe physical styling lane without manufacturing a risky JS dependency seam. Functional UI rendering remains serialized/core-owned until a later clean JS seam is justified by source structure.

## Dependency/order constraints

- Google Fonts `<link>` remains before FreightLogic styles.
- FreightLogic CSS remains before body markup.
- Existing CSS rule order is byte-preserved.
- No selector/class/ID changes.
- No JS load-order changes.
- No CSP/header changes.

## Expected diff shape

Exactly:

1. `styles.css` — new file containing the former inline style-block contents, byte-preserved.
2. `index.html` — one large deletion (the inline style block) plus one stylesheet link insertion.
3. `service-worker.js` — two small asset-list additions for `./styles.css`.

No other runtime file should change in the extraction PR.

## Verification

Before extraction:

- clean temporary bank-repair CI residue;
- exact-current-main full suite green/logged.

After extraction:

- full `node tests/run-all.mjs` gate;
- source check that `index.html` has exactly one `styles.css` link and no former design-system `<style>` block;
- source check that `styles.css` contains the moved opening design-system comment and representative terminal rules;
- service-worker shell check that `./styles.css` is in both `CORE` and `critical`;
- integrated PR full gate green;
- fresh main gate green after merge.

Do not weaken existing tests to make extraction pass.

## Rollback

Single mechanical reversal:

1. put `styles.css` contents back inside the original `<style>` position in `index.html`;
2. remove the stylesheet link;
3. remove `./styles.css` from `CORE` and `critical`;
4. delete `styles.css`.

No data migration or persistent state is involved.

## Lane update after green merge

After the extraction is merged and fresh main is green, update durable ownership:

- `styles.css` → `gpt` (presentation/design system);
- `index.html` remains `SHARED` because it owns shell/CSP/load order;
- `service-worker.js` remains `SHARED`/release-critical;
- `app.js` remains `SHARED`/serialized or Claude core-owned per the existing protocol; no claim that JS UI has been separated.

This gives GPT a real, low-risk visual lane for v24.1 presentation polish and the later v24.5 visual overhaul while core behavior remains protected.
