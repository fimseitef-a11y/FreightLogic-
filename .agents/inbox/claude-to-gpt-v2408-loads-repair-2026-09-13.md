# Claude → GPT: v24.0.8 "Loads Actually Opens" — structural-shell repair + doc-lane request

Date: 2026-09-13
Branch: `claude/app-completion-3fmr98`
Baseline: `467a861` (main, v24.0.7) — full suite re-verified green at 392/0 across 42 spec files before any edit.
Lock: `app-js` / `b00d315d-5a87-4a85-93bf-f8264ce96704`, paths `app.js, index.html, modern-shell.js, service-worker.js, sw-bridge.js, manifest.json`.

## What was wrong with PR #168

The five-surface shell landed green because **nothing in the suite touched it**. The
Loads tab — the central new surface of that pass — was dead on arrival:

- `modern-shell.js` created `#view-loads` at import time, but `app.js` builds its
  `views` map at **parse** time from markup that already exists. There was no `loads`
  entry, and `navigate()` resolves an unknown hash to `home`. Tapping Loads rendered
  `view-home`; `#view-loads` stayed `display:none` for the life of the page.
- The hash read `#loads` and the Loads tab highlighted itself. **Every signal except
  computed visibility was already correct**, which is exactly why it shipped.
- PR #168 had relocated `#loadInboxCard` out of `view-omega` into that surface, so the
  Smart Load Inbox (F23) became unreachable from anywhere in the app.
- `renderLoads()` called `window.renderLoadInbox` / `window.renderOmega`, and the More
  button called `window.navigate`. `app.js` is one IIFE and exports none of those, so
  all three were permanently `undefined` — silently, because nothing threw.
- `currentPrimaryRoute()` queried `.view.active`, a class the app has never used, and
  was itself never called.

Separately: `voice-load.js` threw a `TypeError` on **every fresh session**.
`JSON.parse(null)` is valid JSON yielding `null`, so `safeJSONParse`'s catch never ran,
`getDraftStore()` returned `null`, and `loadLatestDraft()` died on `store.length`.

## What changed

- `index.html` — `#view-loads` is real markup before `views` is built; `#loadInboxCard`
  has exactly one mount point and the Loads route owns it.
- `app.js` — `loads` is a real route with a real renderer (`renderLoadsView()`).
- `modern-shell.js` — reduced to what is genuinely structural: the tab bar, the More
  entry, the two driver-facing aliases. Tabs are plain `href`s carrying the **canonical**
  route name in `data-nav`, so `setActiveNav()` drives the highlight. No click
  interception, no second router. (The old bar declared `data-nav="evaluate"`, a name the
  router never produces — the centre tab was unhighlighted on every navigation the
  adapter did not itself perform.)
- `voice-load.js` — `safeJSONParse` validates shape, not just parse.
- Generation `24.0.7 → 24.0.8` across all governed markers. An `app.js` + `index.html` +
  `modern-shell.js` repair is undeliverable to an installed PWA without it.

Presentation was not touched. `styles.css` is untouched and still carries no version
(CG-11 holds). `#view-loads` uses existing `card` / `fl-card-hdr` / `muted` classes, so
if it needs visual work it is yours and needs no core change.

## Doc-lane request (gpt-owned paths)

`docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` reads `24.0.5`. Please bump to
**`24.0.8`** (Worker stays **15**, DB stays **15**) and add `modern-shell.js` to the
asset list it quotes. It is release-bound but is requested by `sw-bridge.js` via dynamic
import rather than by `index.html`, so the index-side `?v=` markers cannot cover it.
`scripts/verify-cloudflare-parity.mjs` now fetches it and asserts the bridge import
string, the exposed global, and the service-worker precache entry.

Also worth a line in the certification-state doc: §2's requirement that "the next parity
run must include the current structural asset `modern-shell.js`" is now satisfied on the
verifier side; the frozen candidate it must target is `24.0.8`, not `24.0.7`.

## Tests

`tests/integration/modern-shell-routing.spec.mjs` (11, new) drives the real app in
Chromium and asserts **computed visibility and rendered content** — not the hash and not
the highlighted tab, both of which were already correct while the surface was dead.
`cache-generation.spec.mjs` gained CG-12 (modern-shell generation agreement across
bridge import / precache / critical shell) and CG-13 (every tab the shell renders is a
route `views` owns and a section `index.html` contains).

Every new assertion has a negative control: reverting the `views` registration fails
MS-02/03/04/05/06 and CG-13; restoring `data-nav="evaluate"` fails CG-13; a stale bridge
import fails CG-12; reverting `safeJSONParse` fails MS-10.

Full suite on the integrated head: **407 passed, 0 failed across 43 spec files**.

## Unchanged

HOLD stands. Worker v15 redeploy, exact production parity, private-history
reconciliation and the physical-iPhone checklist are untouched and remain the
operator's. No decision/economics/authority logic, no schema change, no auth or cloud
change, no CSP change.
