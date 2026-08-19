# FreightLogic adversarial-audit test suite

Real Playwright/Chromium tests against the live app — no mocks, no
reimplementation of app logic. Each spec launches a headless Chromium
instance with a fresh browser context (real IndexedDB, real Cache Storage,
real `crypto.subtle`) pointed at the app served from the repo root over
plain HTTP (`http-server`).

See `AUDIT_REPORT.md` at the repo root for the findings these tests prove.

## Setup (one-time per checkout)

Playwright is installed globally in this environment but the app has no
`package.json`/`node_modules` of its own, and Node's ESM resolver does not
honor `NODE_PATH`. Symlink it in:

```bash
mkdir -p node_modules
ln -sfn "$(npm root -g)/playwright" node_modules/playwright
```

(`node_modules/` is gitignored — this symlink is local-machine setup, not a
committed dependency.)

## Running

```bash
node tests/run-all.mjs                          # everything, aggregated
node tests/unit/pure-functions.spec.mjs          # one spec file at a time
node tests/integration/dz-exit-grade-cap.spec.mjs
```

Each spec file is independently runnable (`node tests/.../foo.spec.mjs`) and
exits non-zero if any of its own assertions fail. `run-all.mjs` always exits
0 — several specs are *expected* to fail one assertion each, because that
failure is the proof of a specific finding in `AUDIT_REPORT.md` (read the
assertion message, it names the finding and file:line). Look at the printed
"Failing" list at the end of a `run-all.mjs` run to see which findings are
still reproducing.

## Layout

- `lib/harness.mjs` — `launchApp()` boots the app in a fresh context and
  waits for real boot completion; `createSuite(label)` gives each spec file
  its own isolated `{test, run}` pair (so multiple specs can be imported
  into one process, as `run-all.mjs` does, without registry collisions).
- `unit/` — tests against pure functions exposed via `window.__FL_TESTS`
  (see `app.js:16021-16038`) — no DOM interaction, fast.
- `integration/` — drives the real UI (filling forms, clicking tiles,
  opening modals) and/or seeds IndexedDB directly through the same document
  shape `sanitizeTrip()` produces, then reads back what the app itself
  wrote to the DOM/sessionStorage/IndexedDB/exported Blob. Includes
  `field-resilience.spec.mjs` (Phase 4: storage quota, offline/reconnect,
  DST/clock-skew, GPS resilience).
- `e2e/` — full multi-step user journeys (Phase 5), driven purely through
  the real UI end to end, with tap counts and elapsed time reported per
  journey rather than isolated assertions.

## What this suite does NOT cover

See "What could NOT be tested, and why" in `AUDIT_REPORT.md`. Real iOS
Safari eviction, week-long cold start, and real device backgrounding are
device-only (see `FIELD_TEST_CHECKLIST.md`, not faked here). OCR-specific
flows are stubbed where Tesseract can't run headless (noted inline in the
`e2e/` spec that hits them). The live Cloudflare Worker (rate limiting, AI
endpoints, real invite-link token handling against production) is not
exercised — the multi-user isolation journey tests the client-side
namespacing/encryption logic locally instead of hitting production.
Visual/accessibility usability checks are measured, not automated as
pass/fail (Phase 6 — see AUDIT_REPORT.md).
