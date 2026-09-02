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
exits non-zero if any of its own assertions fail.

### Exit code (X-06, v23.9 Phase 2)

`run-all.mjs` exits **non-zero if any assertion in any spec fails**
(`process.exit(totalFail ? 1 : 0)`), and CI (`.github/workflows/tests.yml`)
blocks merge to `main` on that exit code. This is a change from pre-v23.9
behavior, worth calling out explicitly: an earlier version of this file
always exited 0, on the reasoning that several specs were *expected* to fail
one assertion each — each failure was the reproduction of a specific
still-open finding in `AUDIT_REPORT.md`, and a passing exit code just meant
"the suite ran," not "nothing is broken." That reasoning doesn't hold once a
finding is actually fixed and its test is rewritten to assert correct
behavior (this suite's own convention — see "Note on the retagged tests" at
the bottom of `AUDIT_REPORT.md`): at that point a red assertion is a real
regression, not expected evidence, and a runner that still exits 0
unconditionally can't be used as a merge gate. Every finding this suite
currently covers is FIXED, so there is no longer a legitimate reason for any
spec here to fail — the exit code is real CI signal now, not just a summary.

If a future finding is logged-but-not-yet-fixed (this suite's established
pattern for a bug discovered mid-testing, e.g. F-7/F-8 originally), its test
should either be excluded from `run-all.mjs`'s default run or clearly
isolated so it doesn't sink an otherwise-green CI gate — do not go back to
an unconditional `exit(0)` to work around that; that reopens X-06.

Look at the printed "Failing" list at the end of a `run-all.mjs` run to see
exactly which assertions are red (each names the finding and file:line it
proves).

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
  wrote to the DOM/sessionStorage/IndexedDB/exported Blob.

## Fixture dates must be relative when the assertion depends on age

A spec that hardcodes a calendar date in a fact whose *meaning* changes with
time is a scheduled red build. It passes the day it is written and fails later
against source that never moved.

This is not hypothetical. `[M4-23]`/`[M4-24]` asserted `INVOICED` against a
hardcoded `2026-08-03` invoice date; `_lifecycleStateFromTrip()` derives
settlement against the standard 30-day term, so on 2026-09-02 the same
unchanged code correctly returned `OVERDUE` and turned `main` red.
`[M3R-06]` carried the same fuse with two days left on it — a `laneHistory`
`lastDate` of `2026-08-20` under a HIGH-confidence assertion that requires the
row to sit inside the CURRENT (<=14d) freshness window.

So: derive the date from `Date.now()` whenever the assertion depends on how old
the value is. Inside a `page.evaluate()` body, the idiom the specs use is

```js
const iso = (n) => new Date(Date.now() - n*86400000).toISOString().slice(0,10);
```

The runtime behaviours that make a date time-sensitive today:

- **settlement terms** — `INVOICED` becomes `OVERDUE` after `termsDays` (30);
- **evidence freshness** — CURRENT <=14d, AGING 15-30d, STALE >30d, which
  feeds domain and overall confidence;
- **calibration recency** — observation age drives weight, and unknown age is
  deliberately not weighted as fresh.

Absolute dates stay correct — and are preferable — where the fact is genuinely
fixed in time: IRS mileage-band boundaries, DST transitions, and assertions
about timestamp *precision* surviving a round trip (`batch-a`, `blockers`),
where the point is that the exact instant is preserved unchanged.

## What this suite does NOT cover

See "What could NOT be tested, and why" in `AUDIT_REPORT.md` — field
resilience (quota exhaustion, mid-write kill, iOS Safari eviction, GPS
fault conditions), full timed E2E journeys, OCR-specific flows, the live
Cloudflare Worker (rate limiting, AI endpoints, invite-link token handling),
and visual/accessibility usability checks are all out of scope for this
pass and were not executed.
