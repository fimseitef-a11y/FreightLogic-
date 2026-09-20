# Session handoff — 2026-09-20

Written so the next session resumes instead of re-deriving. This is a **lookup, not a
record**: re-read `APP_VERSION`, `git rev-parse origin/main`, `node scripts/m7-certify.mjs`
and `node scripts/lane-guard.mjs status` before acting on anything below. Every
fast-moving fact here is checkpoint context, not authority.

## State observed this session

- `main` @ `d8e0366`. Branch `claude/app-review-completion-w01r6h` carries one commit
  (`5fc491d`, documentation only) and is pushed.
- App **24.0.24** / DB **16** / Worker **v21**, deployed and observed — parity run
  `35434716935`, production service worker `35434719454`, both PASS on `f75f9cc`.
- **Full suite: 722 passed, 0 failed across 71 spec files**, first attempt, exact `d8e0366`,
  real headless Chromium. Nothing skipped, quarantined or weakened.
- `m7-certify`: 13/13 automated gates clean, resolving to
  `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-19.md`.
- Canonical state: **HOLD on exactly one gate — physical iPhone A1-A13**, deferred by the
  operator's 2026-09-16 decision to the final post-v24.5 candidate. Operator-only.

## Running the suite in a fresh container — READ THIS FIRST

A fresh remote container has **no Playwright**, and the preinstalled Chromium does **not**
match the version Playwright 1.62.1 expects. Both failures look like product defects and
are not. Do **not** run `npx playwright install` — the environment forbids it and it is
not what is wrong.

```bash
npm install -g playwright@1.62.1
mkdir -p node_modules
ln -sfn "$(npm root -g)/playwright" node_modules/playwright
ln -sfn "$(npm root -g)/playwright-core" node_modules/playwright-core
# the suite honours FL_CHROME_PATH at every launch site — use the preinstalled browser
FL_CHROME_PATH=/opt/pw-browsers/chromium-1194/chrome-linux/chrome node tests/run-all.mjs
```

Without `FL_CHROME_PATH` the run dies with *"Executable doesn't exist at
.../chromium_headless_shell-1234/..."*. `node_modules/` is gitignored. The chromium build
number (`1194`) is environment-specific — check `ls /opt/pw-browsers` rather than pasting it.

## What this session changed

Documentation only. No runtime file, so no version marker moved. Three governance
instruments each carried a superseded claim:

- **CLAUDE.md** — Project Overview was two generations stale (read 24.0.23 source /
  24.0.22 production, and called v24.0.23 "source-only"); the three governed version
  locations (checklist item 10) still read 24.0.23; the certification authority named the
  2026-09-18 document; and there was no v24.0.24 release section at all. All corrected,
  superseded wording kept as history per this repo's convention.
- **AUDIT_REPORT.md** — S-4 still headed *"issue #224 remains OPEN"*. #224 closed
  2026-09-18 (PR #242 → `7252d29`). Corrected with the root cause and its measurement.
- **FIELD_TEST_CHECKLIST.md** — contradicted itself (line 7 said 24.0.24/v21, line 17 said
  24.0.19/v20); its A13 "runner does not carry this row yet" note had been fulfilled by the
  GPT lane; its release-hold paragraph named two blockers and the 2026-09-15 document when
  the current authority names exactly one.

## The next real work: Issue #278 — BLOCKED, and correctly so

**Do not start this by reaping a lock.** `.agents/locks/ia-redesign-v24025.lock` (owner
`gpt`, token `7b5b6628-8d66-4f4f-a012-a23bbf4a22a1`) covers `app.js`, `index.html`,
`modern-shell.js`, `service-worker.js`, `sw-bridge.js`, `manifest.json`. It is past
`expected_release_utc` so `lane-guard status` reports **STALE** — but the `.agents/NOW.md`
row shows GPT **actively** working that task, and **PR #277 is open** against those exact
paths. Issue #278 itself says to implement *"in the next safe runtime/economics lane after
the current `app.js` lock is released"* and *"Do not mix this economics change into #277."*

Stale means it grants GPT nothing either; it does **not** mean free to take. Reaping is a
deliberate act per `AGENTS.md` (delete the file, commit, push, log the token and reason in
`STATUS.md`) and it was **not** taken this session. Wait for #277 to land, or ask the
operator.

### When it unblocks — what the audit already established

Verified against current source, so the next session need not re-derive it:

- `MW.mpg = 17.5` (`app.js:9387`) → operator authority is now **16.7**.
  `MW.fuelBaseline = 3.55` (`app.js:9388`) → **$3.79/gal**, and must stay overrideable and
  provenance-dated rather than treated as permanently current.
- `deriveUnifiedEconomics()` (`app.js:9869`) already keeps `opCPM` and fuel **separate**, so
  the double-count the issue warns about is avoidable — but `opCostPerMile` is currently
  derived from *monthly fixed costs / monthly miles* (`app.js:14269`), i.e. **fixed only**.
  The **non-fuel variable** band (oil 0.021 + tires 0.010 + repair reserve 0.035 ≈
  **0.066/mi**) is not represented anywhere, so the app currently **understates cost by
  ~$0.066/mi**. Do not write `0.405` into `opCostPerMile` — that re-adds fuel.
- The issue wants the ladder **additive**: *"distinct from any retained letter-grade
  taxonomy unless an intentional tested migration replaces it."* Add the economic band
  alongside `deriveUnifiedGrade()` (`app.js:9826`) rather than replacing it — that keeps the
  v24.0.0 authority-boundary regressions (1.39 rejects / 1.40 survives, and the rest) intact.
- **`M1-17` will fail and must be updated deliberately.**
  `tests/integration/m1-doctrine-integrity.spec.mjs:232` asserts `MW.mpg === 17.5` as "the
  approved ~17.5 Gate 0 baseline". That is a superseded operator baseline, not a defect —
  update it to 16.7 with the reason recorded, exactly as this repo documents other
  intentional assertion changes. It is the one place a newer operator decision collides with
  an older one encoded as a test. Do **not** weaken it silently.
- Weekend overlay must stay **contextual, never an automatic hard reject**; a strategic
  weekend bridge below the weekday target must remain possible.
- Preserve: unknown deadhead is never zero; loaded / deadhead / platform-displayed /
  reposition miles stay four distinct numbers.

`app.js` is SHARED — the work needs `lock/app-js`, a full suite, and release-generation
markers, since changing `app.js` bytes under a reused generation is refused by
`scripts/verify-release-generation.mjs` (RG-03).

## Everything else open is not ours to close

- **#222** repository branch protection / secret scanning — repository-admin controls, not
  writable through the connector. CodeQL is already present and green. Operator action.
- **#252** screenshot OCR — the pipeline shipped in v24.0.21 and the benchmark harness
  exists (`scripts/benchmark-vision-providers.mjs`, `scripts/lib/vision-bench.mjs`,
  `tests/unit/vision-benchmark.spec.mjs`, registered in `run-all.mjs`). What remains is
  running it against the **sanitized DispatchLand corpus**, which is operator data and
  deliberately not in this repository, plus A13 on a real device.
- **#231** Admin Console, **#226** field-certification runner — GPT-owned paths.
- **#205**, **#204** — master/roadmap trackers.
- **Physical iPhone A1-A13** — operator-only, and deferred by decision to the final
  post-v24.5 candidate. A partial A-section against a superseded generation is not evidence.
