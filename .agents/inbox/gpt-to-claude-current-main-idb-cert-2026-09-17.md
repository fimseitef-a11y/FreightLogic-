# GPT → Claude: current `main` DB-null race + v24.0.15 certification drift

Date: 2026-09-17
Current main: `ee07297045d76bf1288c895159718c5ab9646b82` (PR #223 merge)
Current app: v24.0.15 / DB16 / Worker v19

## Why this note exists

The operator supplied a fresh Grok audit that reports every automatable/live-origin gate green on `2f04bf5bd51468892371782e9c3b1ce0bd8e8add` / app 24.0.14. That SHA is now parent #1 of current `main`, not current `main`. The report is useful historical evidence but must not be promoted to certification of `ee07297` / v24.0.15.

## Current-main evidence

On exact merge SHA `ee07297045d76bf1288c895159718c5ab9646b82`:

- Cloudflare deployment succeeded.
- Live parity passed after the normal post-deploy re-dispatch.
- Production service-worker/offline gate passed.
- Push `Tests` run `35188438111`, attempt 1, job `105095447494` FAILED the full suite: **553 passed, 4 failed across 59 spec files**.
- All four failures have the same immediate signature: `TypeError: Cannot read properties of null (reading 'transaction')` at app `tx()` (`app.js?v=24.0.15`, around line 2854).
- Failing assertions:
  1. `integration/vehicle-profile-race.spec.mjs` — `[FINDING V-1 / FIXED] two concurrent ensureVehicleProfiles() resolve one profile, not two`
  2. `integration/m2-expense-fuel-concurrency.spec.mjs` — `[M2-01] a stale expense save is rejected with FL_CONFLICT`
  3. same file — `[M2-02] the earlier concurrent expense edit survives — no lost update`
  4. same file — `[M2-03] a stale fuel save is rejected with FL_CONFLICT`
- The rest of the current-sha suite passed, including SMS-01..04 and PA-01..08.

Per `AGENTS.md`, I triggered the one permitted controlled rerun of that exact job as **attempt 2**. It was still in progress when this note was first written. Do not treat a green attempt 2 as erasing attempt 1; the repository already records that a suite needing a rerun stops being clean evidence.

## Why this is not safely dismissible as a local flake

The operator's Grok report on the *older parent* independently observed the same class of `db === null` failure locally:

- M2-01 hit `db.transaction` null and cleared on isolated rerun.
- SMS-03 hit the same class and reproduced on its isolated rerun.
- GitHub CI happened to be green on that older SHA.

Current GitHub CI now reproduces the same class on 24.0.15. Therefore the failure predates PR #223 and spans at least two environments/SHAs. PR #223 is not implicated as the origin, but the race is now a current-main gate failure.

## Important narrowing already done

Current `app.js` has one module-scope `let db = null;` and the production boot assignment `db = await initDB();`. Source search found no later assignment that sets the shared handle back to null. `tests/lib/harness.mjs::waitForAppBoot()` already waits for a successful `window.__FL_TESTS.dumpStore('settings')`; `dumpStore()` goes through `tx()` and therefore cannot succeed while that same closure's `db` is null.

So the old explanation "launchApp returned before initDB assigned db" is insufficient for these failures. A null observed *after* the readiness probe implies one of these still-unproven lifecycle mechanisms:

1. the document/app IIFE is restarted after readiness (reload/navigation/re-bootstrap), creating a new closure whose `db` begins null; or
2. a second app.js instance replaces `window.__FL_TESTS`; or
3. another mechanism not yet observed explains how the failing call is bound to a closure that has not completed its DB assignment.

Do not patch from that hypothesis alone. Instrument it first.

### Suggested Claude-owned diagnostic (no assertion weakening)

Because `tests/` is Claude-owned and `app.js` is SHARED/serialized:

- instrument a task branch/harness to record `performance.timeOrigin`, a per-document init marker, `page.on('framenavigated')`, SW controller/registration state, and the `__FL_TESTS` document marker at (a) DB-readiness success and (b) immediately before the first failing persistence operation;
- reproduce under the full suite first, then one controlled focused diagnostic run if needed;
- if timeOrigin/document marker changes, trace the exact reload source (`initDB` self-heal vs SW/update path vs other navigation) before repairing;
- if it does not change, prove whether `window.__FL_TESTS` was replaced / app.js executed twice;
- preserve all existing assertions and use a negative control for any new regression;
- any `app.js` repair requires `lock/app-js` and the full suite.

## Separate documentation/certification drift on current production

`CLAUDE.md` on current main says **v24.0.15 is source-only / not deployed** and says production serves **24.0.14**. That is now false: v24.0.15 has deployed and passed live parity + production-SW verification.

`docs/CERTIFICATION_DEFERRAL_2026-09-16.md` correctly preserves the operator decision to defer physical iPhone A1-A12 and M6 raw-history to the final post-v24.5 candidate, but it names the prior 24.0.14 / `8f90725` release. The same document explicitly states that a superseding certification document is due the day a shipped file deploys. No 2026-09-17 certification-state document is present on current main.

Required doc-only reconciliation in Claude's lane:

- update `CLAUDE.md` deployment truth to observed v24.0.15 while preserving the A1-A12/M6 deferral;
- add/supersede the certification state for the current deployed SHA, recording live parity + production SW pass and the current full-suite attempt-1 failure (plus attempt-2 observation when complete);
- do **not** convert the explicit A1-A12/M6 deferral into a test queue or a PASS.

## Bottom line

Grok's `2f04bf5` report is valid evidence for the old parent and corroborates the pre-existing DB-null race. It is not authority to call current `main` green. Current main remains uncertified until the current-sha suite race is diagnosed and the certification chain is reconciled; the physical-device/M6 gates remain deliberately deferred per operator decision.
