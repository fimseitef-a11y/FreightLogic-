# GPT -> Claude: v24.0.2 iPhone stale-generation/update-path failure

Date: 2026-09-02
Priority: completion-release blocker / field A1
Current live `main` at observation: `9fb3b6931a513b81920c231508eca6c5982095f9`
Expected runtime: app/PWA/service worker v24.0.2, DB v15, Worker v13

## Physical-device evidence

The operator supplied two screenshots from the installed iPhone PWA. The app
launches, but the header visibly reads `Omega • v23.x` (the final digits are
obscured by the iPhone status/Dynamic Island overlay), not v24.0.2. The app also
shows the first-run home card and setup wizard.

Disposition:

- `FIELD_TEST_CHECKLIST.md` A1 is **FAIL**, not PASS: the installed PWA remains
  on an older generation.
- Do not ask the operator to uninstall the PWA, clear Safari website data, or
  enter real data until the origin/deployment and local-data implications are
  understood. Those actions could destroy local IndexedDB evidence.
- The screenshots do not by themselves prove whether the cause is an old
  production deployment, an origin mismatch/new storage partition, or a stale
  service-worker update. Verify each separately.

## Current-source update handshake defect

Exact-current source contains an uncovered update handshake defect consistent
with a waiting update failing to reload immediately:

1. `sw-bridge.js` reloads on `controllerchange` only when its private
   `skipWaitingRequested` flag is true.
2. That flag is set only inside `window._flRequestSWUpdate`.
3. The `app.js` `#swUpdateNow` handler bypasses that function and directly calls
   `nw.postMessage({ type: 'SKIP_WAITING' })`.
4. Therefore the waiting worker can activate while the bridge refuses the
   resulting `controllerchange` reload.
5. The bridge helper's current fallback targets
   `navigator.serviceWorker.controller`, which is the active worker rather than
   necessarily `registration.waiting`; the repair must target the actual
   waiting/installing worker deliberately.
6. `rg` finds no current regression covering `_flRequestSWUpdate`,
   `swUpdateNow`, `controllerchange`, or the update-ready reload handshake.

## Required Claude-lane repair

Under `lock/app-js` (and any other required shared-path lock):

1. Make the update-ready button and bridge use one explicit handshake that:
   - marks the reload as agent-requested before sending `SKIP_WAITING`;
   - sends the message to the actual waiting worker;
   - reloads exactly once on `controllerchange`;
   - remains safe on first install when there was no prior controller; and
   - provides a deterministic fallback if the waiting worker disappears.
2. Add a real regression for the update-ready button -> waiting worker ->
   controller change -> one reload path. Do not settle for a string-presence
   assertion.
3. Run the full suite on the exact PR head.
4. Verify the production deployment is sourced from current `main` and that the
   live app, manifest, service worker, and cache-busted assets all report
   v24.0.2.
5. Preserve IndexedDB/local-storage safety. Do not use delete/reinstall/clear as
   the primary update procedure.

## Acceptance evidence to return

- repair commit/PR and lock trailer;
- exact full-suite result;
- test name proving the one-reload handshake;
- production deployed SHA and visible v24.0.2 generation markers; and
- a safe operator update sequence that does not erase existing local data.

This is a newly observed physical-field failure and reopens the code/live side
of the completion HOLD until repaired and re-tested on the operator's iPhone.
