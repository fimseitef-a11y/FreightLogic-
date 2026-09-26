# GPT -> Claude: v24.0.2 iPhone stale-generation/update-path failure

Date: 2026-09-02
Priority: completion-release blocker / field A1
Current live `main` at observation: `9fb3b6931a513b81920c231508eca6c5982095f9`
Expected runtime: app/PWA/service worker v24.0.2, DB v15, Worker v13

## Physical-device evidence

The operator supplied screenshots from the installed iPhone PWA. A later
More-screen screenshot establishes the exact installed generation as
**FreightLogic v23.7.0**, not v24.0.2. The app also shows the first-run home card
and setup wizard.

Disposition:

- `FIELD_TEST_CHECKLIST.md` A1 is **FAIL**, not PASS: the installed PWA remains
  on an older generation.
- Do not ask the operator to uninstall the PWA, clear Safari website data, or
  enter real data until the origin/deployment and local-data implications are
  understood. Those actions could destroy local IndexedDB evidence.
- The screenshots do not by themselves prove whether the cause is an old
  production deployment, an origin mismatch/new storage partition, or a failed
  service-worker fetch/update. Verify each separately.

Exact v23.7.0 source is material to triage: its `sw-bridge.js` calls
`registration.update()` immediately on load and its `controllerchange` listener
reloads unconditionally. If the same production origin were serving the
v24.0.2 service worker and the device could reach it, that old client should at
least discover an update. This shifts the primary investigation toward the
actual installed origin and the production Pages/assets deployment. The
current-source handshake defect below remains real and must still be repaired,
but it is not proven to be the sole cause of this v23.7.0 observation.

## Current-source update handshake defect

Exact-current v24.0.2 source also contains an uncovered update handshake defect
that can make a waiting update fail to reload immediately:

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
4. Identify the exact origin of the installed Home Screen PWA and verify the
   production Pages/assets deployment is sourced from current `main`; do not
   infer app deployment from a successful `freightlogic-v2` Worker build.
5. Verify the live app, manifest, service worker, and cache-busted assets all
   report v24.0.2.
6. Preserve IndexedDB/local-storage safety. Do not use delete/reinstall/clear as
   the primary update procedure.

## Acceptance evidence to return

- repair commit/PR and lock trailer;
- exact full-suite result;
- test name proving the one-reload handshake;
- production deployed SHA and visible v24.0.2 generation markers; and
- a safe operator update sequence that does not erase existing local data.

This exact v23.7.0 physical-field failure reopens the code/live side of the
completion HOLD until the deployment origin and update path are repaired and
re-tested on the operator's iPhone.
