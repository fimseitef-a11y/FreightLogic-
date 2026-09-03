# GPT -> Claude core-lane handoff: freeze a new cache generation before field retest

Date: 2026-09-03
Priority: RELEASE BLOCKER
Tracker: Issue #119
Current main at review: `0282cf18769acf2b82b692a4e73048542f811308`
Core PR in flight: #137

## Finding

PR #134 changed `app.js` and `sw-bridge.js` to repair the update handshake. PR #136 changed `app.js` to report install identity. The live repository still uses `24.0.2` for:

- `APP_VERSION`
- `SW_VERSION` and `freightlogic-24.0.2`
- versioned app/voice/bridge/manifest/overlay URLs
- manifest name
- parity-script expectations

A client that already cached the pre-repair v24.0.2 shell has no new release/cache identity. In particular, the service-worker script itself was not changed by PR #134 or #136, so the browser need not install a new worker merely because same-version child assets changed. Cache-first requests and unchanged query strings can therefore keep an earlier v24.0.2 client from receiving the bridge repair or Diagnostics readout.

This is separate from the observed iPhone v23.7.0 wrong-origin/deployment investigation. It is a release-generation correctness problem for any earlier v24.0.2 client.

## Required core-lane work

After PR #137 is repaired/green/merged, freeze the corrected runtime as a new generation (recommended `24.0.3`, unless another coordinated version is already reserved):

1. Update every governed app/PWA/SW/manifest/overlay/versioned-asset marker atomically.
2. Update parity-script expectations.
3. Keep DB v15 and Worker v13 unless source semantics require otherwise.
4. Add/adjust a regression proving the current cache generation and versioned URLs move together and the SW script bytes/version change.
5. Run the complete suite and static parity check on the exact head.
6. Do not certify or instruct the operator to reinstall/clear data. The installed-origin Diagnostics evidence and safe iPhone retest remain required.

## Separate red check on PR #137

The PR's MRC tests pass, but exact-head CI is red because `DXI-04` races SW activation cleanup. The fake `freightlogic-1.2.3` cache is sometimes deleted before Diagnostics enumerates caches. Stabilize that test before merge; see the PR review comment for the exact log.

