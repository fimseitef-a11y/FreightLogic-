# Request: carry the v24.0.27 generation into the three documentation markers

From: claude lane
Date: 2026-09-21
Branch under review: `claude/freight-logic-completion-helmys`

## What landed

F-9, a reproduced driver-facing defect. `#toast` is a single element with a
single timer, and `toast()` let any later caller overwrite whatever was on it.
The GPS-loss reassurance fires exactly **once per error streak** by design
(watchPosition re-fires every 15s and toasting each one would bury the driver),
so a cosmetic "FreightLogic <version> installed." notice landing inside its
2.4s window did not merely reorder two messages — it permanently destroyed the
driver's only signal that the trip was degraded but still tracking.

This is the failure recorded in `STATUS.md` against PR #288 Tests run
`35556446150` attempt 1 (740/1) and cleared by a controlled retry. **It was not
timing noise.** It was reproduced deterministically through the real
`SW_ACTIVATED` listener in the real app before any code changed.

The rule now matches the one the cloud-backup paused banner already follows: an
informational notice may vanish, a warning may not. Escalation is unrestricted —
a warning still replaces anything, including another warning — so only the
informational-over-a-visible-warning direction is refused.

## Why a generation moved

`RG-03` correctly refused the tree at a reused `24.0.26`. `CACHE_NAME` is
`freightlogic-${SW_VERSION}` and the `?v=` query is the only other identity a
child asset carries, so an installed PWA would never have fetched the repaired
`app.js`. Every governed runtime marker moved together to **24.0.27**; DB stays
**16** and the Worker stays **v21**.

Evidence on the exact candidate head:
- full suite **743 passed / 0 failed across 72 specs**, first attempt, nothing
  skipped or weakened (main's 741 plus the two new F-9 assertions)
- red-first control: 13 passed / 2 failed, with **only** the two new tests
  failing, each on its own assertion
- `lane-guard ci-paths` (claude, 10 changed) OK; `ci-prefix` OK
- `verify-cloudflare-parity --static-only` PASS at 24.0.27, CSP byte-identical,
  22 declared runtime assets
- `verify-release-generation` → "Runtime changes advance the release generation"

## The request

Three documentation markers still read `24.0.26` and are **all three inside open
PR #289's scope**, so they were deliberately not edited across lanes:

1. `CLAUDE.md` — Project Overview, Key Constants, PWA section (checklist item 10),
   plus a release section for v24.0.27.
2. `FIELD_TEST_CHECKLIST.md` — current candidate generation.
3. `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` — checklist item 13. Note this
   file was **already three generations stale before this change**, reading
   `24.0.24` while production served `24.0.26`. PR #289 rewrites it substantially,
   which is why nothing was touched here rather than creating a conflict.

Please carry `24.0.27` into these as part of, or immediately after, PR #289.

## One thing to preserve, not bump

`app.js` now contains the literal string `"FreightLogic 24.0.26 installed."`
inside the F-9 comment. That is a **verbatim quote of the observed CI evidence**
and must not be advanced by a future blanket release bump.

That failure mode is not hypothetical: this change also restored a provenance
comment in `scripts/verify-cloudflare-parity.mjs` which originally read
`v24.0.14` and had been rewritten to each new generation in turn by successive
blanket `sed` bumps, until it claimed the adapter check was added in the release
that was merely passing through.

## Not claimed

Nothing here touches the physical iPhone A1-A13 gate or M6. Production still
serves **24.0.26** until 24.0.27 is merged, deployed and re-observed, and PR
#289's record of the 24.0.26 production observation remains accurate.
