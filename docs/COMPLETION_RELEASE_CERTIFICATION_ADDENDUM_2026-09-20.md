# Completion release certification state — production 24.0.25 / DB16 / Worker v21

Date: 2026-09-20
Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-19.md
Status: **HOLD — every automatable and live-origin gate is OBSERVED and PASSING on this candidate, on BOTH generations. Exactly one gate remains: physical iPhone A1-A13, deferred by the operator's 2026-09-16 decision to the final post-v24.5 candidate.**

This document is the certification authority. Every earlier state and addendum document is
historical evidence and must not be read as the current candidate.

> **Not a live test queue.** The operator's 2026-09-16 decision deferring the physical-device
> gate to the **final post-v24.5 candidate** still stands. See
> `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` before acting on the HOLD or on any open row in
> `FIELD_TEST_CHECKLIST.md`. The M6 private-history gate is **not** part of that wait — Gate C
> ran on 2026-09-18 and passed all six criteria.

## Why this document exists

The document it supersedes certified **24.0.24 / Worker v21** on candidate `f75f9cc`. Production
has since moved to **24.0.25** — PR #277, the operator-directed Apple-style driver
information-architecture / evaluator simplification — and that deploy had no superseding record.

It is the same drift this chain exists to prevent, and this instance had a second symptom worth
recording, because it is the one a reader would actually have been misled by. Two governance
records disagreed:

- `CLAUDE.md`'s Project Overview still read *"LAST VERIFIED PRODUCTION SERVES 24.0.24"* and
  described v24.0.25 as *"source-only until merged, deployed, and observed."*
- `.agents/LANES.md` had already recorded, on 2026-09-20, that *"production service-worker and
  live-parity gates subsequently observed v24.0.25."*

Neither was treated as evidence. **Both live gates were re-dispatched and their verdicts read**,
and `CLAUDE.md` was corrected to match what they returned. A lane-ownership map is not the
release record, and prose in either file is not an observation.

The rule is unchanged and is the one this chain keeps relearning: **a superseding record is due
the day a shipped file deploys, not the day it merges, and not whenever somebody notices.**
Merging leaves a commit; deploying leaves nothing, which is the entire mechanism.

## The observation of record

Candidate: `266d74e5eba3b55ad90083f951fa3e571f307539` — `main`, PR #280.

The runtime generation is **v24.0.25**, which merged as `436d6778` (PR #277). `266d74e`
(PR #280) is a governance-only cleanup retiring the temporary marker ownership: it modifies
`.agents/LANES.md` and nothing else (+4/-5, one file), so **the runtime tree observed here is
byte-identical to the v24.0.25 runtime tree**. `scripts/verify-release-generation.mjs` agrees —
`"No deployed app bytes changed"`.

`DB_VERSION` stays **16** and the Worker stays **v21**. No schema, Worker, economics or doctrine
semantics changed in this generation.

### Live all-asset Cloudflare parity — `workflow_dispatch` on `main`, run `35542846195`, job `106163516058`, `VERDICT: PASS`

- manifest loads (HTTP 200) and its name is `FreightLogic v24.0.25`
- Worker `/health` → `{"ok":true,"version":"21"}`
- admin endpoint rejects without a token — 401
- all **22** declared runtime assets load from the app origin
- no runtime asset served as HTML (no SPA fallback masking a miss)
- **20** repository-only paths confirmed non-public — Issue **#228**'s live half
- every withheld path answered with a definite status, so none was counted as withheld merely
  because it could not be reached

### Production service worker / offline — `workflow_dispatch` on `main`, run `35542851411`, job `106163528152`, `VERDICT: PASS`

This is the half delivery cannot prove. A 200 proves an asset was served; it says nothing about
what a browser does after installing the deployed worker.

- the origin serves the app shell (HTTP 200); the service worker reaches **ACTIVATED**; the page
  is **CONTROLLED** after one reload
- `admin-driver-ui.js` and `midwest-stack-authority.js` are each injected **and fetchable as
  script** — HTTP 200, `text/javascript`
- the precache is the current generation, `freightlogic-24.0.25`, and carries all **22** declared
  runtime assets
- **after reload the driver shell renders five tabs and a visible Today surface**, with no
  uncaught page errors during install or reload
- with the network verifiably down, checked against the running worker instance: an uncached
  subresource miss returns `504 text/plain` rather than the HTML shell
  (`/does-not-exist.js`), a cached asset still serves as script (`/app.js`, 200
  `text/javascript`), and a drifted `?v=` on a known asset self-heals to the real file
- the cached app shell is a complete HTML document (60677 bytes, `text/html`), carries the driver
  tab-bar markup, and requests the current generation's assets (`?v=24.0.25`)
- the worker recovers cleanly when the network returns
- exactly **one** generation cache survives — `freightlogic-24.0.25`, with no stale generation
  left behind. `freightlogic-share-v2` is also present and is expected: it is `SHARE_CACHE`, not
  a generation.

**This release's own subject was observed, not asserted.** v24.0.25 is an information-architecture
change, so "five tabs and a visible Today surface after reload, with no uncaught errors" is the
gate that actually looks at what shipped. v24.0.8 is the precedent for why that matters: the Loads
tab shipped green because the hash and the highlighted tab were both correct while the surface
itself was dead.

### Repository-side

`node scripts/verify-cloudflare-parity.mjs --static-only` is **PASS** at 24.0.25: CSP is
byte-identical between `index.html` and `_headers`, and no runtime asset is excluded from
deployment by `.assetsignore` (22 declared).

## What this document does NOT claim

Stated explicitly, because an unobserved gate recorded as passing is the failure this chain
exists to prevent.

1. **The full Playwright suite was not re-run for this document.** Playwright is not installed in
   the session container that produced this record, so no suite total is asserted here. The
   exact-head suite evidence for the v24.0.25 integration is recorded in `CLAUDE.md`'s v24.0.25
   release section and in the `Tests` workflow runs on `main`; read it there rather than from this
   sentence.
2. **The offline navigation itself was not observed.** The production service-worker gate says so
   in its own output. Offline emulation does not survive a navigation for a service worker —
   documented in `CLAUDE.md` — so the gate declines to claim it rather than implying it. That is
   `FIELD_TEST_CHECKLIST.md` A4, on a device.
3. **Nothing here is evidence for the physical-device gate.** No headless browser result may be
   read as A1-A13 PASS.

## What remains

**One gate: physical iPhone A1-A13** (Issue #226), deferred by the operator's 2026-09-16 decision
to the final post-v24.5 candidate. `FIELD_TEST_CHECKLIST.md` remains the instrument. The device
gate for this generation still includes the v24.0.21 screenshot-intake row A13, which requires a
deployed Worker exposing `POST /extract-image`; the deployed Worker reports v21, so that
precondition is met and a failing attempt there is a real result rather than BLOCKED.

**Gate C (M6 private-history reconciliation) is not part of that wait.** It ran on 2026-09-18 and
passes all six criteria. Adoption still requires the conflict review, the single `in_progress` row
carrying `awarded: true` is flagged for operator confirmation rather than absorbed, and the
separate 125-row master CSV remains unavailable and **must not be reconstructed from summaries** —
reconstructing it would test the summary, not the source, which is the one thing that gate exists
to catch.

## Provenance note

The two runs named above were **re-dispatched**, not taken from a push-triggered run. A parity or
service-worker run that fires on the merge push races the Cloudflare deploy and has been recorded
failing for that reason nine times in this repository. Such a failure is real evidence about the
origin at that instant and is **not** evidence about the release. The converse also holds and is
not softened here: a re-dispatch that fails *the same way* is a real finding, as it was for the
v24.0.17 Worker-generation mismatch.
