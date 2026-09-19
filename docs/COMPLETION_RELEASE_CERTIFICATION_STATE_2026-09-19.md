# Completion release certification state — production 24.0.24 / DB16 / Worker v21

Date: 2026-09-19
Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-18.md
Status: **HOLD — every automatable and live-origin gate is OBSERVED and PASSING on this candidate, on BOTH generations. Exactly one gate remains: physical iPhone A1-A13, deferred by the operator's 2026-09-16 decision to the final post-v24.5 candidate.**

This document is the certification authority. Every earlier state and addendum document is
historical evidence and must not be read as the current candidate.

> **Not a live test queue.** The operator's 2026-09-16 decision deferring the physical-device
> gate to the **final post-v24.5 candidate** still stands. See
> `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` before acting on the HOLD or on any open row in
> `FIELD_TEST_CHECKLIST.md`. The M6 private-history gate is **not** part of that wait — Gate C
> ran on 2026-09-18 and passed all six criteria.

## Why this document exists

The document it supersedes certified **24.0.19 / Worker v20** and named the device gate as
A1-**A12**. Production has since moved through five app generations — 24.0.20, .21, .22, .23,
.24 — and the device gate widened to **A1-A13** when v24.0.21 added screenshot intake. Neither
fact had a superseding record.

That is the drift this chain exists to prevent, and the rule it keeps relearning: **a superseding
record is due the day a shipped file deploys, not the day it merges, and not whenever somebody
notices.** Merging leaves a commit; deploying leaves nothing, which is the entire mechanism.

## The observation of record

Candidate: `f75f9cc92b4e6e27463bc13a3eca5f89d7bcb057` — PR #275, v24.0.24, the Issue #268
Apple/iOS accessibility completion.

**Live all-asset Cloudflare parity — `workflow_dispatch` on `main`, run `35434716935`,
job `105875325854`, `VERDICT: PASS`:**

- Worker `/health` → `{"ok":true,"version":"21"}`
- all **22** declared runtime assets load from the app origin
- no runtime asset served as HTML (no SPA fallback masking a miss)
- **20** repository-only paths confirmed non-public — Issue **#228**'s live half
- every withheld path answered with a definite status, so none was counted as withheld
  merely because it could not be reached
- unauthenticated admin boundary still denying

**Production service worker — `workflow_dispatch` on `main`, run `35434719454`,
job `105875332085`, `VERDICT: PASS`, 16 checks / 0 failures:**

- app and service worker both at **24.0.24**
- precache is `freightlogic-24.0.24` carrying all 22 declared assets
- `admin-driver-ui.js` and `midwest-stack-authority.js` injected **and fetchable as script**
  (HTTP 200, `text/javascript`)
- after reload the driver shell renders five tabs and a visible Today surface, with no uncaught
  page errors during install or reload
- with the network verifiably down: a subresource miss is `504 text/plain` rather than the HTML
  shell, and a drifted `?v=` on a known asset self-heals to the real file
- the cached shell is a complete current-generation document requesting `?v=24.0.24`
- exactly one generation cache survives; `freightlogic-share-v2` is present and is not a
  generation

### The push race recurred for the ninth time and must not be cited

Live parity also fired on the merge push (`35434651294`) and **FAILED** eleven seconds later,
observing the previous generation while Cloudflare was still deploying. The re-dispatched run
ninety seconds afterwards is the observation of record. That failure is real evidence about the
origin *at that instant* and is **not** evidence about the release.

A re-dispatch is not a way of making a failure go away. When a re-dispatch fails *the same way*,
that is a real finding — as it was for the v24.0.17 Worker-generation mismatch.

### One check was verified rather than trusted

The service-worker gate's own step completed in about 1.6 seconds, which is implausible on its
face for something that installs a worker, reloads, and exercises offline behaviour. The job log
was read rather than the conclusion believed: each of the sixteen checks carries its own
progressing timestamp, so the work genuinely happened — Chromium against a Cloudflare Worker is
simply that fast. A green check that did not actually look is the failure mode this repository
records repeatedly, and the only defence is reading the evidence.

## What is closed

Every automatable and live-origin gate, on both generations:

| Gate | Result | Evidence |
|---|---|---|
| Live all-asset Cloudflare parity | **PASS** | run `35434716935` @ `f75f9cc` |
| Production service worker / offline | **PASS** | run `35434719454` @ `f75f9cc` |
| Repository-only paths non-public (#228) | **PASS** | 20 paths, inside the parity run |
| Worker generation agreement | **PASS** | `/health` reports v21; source carries v21 |
| Full Playwright suite | **PASS** | `Tests` on the exact candidate |
| CodeQL | **PASS** | on the exact candidate |
| Lane ownership / commit prefix / lock trailer | **PASS** | `Lanes` on the candidate PR |
| M6 Gate C — authentic private-history reconciliation | **PASS** | 2026-09-18, commit `2ece6f31`; 5/5 files, 216 source rows, 149 records, 141 null / 8 positive / **0 fabricated deadhead zeros** |

Gate C is **not** re-run merely because the app generation changed. Re-open it only if a later
change touches the historical importer or reconciliation semantics it certified. The separate
125-row 2026-08-24 master CSV remains unavailable and must never be reconstructed from
summaries — that is the one thing the gate exists to catch.

## What holds the release — exactly one gate

**Physical iPhone A1-A13.** Safe-area insets, the software keyboard, background GPS across a
real lock/unlock, iOS permission revocation mid-trip, installed-PWA update behaviour, a genuine
Airplane Mode round trip including the offline **navigation** the automated gate explicitly
declines to claim, the iOS 27 / Safari 27 visual pass, zero-token onboarding across the
Safari → Home Screen storage boundary, and **A13** screenshot intake.

A13's stated prerequisite is **discharged**: it requires a deployed Worker exposing
`POST /extract-image`, and Worker v21 is deployed and observed above. The row is therefore
**OPEN**, not BLOCKED. Confirm `/health` still reports that generation before running it — the
prerequisite is a live fact, not a permanent one.

Deferred by the operator's 2026-09-16 decision to the final post-v24.5 candidate. Deploying a
generation does not promote it into that candidate, and a partial A-section run against a
generation that will be superseded is not evidence.

## Known open, and not gating certification

- **Issue #222 — repository control-plane.** `main` reports `protected:false` and the rulesets
  collection is empty. This is not reachable from any connected integration: the GitHub tool
  surface available to the agent lanes has no branch-protection, ruleset or repository-settings
  capability, re-verified three times on 2026-09-19. Exact steps are recorded on the issue.
  It is an operations gap rather than a release gate, but it is the reason `Tests` and `Lanes`
  are advisory rather than binding on `main` today.
- **`tests/run-all.mjs` ownership deadlock, second occurrence.** The 2026-09-19 Issue #268 grant
  gives that file's Owner column to `gpt` while its Notes describe a registration-only grant;
  `lane-guard` reads the column, and `RH-01` requires every spec on disk to be registered.
  Requested at `.agents/inbox/claude-to-gpt-run-all-deadlock-again-2026-09-19.md`. It blocks any
  new Claude regression file, not one specific spec.
- **Issue #252 provider benchmark — instrument ready, not run.** `workers-ai` remains the
  zero-cost **candidate** rather than a measured winner. The harness
  (`scripts/benchmark-vision-providers.mjs`) needs real DispatchLand screenshots, which are
  operator data and must not enter this repository.

## How to supersede this document

The next state document names this file in its `Supersedes:` line. `scripts/m7-certify.mjs`
resolves the chain by explicit supersession and **not** by date ordering, so a newer filename
alone does not clear a blocking state.

Two mechanics worth knowing before writing one:

- The resolver matches an exact `YYYY-MM-DD` filename with no suffix, so **two certification
  events on one day cannot be two documents** — append a same-day section instead.
- A `Supersedes:` value is normalized for a backticked or directory-prefixed reference
  (`` `docs/NAME.md` ``), which is how every real document in this directory writes it. That
  normalization was itself a repair: before it, seven documents resolved as current at once.
