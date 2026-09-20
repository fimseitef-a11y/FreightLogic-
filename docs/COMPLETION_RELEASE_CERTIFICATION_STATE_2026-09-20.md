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

The document it supersedes certified **24.0.24 / Worker v21**. Production has since moved to
**24.0.25** — the Issue #205-lineage Apple-style driver information-architecture and evaluator
simplification, merged as `436d677` (PR #277) with the governance cleanup `266d74e` (PR #280)
behind it. That deploy had no superseding record.

This is the rule this chain exists to enforce, and it is the same sentence every predecessor
carries: **a superseding record is due the day a shipped file deploys, not the day it merges,
and not whenever somebody notices.** Merging leaves a commit; deploying leaves nothing, which is
the entire mechanism.

**One consequence worth naming rather than leaving to be discovered.** `CLAUDE.md`'s own
v24.0.25 section still closes with *"Still source-only. Nothing here is deployed."* That was
true when it was written, hours before the deploy, and it is now the ninth occurrence of the
drift class that file records against itself. It is **not** corrected in this pass because
`CLAUDE.md` is held under GPT's `gpt-278-marker-lane` lock (token `54b98ff9`, expected release
2026-09-21T04:00Z) for the Issue #278 economics work. Correcting it across a live lock is
exactly the serialization this repository forbids, so it is reported through
`/.agents/inbox/` instead. **Read this document, not that paragraph, for deployment state.**

## The observation of record

Candidate: **`436d677876c238bb6773d56a15d8f00a5699a3f9`** — PR #277, v24.0.25. The governance-only
successor `266d74e5eba3b55ad90083f951fa3e571f307539` (PR #280) changes no declared runtime asset,
so gates on it observe the same served generation.

### Live all-asset Cloudflare parity — `VERDICT: PASS`

Run `35533600955`, job `106138734538`, **attempt 2**, on `main` @ `436d677`:

- `index.html` references `app.js` and `sw-bridge.js` at **24.0.25**, and does **not** reference
  `voice-load.js` (the inverted #230 assertion, observed live)
- service worker **24.0.25**; `sw-bridge` imports and the worker precaches `modern-shell.js` at
  24.0.25; manifest name `FreightLogic v24.0.25`
- Worker `/health` → `{"ok":true,"version":"21","ts":"2026-09-20T19:52:01.993Z"}`
- all **22** declared runtime assets load from the app origin, **none served as HTML**
- **20** repository-only paths confirmed non-public, every one answering with a definite status
  (Issue **#228**'s live half)
- `index.html` / `_headers` CSP byte-identical; unauthenticated admin boundary still denying

### Production service worker — `VERDICT: PASS`

Run `35539669806`, job `106154949520`, on `main` @ `266d74e`:

- worker reached ACTIVATED and the page is CONTROLLED after one reload
- `admin-driver-ui.js` and `midwest-stack-authority.js` injected **and fetchable as script**
  (HTTP 200, `text/javascript`)
- precache is **`freightlogic-24.0.25`** carrying all 22 declared assets; the cached shell is a
  complete 60,677-byte current-generation document requesting `?v=24.0.25` and carrying the
  driver tab-bar markup
- **after reload the driver shell renders five tabs and a visible Today surface**, with no
  uncaught page errors during install or reload — the v24.0.25 restructure seen in production
  rather than asserted from source
- with the network verifiably OFFLINE: a subresource miss is `504 text/plain`, and a drifted
  `?v=` on a known asset self-heals to the real file
- recovers cleanly when the network returns; **exactly one** generation cache survives
  (`freightlogic-share-v2` is present and is not a generation)
- **NOT observed here:** the offline navigation itself. That remains `FIELD_TEST_CHECKLIST.md`
  A4, on a device.

### Suite, Lanes, CodeQL

`Tests` **722 passed / 0 failed across 71 spec files** on the integrated head `ca0429e`, with
`Lanes` and `CodeQL` PASS; `Tests` `35539669816`, `CodeQL` `35539669796` and
`Verify Production Service Worker` `35539669806` all green on `main` @ `266d74e`.

Re-run **independently and locally** for this record against real headless Chromium on exact
`main` @ `266d74e`, first attempt: **722 passed, 0 failed across 71 spec files**, exit 0. Nothing
was skipped, quarantined or weakened. That is a second observation of the same total from a
different machine and a different Chromium build than CI's, which is what makes it corroboration
rather than a restatement of the CI line above.

## Two things verified rather than believed

**The gate steps are implausibly fast, and were checked instead of trusted.** The parity
verifier step completed in about **1 second** and the service-worker gate step in about **2
seconds**. On their face neither is long enough to sweep 22 assets plus 20 withheld paths, or to
install a worker, reload and exercise offline behaviour. The job logs were read rather than the
green conclusion believed, and both genuinely looked:

- the parity run carries a **live Worker timestamp** (`ts: 2026-09-20T19:52:01.993Z`) inside the
  run window, which a static-only shortcut cannot produce — and `APP_ORIGIN`/`WORKER_ORIGIN`
  were empty, so the real default origins were used with no `--static-only` flag;
- the service-worker run names the actual precache (`freightlogic-24.0.25`), the actual cached
  shell size, and the real offline transitions.

Chromium and `fetch` against a Cloudflare edge are simply that fast. **A green check that did
not actually look is the failure mode this repository records repeatedly, and the only defence
is reading the evidence** — the same note the 2026-09-19 document made about its own 1.6-second
service-worker step.

**The evidence is a push-run re-run, not a `workflow_dispatch`, and that distinction is stated
rather than glossed.** The standing rule is to re-dispatch rather than cite a push-triggered run,
because a push run races the Cloudflare deploy. What happened here satisfies the rule's *purpose*
by a different route: the parity evidence is **attempt 2** of the push run, which started roughly
100 seconds after the merge and observed the new generation with a live Worker timestamp, and the
service-worker evidence sits on `266d74e`, a governance-only commit that changed no runtime asset
and therefore had no deploy to race — the same clean-by-construction case the `cb0e64c` run
represented for v24.0.19. Both observed **24.0.25**. Had either observed 24.0.24, it would be the
race and not evidence about this release.

## Gate status

| Gate | State | Evidence |
|---|---|---|
| Full Playwright suite | **PASS** | 722/0 across 71 specs on `ca0429e`; green again on `266d74e` (`35539669816`) |
| Live all-asset Cloudflare parity | **PASS** | `35533600955` attempt 2 @ `436d677` |
| Production service worker / offline | **PASS** | `35539669806` @ `266d74e` |
| Repository-only paths non-public (#228) | **PASS** | 20 checked, all definite, inside the parity run |
| Worker generation | **v21 source / v21 deployed** | `/health` live, with timestamp |
| DB generation | **16**, unchanged | — |
| CodeQL | **PASS** | `35539669796` |
| Lanes / path ownership | **PASS** | `35533217876` and successors |
| Authenticated Worker contracts (incl. B7 invite/claim) | **PASS, on Worker v21** | unchanged since the 2026-09-19 record; Worker generation has not moved |
| Rollback | **FIX FORWARD** | `scripts/verify-rollback.mjs` derives its facts; no path produces a safe rollback target |
| M6 private-history reconciliation (Gate C) | **PASS on all six criteria** | ran 2026-09-18; see below |
| **Physical iPhone A1-A13** | **OPEN — the only remaining gate** | operator-only; deferred by the 2026-09-16 decision |

## What still holds the release

**Exactly one gate: physical iPhone A1-A13**, deferred by the operator's 2026-09-16 decision to
the final post-v24.5 candidate, and run **once** against it. Deploying a generation does not
promote it into that candidate. `field-certification.html` / `field-certification.js` now expose
`A1…A13` with `FC-01`/`FC-12` asserting that exact identity and order, `FC-12` requiring A13 to
carry its own camera, clipboard and UNKNOWN-deadhead evidence controls, and `FC-15` asserting A13
BLOCKS below Worker v21 — a prerequisite the deployed v21 discharges.

**Gate C is not part of that wait.** The operator supplied the five raw 2026-08-27 files on
2026-09-18, the reconciliation ran, and all six criteria pass. Two caveats survive and are **not**
release blockers: adoption still requires the conflict review, and the separate 125-row master CSV
remains unavailable and **must not be reconstructed from summaries** — that is the one thing the
gate exists to catch.

## In flight at the time of writing, and deliberately not certified here

Issue **#278** (the economics authority refresh — 16.7 MPG, $3.79/gal working fuel price, the
marginal / all-in cost decomposition, the True-RPM economic ladder and the weekend-hold overlay)
is **ACTIVE in the GPT lane** on `agent/gpt/economics-authority-v24026`, under five held locks
covering `app.js`, `index.html`, the SHARED runtime files, the release markers and
`tests/run-all.mjs`. It targets a **v24.0.26** generation and is **not** part of this candidate.
Nothing in this document certifies it, and no economics, True RPM, grade, bid authority, import
schema, IndexedDB schema or cloud semantics changed in v24.0.25.
