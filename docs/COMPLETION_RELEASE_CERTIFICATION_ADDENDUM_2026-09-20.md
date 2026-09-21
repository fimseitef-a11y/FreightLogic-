# Completion release certification state — production 24.0.26 / DB16 / Worker v21

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
has since moved through **24.0.25** (PR #277, the Apple-style driver IA slice) and **24.0.26**
(PR #281, the Issue #278 economics-authority refresh), and neither deploy had a superseding
record.

**This document was itself amended before it merged, and that is recorded rather than hidden.**
It was first written certifying 24.0.25, from two re-dispatched gates on `266d74e`. While it sat
unmerged, PR #281 merged and deployed, moving production to 24.0.26 within the hour. Rather than
merge a certification record that was already superseded — the exact defect this chain exists to
prevent — it was re-verified against the new head and rewritten. The 24.0.25 evidence is kept
below as history, because those runs remain permanent provenance for the tree they looked at.

That is the second symptom worth recording. Four governance records disagreed about what
production served inside one hour:

- `CLAUDE.md`'s Project Overview said 24.0.24, then said 24.0.25, while PR #281's own overview
  shipped saying *"LAST VERIFIED PRODUCTION SERVES 24.0.25 … Production therefore remains
  v24.0.25 until this 24.0.26 candidate is merged, deployed, and observed"* — superseded by its
  own deploy within minutes;
- `FIELD_TEST_CHECKLIST.md` said 24.0.24 and named a superseded certification document;
- `.claude/CLAUDE.md` said 24.0.19;
- `.agents/LANES.md` was correct for 24.0.25 and stale for 24.0.26.

None was treated as evidence. **The gates were re-dispatched and their verdicts read**, twice —
once for 24.0.25 and again for 24.0.26.

The rule is unchanged: **a superseding record is due the day a shipped file deploys, not the day
it merges, and not whenever somebody notices.** Merging leaves a commit; deploying leaves
nothing, which is the entire mechanism.

## The observation of record

Candidate: `9e3be9e0e61592c6cdaaec1fd489391f7dfa28e8` — `main`, PR #281, v24.0.26.

`DB_VERSION` stays **16** and the Worker stays **v21**. The Worker's semantics did not change in
this generation; the economics refresh is client-side.

### Live all-asset Cloudflare parity — `workflow_dispatch` on `main`, run `35544113040`, job `106166881011`, `VERDICT: PASS`

- Worker `/health` → `{"ok":true,"version":"21"}`
- all **22** declared runtime assets load from the app origin
- no runtime asset served as HTML (no SPA fallback masking a miss)
- the unauthenticated admin endpoint still rejects — 401
- **20** repository-only paths confirmed non-public — Issue **#228**'s live half
- every withheld path answered with a definite status, so none was counted as withheld merely
  because it could not be reached

This run was **re-dispatched**, not taken from the merge push.

### Production service worker / offline — `main`, run `35543985994`, job `106166542768`, `VERDICT: PASS`

- the origin serves the app shell; the service worker reaches **ACTIVATED**; the page is
  **CONTROLLED** after one reload
- `admin-driver-ui.js` and `midwest-stack-authority.js` are each injected **and fetchable as
  script** — HTTP 200, `text/javascript`
- the precache is the current generation, `freightlogic-24.0.26`, carrying all **22** declared
  runtime assets
- after reload the driver shell renders five tabs and a visible Today surface, with no uncaught
  page errors
- with the network verifiably down: an uncached subresource miss returns `504 text/plain` rather
  than the HTML shell, a cached asset still serves as script, and a drifted `?v=` self-heals
- the cached app shell is a complete HTML document (61762 bytes, `text/html`), carries the driver
  tab-bar markup, and requests `?v=24.0.26`
- the worker recovers cleanly when the network returns
- exactly **one** generation cache survives — `freightlogic-24.0.26`. `freightlogic-share-v2` is
  also present and expected: it is `SHARE_CACHE`, not a generation.

**This run was push-triggered, four seconds after the merge, and it is still evidence.** That is
squarely inside the window this repository records nine push races in — but the rule those
occurrences produced is about a **FAILURE**. A run that observes the *previous* generation
mid-deploy proves nothing about the release. A push run that **passes** is the opposite case:
the gate derives its expected generation from source and asserts the precache **equals** it, so
`freightlogic-24.0.26` cannot be observed unless production is serving 24.0.26. The parity half
was re-dispatched rather than reasoned about, and it agrees.

### Prior observations, kept as history

- **24.0.25** — PR #277, merged `436d677`; governance-only #280 head `266d74e` changed no runtime
  bytes. Observed on that tree by live parity `35539669777` and production service worker
  `35539669806`, and again by re-dispatch at live parity `35542846195` (job `106163516058`) and
  production service worker `35542851411` (job `106163528152`), precache `freightlogic-24.0.25`.
- **24.0.24** — PR #275, merged `f75f9cc`. Live parity `35434716935` (job `105875325854`) and
  production service worker `35434719454` (job `105875332085`), precache `freightlogic-24.0.24`.

Each set is evidence for the exact tree its gate looked at, and for no other.

### Repository-side

`node scripts/verify-cloudflare-parity.mjs --static-only` is **PASS** at 24.0.26: CSP is
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

**Issue #278 remains OPEN, and a deployed generation does not close it.** The core v24.0.26
economics slice has merged, deployed and been observed by both gates above — but its later
accepted addenda and the independent Claude economics-audit / joint-consensus gate are not
complete. Nothing in this document closes #278, and a green runtime observation must not be read
as discharging an economics-authority review that has not happened. This is the same distinction
the chain draws everywhere else: delivery observed is not correctness certified.


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
