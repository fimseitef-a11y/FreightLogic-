# Completion release certification state — v24.0.12 / Worker v17

Date: 2026-09-15
Supersedes: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-14.md`
Status: **HOLD — EVERY AUTOMATABLE AND LIVE-ORIGIN GATE IS OBSERVED AND PASSING ON THIS CANDIDATE. THE SAME TWO GATES REMAIN: PHYSICAL-iPHONE EVIDENCE, AND THE PRIVATE M6 HISTORY BUNDLE.**

This document is the certification authority. Every earlier state and addendum document is historical evidence and must not be read as the current candidate.

## v24.0.13 supersession notice (added with the zero-token onboarding work)

**This document certifies 24.0.12 / Worker v17, which is what production serves. It does
NOT certify 24.0.13 / Worker v18, and nothing in it should be read as doing so.**

Shipped files changed again after this document was written: v24.0.13 "Zero-Token
Onboarding" moves the app generation and the Worker generation together. By this
document's own standing rule — *if a shipped file changes, the candidate section must be
updated and the live gates re-observed* — a superseding certification state document is
due **the day 24.0.13 deploys**, not the day it merges.

Until that happens the position is:

- Every gate recorded below remains valid evidence about **24.0.12 / v17**, the candidate
  production is actually serving. None of it is evidence about 24.0.13.
- 24.0.13 is **source-only**. Its suite, static parity, cache-generation and
  release-generation gates are green in-repo, which is a source claim, not a live one.
- Two deploys are outstanding and **ordered**: Worker **v18 first**, then the app. The
  app's invite and claim flows call `POST /admin/invites` and `POST /claim`, neither of
  which exists on the deployed v17, so shipping the app first leaves the owner an Invite
  button that 404s and a driver holding a link that cannot be redeemed.
- After both deploys, **re-dispatch** live parity and the production service-worker gate
  rather than citing the push-triggered runs; a push-triggered run races the Cloudflare
  deploy, and its FAILURE is evidence about the origin at that instant, not the release.
- The physical-iPhone gate widens to **A1-A12**. A12 is the new one, and it carries the
  question no automated environment can answer: whether a claim performed in Safari
  survives **Add to Home Screen**, or whether the installed app is a separate storage
  partition. If it is separate, the re-claim path is the recovery and must be walked end
  to end, confirming the owner still sees **one** driver with their backup count intact.

**One gate was ADDED after 24.0.13 deployed, because the deploy exposed a hole
nobody had listed.** `/admin/invites` and `/claim` went live with no production
verification of any kind: the offline spec proves them against the real fetch handler
with an in-memory KV, and every existing live gate predates the endpoints. That left
the only flow in the app that mints a credential unobserved in production, which is
the worst place in this system to have an unobserved contract. `B7` in
`FIELD_TEST_CHECKLIST.md` and `scripts/verify-live-invite-claim.mjs` close it; the
verifier runs inside `Verify Authenticated Worker` after every dispatched Worker
deploy, and carries the same three-verdict discipline as the other live gates, so an
unreachable origin can never be recorded as evidence the contract holds.

The HOLD is unchanged and is now three things rather than two: the private M6 history
bundle, the physical-iPhone gate, and — for 24.0.13 specifically — a deploy that has not
happened and live gates that have not been observed.

## Exact candidate

- FreightLogic app / PWA / service-worker generation: **24.0.12**
- IndexedDB schema: **15**
- backup/API Worker: **17**, deployed and live
- Production app origin: `https://freightlogic-v2.fimseitef.workers.dev`
- Production backup/API Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`
- Runtime candidate SHA: **`4f2daf22819feb8d7aeba40324e53ce971f22418`**

## Why this document exists

The 2026-09-14 state document named **24.0.10** at `fb4fe119cced5bc938bd13d3c2aa877ad92cc308`, and closed with an explicit rule: *"If a shipped file changes, this section must be updated and the live gates re-observed."*

Shipped files changed twice since — v24.0.11 (`fb408a0`, the OMEGA economics continuation) and v24.0.12 (`4f2daf2`, the OI-11/OI-14/CG-14 regression and marker pass). The candidate was therefore **two generations stale**, and this is the document its own rule required.

That staleness was not inert. `FIELD_TEST_CHECKLIST.md` deliberately stopped carrying its own copy of the candidate SHA — precisely to stop it going stale — and instead points a tester at this document. With this document at 24.0.10, that indirection relocated the drift rather than removing it: a tester following the checklist on 2026-09-15 would have been sent to certify a candidate three generations behind what production serves. The anti-drift move was right; it just needs the document it defers to kept current, which is what the rule above is for.

## What changed since the 2026-09-14 state document

### v24.0.12 is deployed, and that is now observed rather than assumed

At the time v24.0.12 merged, `CLAUDE.md`, `FIELD_TEST_CHECKLIST.md` and `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` all recorded — correctly, at the time — that it was **source-only, not deployed, not observed live**, and that the parity run must be re-dispatched after the deploy because a push-triggered run races Cloudflare.

That re-dispatch happened and both live gates passed. The three documents were not updated to match, so all three were still asserting "not deployed" about a generation production had been serving for over an hour. They are corrected in the same change that lands this document.

### 1. Live all-asset production parity — **PASS**

`Verify Live Parity` run **`34939229143`**, `workflow_dispatch` on `main` @ `4f2daf22819feb8d7aeba40324e53ce971f22418`, 2026-09-15T06:56:35Z. `VERDICT: PASS`.

Observed from the production origin, not inferred from a build:

- `sw-bridge` imports `modern-shell.js` **v24.0.12**, and the service worker precaches it at that generation;
- the manifest name is **`FreightLogic v24.0.12`**;
- the Midwest overlay loads and exposes `FreightLogicMidwestStack`; the modern shell loads and exposes `FreightLogicModernShell`;
- the SW critical shell still carries `midwest-stack-authority.js` and `vendor/xlsx.full.min.js`, and still does not precache the removed rate-overrides JSON;
- Worker `/health` returns `{"ok":true,"version":"17"}`;
- the admin endpoint rejects an unauthenticated request with 401;
- **all 23 declared runtime assets load from the app origin**, and **none is served as HTML** — the SPA-fallback shape that masks a miss with a 200 the browser then refuses to execute.

### 2. Production service-worker / offline behaviour — **PASS**

`Verify Production Service Worker` run **`34939417958`**, `workflow_dispatch` on `main` @ the same SHA, 2026-09-15T06:59:25Z. **16 checks, 0 failures**, `VERDICT: PASS`, against a real headless Chromium driving the production origin.

- the worker reaches ACTIVATED and the page is CONTROLLED after one reload;
- `admin-driver-ui.js` **and** `midwest-stack-authority.js` are injected AND fetchable as script — HTTP 200, `text/javascript`. This is the 2026-09-13 defect (a tag pointing at a 404) confirmed still closed in production at this generation, on the axis a markup check cannot see;
- the precache is **`freightlogic-24.0.12`**, and all 23 declared assets are present in it;
- the cached shell is a complete 54068-byte HTML document carrying the driver tab bar and requesting **`?v=24.0.12`**;
- the driver shell renders five tabs and a visible Today surface with no uncaught page errors;
- with the network verifiably down against the running worker instance, a subresource miss returns **504 `text/plain`** and never the HTML shell, and a drifted `?v=` on a known asset self-heals to the real file;
- it recovers cleanly when the network returns, and **exactly one generation cache survives** (`freightlogic-share-v2` is present and is correctly not counted as a generation).

**It states its own limit, unchanged from the 09-14 document:** the offline *navigation* is not observed there, because a navigation restarts the service worker outside the network emulation that covered its predecessor. On a real device that is checklist item **A4**.

### 3. Full automated suite green on the candidate — **PASS**

`Tests` run **`34938834977`**, push on `main` @ `4f2daf2`: green. The candidate's own PR head (`aaa3569`, PR #202) ran **483 passed / 0 failed across 52 spec files** in run `34933327774`.

### 4. The push-race is recorded, and must not be cited

Both live workflows also fired on the push at 06:51Z and both **FAILED**: `34938834929` (live parity) and `34938834924` (production service worker), roughly five minutes before the dispatched runs above passed.

This is the documented pattern, not a new finding: a push-triggered run races the Cloudflare deploy, so it observes the *previous* generation still being served. Those FAILUREs are real evidence about the origin at that instant and are **not** evidence about the release. Re-dispatch and record the later run. Do not dismiss the first one and do not cite it.

### 5. Gates carried forward unchanged

These were observed on the 24.0.10 candidate and nothing since has touched the surfaces they cover. They are carried forward as stated, not re-claimed as fresh observations on this candidate:

- **Authenticated Worker authority + backup/restore/rotation** — run `34884786623`, 21 passed / 0 failed against the deployed Worker. The Worker is still **v17** and its source is unchanged since, so this remains current evidence for the component it covers.
- **Six-width visual acceptance** — `tests/integration/six-width-layout.spec.mjs`, in the suite on every PR and push, and green in run `34938834977` above.
- **Rollback / fix-forward** — `scripts/verify-rollback.mjs` derives the candidate and both generations rather than pinning literals, so it is current by construction. No path through it can name a safe rollback target. Approved policy remains **fix forward**.
- **W-01** — the same-millisecond backup/delta key collision, fixed at Worker v17 and deployed by run `34884719806`. CLOSED, with its residue unchanged: anything already lost to a collision before that deploy is unrecoverable, and nothing in the data identifies what is missing.

## Current blocking checklist

- [x] Exact live all-asset production parity on this candidate — run `34939229143`, PASS.
- [x] Production service-worker / offline behaviour on this candidate — run `34939417958`, 16/0, PASS.
- [x] Full automated suite green on this candidate — run `34938834977`.
- [x] Authenticated Worker authority + backup/restore/rotation — run `34884786623`, PASS (Worker v17, unchanged).
- [x] Six-width visual acceptance — PASS.
- [x] Rollback / fix-forward evidence — derived verifier, PASS.
- [ ] **Private operator-history reconciliation.** The recovered August 27 M6 bundle is not in this repository and has not been mounted in any session that has run so far.
- [ ] **Physical iPhone certification.** `FIELD_TEST_CHECKLIST.md` A1-A11 against this exact candidate, in Safari and as the installed Home Screen PWA.

## The two remaining gates, and why they are not closable from here

Unchanged from the 2026-09-14 document, and repeated rather than cross-referenced because a gate described only by pointer is a gate nobody reads.

**Private-history reconciliation** requires the five raw M6 files. Preflight evidence says 216 source rows deterministically produce 149 candidate records, but those candidates have never completed the application round trip, the repeated-import idempotence run, or the source-conflict review. The instrument is committed and ready (`scripts/m6-import.mjs`, the adapter, and `batch-b-m6-reconciliation.spec.mjs`); only the data is missing. **Do not reconstruct the bundle from summaries** — a reconstruction would test the summary, not the source, which is the one thing this gate exists to catch. The separate 125-row master is likewise unavailable and must not be synthesized.

**Physical iPhone certification** covers exactly what a headless runner cannot: safe-area insets, the software keyboard, background GPS across a real lock/unlock, iOS permission revocation mid-trip, installed-PWA update behaviour, and a genuine Airplane Mode round trip. A1-A11 are finite and written to be run in one sitting. A4's offline navigation is the specific thing gate 2 above declines to claim.

Neither is a reason to hold the other work. Both can be run in parallel with anything else.

## Candidate SHA

- **Runtime candidate SHA: `4f2daf22819feb8d7aeba40324e53ce971f22418`** — the `main` commit against which live all-asset parity and the production service-worker gate were both observed at generation 24.0.12. Confirm it against Diagnostics on the device before running A1-A11.
- Later `main` commits that change only documentation or verification tooling do not create a new runtime candidate, because they do not change a shipped file or the cache generation.
- **If a shipped file changes, this section must be updated and the live gates re-observed.** That rule is what this document exists to honour: it was written into the 09-14 document, two shipped-file releases went out, and nothing enforced it. The next generation needs a superseding document on the day it deploys, not whenever someone notices.

`FIELD_TEST_CHECKLIST.md` deliberately does not carry its own copy of this SHA, and should not be given one. The fix for the indirection going stale is keeping this document current, not duplicating the value into a second place that can disagree.

## Final rule

FreightLogic remains **HOLD**. Source completeness, green CI and a successful Cloudflare build were never sufficient, and still are not. But every gate that can be observed from an automated environment has been observed on the live production origin **at this exact generation** — not inferred, not assumed from a build, and not carried forward from an older candidate except where explicitly named as such in section 5.

The hold may be cleared only by a later authoritative certification document recording real physical-iPhone evidence and real private-history reconciliation on this same named candidate. Do not mark either PASS by inference. Do not clear Safari website data or delete the installed PWA to force an update: that destroys the local IndexedDB evidence the installed-origin investigation still needs.

## Addendum 2026-09-15 — the A-series grew by one

iOS 27 and Safari 27 shipped **2026-09-14**, one day before this candidate's live gates were observed. Safari 27 carries 525 fixes, 30 of them SVG, and WebKit characterises the release as existing features behaving differently — more correctly — than before.

FreightLogic renders hand-built SVG in two surfaces a driver looks at constantly: the F31 Earnings Trends chart (`<rect>` bars, a `<polyline>` overlay, `<text>` labels) and the driver tab-bar icons. **No gate in this repository can see a rendering change there** — the six-width spec asserts overflow and interactive geometry, the production service-worker gate asserts delivery and offline semantics. So `FIELD_TEST_CHECKLIST.md` gains **A11**, an iOS 27 regression pass, and the physical-device gate in this document is now **A1-A11**.

This does not change the candidate, the live evidence, or the HOLD. It widens the device gate, which is the half that was already open. `docs/IOS27_SAFARI27_ASSESSMENT_2026-09-15.md` is the full assessment, including the two Safari 27 APIs evaluated and declined with their inventories, and a correction to the circulating claim that iOS 27 adds Background Sync — it does not.
