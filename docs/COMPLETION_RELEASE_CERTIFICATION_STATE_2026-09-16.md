# Completion release certification state — v24.0.14 / DB16 / Worker v19

Date: 2026-09-16
Supersedes: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-15.md`
Status: **HOLD — EVERY AUTOMATABLE AND LIVE-ORIGIN GATE IS OBSERVED AND PASSING ON THIS CANDIDATE. THE SAME TWO GATES REMAIN: PHYSICAL-iPHONE EVIDENCE (A1-A12), AND THE PRIVATE M6 HISTORY BUNDLE.**

This document is the certification authority. Every earlier state and addendum document is
historical evidence and must not be read as the current candidate.

> **Not a live test queue.** On 2026-09-16 the operator deferred the physical-device gate
> (A1-A12) and the M6 private-history reconciliation to the **final post-v24.5 candidate**.
> **24.0.14 is not the certification candidate**, and the two open gates below are not
> awaiting imminent testing. See `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` before acting
> on the HOLD or on any open row in `FIELD_TEST_CHECKLIST.md`.

## Why this document exists

The document it supersedes certified **24.0.12 / Worker v17**. Production now serves
**24.0.14 / DB16 / Worker v19** — three app generations and two Worker generations further
on. Four shipped-file releases landed in between (24.0.13 zero-token onboarding with Worker
v18, then 24.0.14 with Worker v19), and no superseding state document was written for any of
them.

**That is the exact failure the superseded document itself describes, suffered again, by the
same number of generations.** Its own §"Why this document exists" records that
`FIELD_TEST_CHECKLIST.md` stopped carrying its own copy of the candidate SHA to stop it going
stale, and that doing so *relocated* the staleness into the document the checklist points at.
It then names the consequence precisely: *"a tester following the checklist would have been
sent to certify a candidate three generations behind what production serves."* That sentence
described the situation this document corrects, written before it happened.

The anti-drift move — one SHA, in one place, read at test time — remains right. What it
requires is the rule that document already states and that this one restates as the first
line of its own close-out: **a superseding certification document is due the day a shipped
file deploys, not the day it merges, and not whenever somebody notices.**

## Exact candidate

- FreightLogic app / PWA / service-worker generation: **24.0.14**
- IndexedDB schema: **16** (`tripRecords` stable internal trip identity; legacy `trips`
  retained for rollback)
- backup/API Worker: **19**, deployed and live
- Production app origin: `https://freightlogic-v2.fimseitef.workers.dev`
- Production backup/API Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`
- Runtime candidate SHA: **`8f90725`** (`main`)

## What is OBSERVED on THIS candidate

| Gate | Result | Evidence |
|---|---|---|
| Live all-asset Cloudflare parity | **PASS** | run `35087770010`, `workflow_dispatch` on `main` @ `8f90725` |

That run is the load-bearing one for this document. The verifier's `EXPECTED` block at that
SHA is `serviceWorkerVersion: "24.0.14"`, `manifestName: "FreightLogic v24.0.14"`,
`workerVersion: "19"`. The gate fails the job on anything but `PASS`, and `UNOBSERVED`
(exit 2) is also non-zero — so a success is a **positive observation** that production serves
those generations, not an absence of complaint.

## What is carried forward, and from which candidate

These were observed on an earlier candidate and are carried forward **named as such**, not
re-claimed as observations of `8f90725`. Anything whose behaviour a later generation could
have changed is listed here rather than in the table above, deliberately.

| Gate | Result | Observed on |
|---|---|---|
| Authenticated Worker contracts (authority + backup/delta/rotation) | PASS | Worker v17 era, run `34884786623` |
| Live invite/claim contract (**B7**) | PASS | Worker v19, run `35049144080` @ `72ab81e` |
| Production service worker / offline behaviour | PASS | 24.0.12, run `34939417958` |
| Six-width visual acceptance (320/375/390/393/430/440, both themes) | PASS | `integration/six-width-layout.spec.mjs` |
| Rollback / fix-forward evidence | PASS | `scripts/verify-rollback.mjs`, derived per-run |

**B7 is the one gate on this list observed against Worker v19 itself**, which matters because
v19 is the generation that touches driver-token storage. The zero-token onboarding flow
reached production with no live verification of any kind: the offline spec proves the contract
against the real fetch handler with an in-memory KV, and every pre-existing live gate predates
`/admin/invites` and `/claim`. That left the only flow in the app that **mints a credential**
unobserved in production. `scripts/verify-live-invite-claim.mjs` closes it and runs inside
`Verify Authenticated Worker` after every dispatched Worker deploy.

**The production service-worker and authenticated-Worker gates should be re-observed on
`8f90725`.** Neither is known to be broken; both simply have not been run against this
candidate, and this document will not record an inference as an observation.

## The push-race, recorded again because it recurred again

A parity or production-service-worker run triggered by the **push** that merges a release
observes the *previous* generation still being served, because Cloudflare has not finished
deploying. Those FAILUREs are real evidence about the origin at that instant and are **not**
evidence about the release. Re-dispatch and record the later run; do not dismiss the first one
and do not cite it.

This has now happened at 24.0.10, 24.0.12 and 24.0.13. It is a property of the pipeline, not
a defect to be fixed by ignoring it.

## Still HOLD — exactly two things

Both are **deferred by the operator's 2026-09-16 decision** to the final post-v24.5
candidate, not queued against this one. HOLD here means deferred by decision, not blocked
on unfinished work — `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` records the rationale and
the conditions under which the deferral lifts. The facts below are unchanged and remain
accurate; only the schedule is stated elsewhere.

- **Private-history reconciliation.** The five raw M6 files are not in this repository and
  have not been mounted in any session. The instrument is committed and ready; only the data
  is missing. Reconstructing the bundle from summaries would test the summary, not the source,
  which is the one thing this gate exists to catch.
- **Physical iPhone A1-A12.** Safe-area insets, the software keyboard, background GPS across a
  real lock/unlock, iOS permission revocation mid-trip, installed-PWA update behaviour, a
  genuine Airplane Mode round trip including the offline navigation the production SW gate
  declines to claim, the iOS 27 / Safari 27 SVG and select pass (A11), and **A12** — whether a
  claim performed in Safari survives **Add to Home Screen** or whether that install is a
  separate storage partition. If it is separate, the re-claim path is the recovery and must be
  walked end to end, confirming the owner still sees **one** driver with their backup count
  intact.

Nothing in this document instructs a reinstall or a website-data clear. That would destroy
local IndexedDB evidence, and under DB16 it would also destroy the only copy of the retained
legacy `trips` store that makes the trip-identity migration reversible.

## The rule this document is bound by

If a shipped file changes, the candidate section above must be updated and the live gates
re-observed. A superseding document is due **the day that candidate deploys**. A document that
describes a candidate production no longer serves is not merely out of date — it actively
misdirects the one gate that still requires a human, which is the whole reason the release is
on HOLD.
