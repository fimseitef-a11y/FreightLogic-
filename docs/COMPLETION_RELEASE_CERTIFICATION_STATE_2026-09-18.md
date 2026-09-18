# Completion release certification state — production 24.0.19 / DB16 / Worker v20

Date: 2026-09-18
Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-17.md, COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-12.md
Status: **HOLD — every automatable and live-origin gate is OBSERVED and PASSING on this candidate, on BOTH generations. Exactly one gate remains: physical iPhone A1-A12, deferred by the operator's 2026-09-16 decision to the final post-v24.5 candidate.**

This document is the certification authority. Every earlier state and addendum document is
historical evidence and must not be read as the current candidate.

> **Not a live test queue.** The operator's 2026-09-16 decision deferring the physical-device
> gate (A1-A12) to the **final post-v24.5 candidate** still stands. See
> `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` before acting on the HOLD or on any open row in
> `FIELD_TEST_CHECKLIST.md`. The M6 private-history gate is **no longer** part of that wait — see
> "Gate C" below.

## Why this document exists

Issue **#244**. The document it supersedes certified **24.0.15 / Worker v19** and recorded #224
as OPEN. Since it was written, three things happened and none of them left a superseding record:

1. Worker **v20** deployed and was verified.
2. App **24.0.19** deployed and was observed live — the first fully-green live parity in the
   whole v24.0.x line, because it is the first time source and production agreed on *both*
   generations at once.
3. **#224**, **#240** and **#221** closed.

That is the same lapse the superseded document was itself written to correct, one generation on,
and it is the seventh time this repository has recorded it against itself. The rule has not
changed and is restated at the bottom: **a superseding record is due the day a shipped file
deploys, not the day it merges, and not whenever somebody notices.** Merging leaves a commit;
deploying leaves nothing, which is the entire mechanism.

**No quiet overwrite.** The superseded documents are accurate about the candidates they describe
and are left intact as evidence. This document does not re-claim their observations; anything
observed on an earlier candidate is carried forward **named as such**.

## Exact candidate — what production serves

- FreightLogic app / PWA / service-worker generation: **24.0.19**
- IndexedDB schema: **16** (`tripRecords` stable internal trip identity; legacy `trips` retained
  for rollback)
- backup/API Worker: **20**, deployed and live
- Declared runtime assets: **22** (Voice Load removed in v24.0.17 by operator decision, #230 — a
  404 for `voice-load.js` is the removal working, not a failed deploy)
- Production app origin: `https://freightlogic-v2.fimseitef.workers.dev`
- Production backup/API Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`
- Generation observed at SHA: **`eac5994`**
- `main` has since advanced to **`cb0e64c`**. No declared runtime asset differs between the two —
  the diff is workflows, tests, documentation and `field-certification.js`, which is served but
  is not one of the 22 declared runtime assets and carries no governed marker. The generation
  observation therefore still describes `cb0e64c`, and the push-triggered parity on `cb0e64c`
  agrees (below).

## What is OBSERVED on THIS candidate

| Gate | Result | Evidence |
|---|---|---|
| Worker v20 deploy | **PASS** | run `35291404482`, `main` @ `eac5994` |
| Authenticated Worker contracts (authority, backup/delta/restore, invite/claim **B7**) | **PASS** | run `35291452993` — authority 5/0, backup/delta/restore 21/0, invite/claim 12/0 |
| Live all-asset Cloudflare parity | **PASS** | run `35291475396`, `workflow_dispatch` @ `eac5994`, job `105435050613` |
| Live all-asset parity on current `main` head | **PASS** | run `35293596465`, push @ `cb0e64c` |
| Production service worker / offline behaviour | **PASS** | run `35293596430` @ `cb0e64c` |
| Full Playwright suite | **PASS** | run `35293596434` @ `cb0e64c` |

The parity job is the load-bearing one. `VERDICT: PASS` reports `app.js`, `sw-bridge.js`, the
service worker, `modern-shell.js` and the manifest all at **24.0.19**; `index.html` does **not**
reference `voice-load.js` (the inverted #230 assertion, observed live rather than asserted
statically); Worker `/health` returning `{"ok":true,"version":"20"}`; all **22** declared runtime
assets loading with none served as an HTML fallback; CSP byte-identical between `index.html` and
`_headers`; and **20** repository-only paths confirmed non-public — which is Issue **#228**'s LIVE
half, the condition that section had been waiting on.

That gate fails the job on anything but PASS, and `UNOBSERVED` (exit 2) is also non-zero, so a
success is a **positive observation** that production serves those generations rather than an
absence of complaint.

**B7 is now observed against Worker v20 itself**, which matters because v20 is the generation
that changed the driver-auth path B7 exercises (#221's canonical-user token authority).

## What is carried forward, and from which candidate

Observed on an earlier candidate and carried forward **named as such**, not re-claimed as
observations of this one.

| Gate | Result | Observed on |
|---|---|---|
| Six-width visual acceptance (320/375/390/393/430/440, both themes) | PASS | `integration/six-width-layout.spec.mjs` |
| Rollback / fix-forward evidence | PASS | `scripts/verify-rollback.mjs`, derived per-run |

## The automatable gates that closed since the superseded document

- **#224 — harness readiness.** Root-caused rather than cleared by a rerun, and the root cause
  was in the repair itself: `page.waitForFunction` evaluates its predicate and tests the
  **result** for truthiness without awaiting it, so an `async` predicate always returned a
  truthy Promise and readiness resolved after exactly **one failed probe**. Measured against the
  real Playwright build (`HR-06`: 67 ms against a predicate that cannot settle for 3000 ms), not
  deduced. `HR-08`/`HR-09`/`HR-10` implement the three probe states the issue's acceptance
  contract names, and all three fail against the pre-fix form. `HR-07`'s control does **not**
  fire, which is recorded rather than glossed: the window is short on a fast host, which is
  exactly why #224 presented as an intermittent CI failure.
- **#240 — "Synced" over unsynced data.** Closed by v24.0.19, which is the generation now live.
- **#221 — Worker trust boundary.** Closed by the v20 deploy above.
- **SQ-10** was a genuine flake and it was ours, not the product's. It was root-caused to a
  second actor (the boot `resumeSyncIfPending()` drain racing the fixture's own push) rather
  than re-run: 5 consecutive runs 20/0 afterwards, and the negative control still fires.

## Gate C — M6 private-history reconciliation: RAN, all six criteria PASS

This gate was blocked on **access**, not on anything physical. The operator supplied the five raw
2026-08-27 files on 2026-09-18 and it ran end to end. Raw rows stay outside this repository; only
the non-sensitive structural result is recorded, here and in `FIELD_TEST_CHECKLIST.md` section C.

Authenticity was established on **independent** evidence rather than the supplier's manifest: the
216 source rows and 149 candidate records both reproduced exactly on a run with no access to the
earlier one, the two documented per-file counts matched independently, and the manifest's
SHA-256 for all five files matched the bytes present. That is what distinguishes this from the
reconstruction the gate exists to catch.

`verify-history-bundle`: 0 blocking, 0 warnings, 5/5 files, 216 rows. `m6-import`: 149 records.
All six criteria verified against the produced records rather than assumed — no invented broker
identity, no unsupported WON/completed promotion, no UNKNOWN-to-zero coercion (deadhead `null` on
141, positive on 8, **zero** zeros), preserved source timestamps and semantics, no collapse of
distinct shipments sharing an external ID, and a byte-identical deterministic re-import.

**What this does NOT close, and is not claimed:**

- The separate **125-row 2026-08-24 master CSV is not in this bundle** (the supplied README says
  so) and must not be reconstructed from summaries.
- **Adoption still requires the conflict review.** This run produced the candidate set and its
  evidence; it adopted nothing.
- **One judgement call is flagged rather than absorbed:** a single `in_progress` row carries
  `awarded: true`. It is defensible — awarded means the bid was won, not that delivery finished,
  and its execution is `NOT_STARTED` — but it is the one award resting on reading the status that
  way, and the operator should confirm it before adoption.

## Still HOLD — exactly one gate

- **Physical iPhone A1-A12.** Safe-area insets, the software keyboard, background GPS across a
  real lock/unlock, iOS permission revocation mid-trip, installed-PWA update behaviour, a genuine
  Airplane Mode round trip including the offline navigation the production SW gate declines to
  claim, the iOS 27 / Safari 27 SVG and select pass (A11), and **A12** — whether a claim performed
  in Safari survives **Add to Home Screen** or whether that install is a separate storage
  partition. If it is separate, the re-claim path is the recovery and must be walked end to end,
  confirming the owner still sees **one** driver with their backup count intact.

  Deferred by the operator's 2026-09-16 decision to the final post-v24.5 candidate, on its own
  rationale: five of the twelve rows measure surfaces the v24.5 redesign rewrites, so running
  them now would certify a build that is about to be replaced. HOLD here means **deferred by
  decision**, not blocked on unfinished work.

  The field-certification runner (`field-certification.html` / `field-certification.js`, PR #227,
  extended in PR #243) structures the evidence; it does **not** replace the device. No row may be
  promoted to PASS without the real iPhone observation it names, and no automated observation —
  however green — may close a hardware-only row.

Nothing in this document instructs a reinstall or a website-data clear. That would destroy local
IndexedDB evidence, and under DB16 it would also destroy the only copy of the retained legacy
`trips` store that makes the trip-identity migration reversible.

## The supersession chain is now one document deep, and that is a repair

Until this document, `scripts/m7-certify.mjs` resolved **seven** documents as "current" when only
one should have been. The resolver compares a `Supersedes:` value against a bare basename, and
every real document writes it as `` `docs/NAME.md` `` — backticked and directory-prefixed —
because that is what reads correctly as prose. Every such reference was inert.

It cost nothing while every document held, which is exactly why it survived: the runner still
returned HOLD, by a different route, and the document it *named* as the source was right by
accident of sort order. The day one of them was meant to clear, six stale HOLDs would have held
the release. This was noticed once before and worked around in prose rather than fixed — the
2026-09-12 addendum exists partly to close a branch "left by the 2026-09-03 record's
path-formatted supersession value."

The parser now normalizes the reference; the historical documents are untouched, which is what
blocker 5 requires. `tests/unit/m7-runner-semantics.spec.mjs` **M7-11** asserts it using the exact
form the real documents use, and fails when the normalization is reverted while **M7-06** — whose
fixture writes bare filenames, the one form the repository does not use — stays green. That is
why M7-06 could never have caught it.

This document supersedes the orphaned 2026-09-12 addendum along with the 2026-09-17 state, so the
chain resolves to exactly one current document.

## The push-triggered parity race — still a property of the pipeline

A parity or production-SW run triggered by the **push** that merges a release fires seconds after
the merge and observes the *previous* generation still being served, because Cloudflare has not
finished deploying. Those FAILUREs are real evidence about the origin at that instant and are
**not** evidence about the release. Re-dispatch and record the later run; do not dismiss the first
one and do not cite it.

Recorded at 24.0.10, 24.0.12, 24.0.13, 24.0.17 and twice more. It did **not** occur on `cb0e64c`,
because that merge changed no runtime asset and so had nothing to wait for — which is the
mechanism confirming itself rather than an exception to it.

A re-dispatch that fails **the same way** is evidence, not a race. That distinction is what made
the v24.0.17 Worker-generation mismatch a real finding instead of a seventh race.

## The rule this document is bound by

If a shipped file changes, the candidate section above must be updated and the live gates
re-observed. A superseding document is due **the day that candidate deploys**. A document that
describes a candidate production no longer serves is not merely out of date — it actively
misdirects the one gate that still requires a human, which is the whole reason the release is on
HOLD.

This is the third consecutive document written to correct that exact lapse. The lapse is not
inattention; it is that deploying leaves no commit. Until something in the pipeline writes the
observation down automatically, the superseding document is part of the deploy, not part of the
merge.
