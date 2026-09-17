# Completion release certification state — production 24.0.15 / DB16 / Worker v19

Date: 2026-09-17
Supersedes: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-16.md`
Status: **HOLD — production is 24.0.15 and observed. Issue #224 is OPEN, so `main` does NOT have all automatable gates green. The same two evidence gates remain and remain deferred by operator decision: physical-iPhone A1-A12, and the private M6 history bundle.**

This document is the certification authority. Every earlier state and addendum document is
historical evidence and must not be read as the current candidate.

> **Not a live test queue.** The operator's 2026-09-16 decision deferring the physical-device
> gate (A1-A12) and the M6 private-history reconciliation to the **final post-v24.5 candidate**
> still stands. See `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` before acting on the HOLD or on
> any open row in `FIELD_TEST_CHECKLIST.md`.

## Why this document exists

Issue **#225**. The document it supersedes certified **24.0.14**, and production has served
**24.0.15** since PR #223 merged and deployed. Repository prose still described 24.0.15 as
source-only and production as 24.0.14.

That is the drift the superseded document's own closing rule exists to prevent, and it names the
rule exactly: *a superseding document is due the day that candidate deploys.* It is written here
again, one generation on, because the failure mode is not that anyone doubts it — it is that
merging and deploying are separate events and only the merge has a commit.

**One generation, one correction, no quiet overwrite:** the superseded document is accurate about
24.0.14 and is left intact as evidence. This document does not re-claim its observations; gates
observed on an earlier candidate are carried forward **named as such** below.

## Exact candidate — what production serves

- FreightLogic app / PWA / service-worker generation: **24.0.15**
- IndexedDB schema: **16** (`tripRecords` stable internal trip identity; legacy `trips` retained
  for rollback)
- backup/API Worker: **19**, deployed and live
- Production app origin: `https://freightlogic-v2.fimseitef.workers.dev`
- Production backup/API Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`
- Runtime candidate SHA: **`ee07297`** (`main` at the time of the observation below)

## What is OBSERVED on THIS candidate

| Gate | Result | Evidence |
|---|---|---|
| Live all-asset Cloudflare parity | **PASS** | job `105095664502` on `ee07297` |
| Production service worker / offline behaviour | **PASS** | same SHA |
| Full Playwright suite | **NOT GREEN — see #224** | run `35188438111` attempt 1 failed 4; controlled rerun job `105100958820` failed 1 |

The parity job is the load-bearing one. It reports `index.html` referencing app / voice /
SW-bridge **24.0.15**, service worker **24.0.15**, manifest name `FreightLogic v24.0.15`, all
**23/23** declared runtime assets loading from the production app origin with none served as an
HTML fallback, and Worker `/health` at **v19** — `VERDICT: PASS`. That gate fails the job on
anything but PASS and `UNOBSERVED` (exit 2) is also non-zero, so a success is a **positive
observation** that production serves those generations rather than an absence of complaint.

## What is carried forward, and from which candidate

Observed on an earlier candidate and carried forward **named as such**, not re-claimed as
observations of `ee07297`. Anything whose behaviour a later generation could have changed is
listed here rather than in the table above, deliberately.

| Gate | Result | Observed on |
|---|---|---|
| Authenticated Worker contracts (authority + backup/delta/rotation) | PASS | Worker v17 era, run `34884786623` |
| Live invite/claim contract (**B7**) | PASS | Worker v19, run `35049144080` @ `72ab81e` |
| Six-width visual acceptance (320/375/390/393/430/440, both themes) | PASS | `integration/six-width-layout.spec.mjs` |
| Rollback / fix-forward evidence | PASS | `scripts/verify-rollback.mjs`, derived per-run |

**B7 remains the one gate on this list observed against Worker v19 itself**, which matters
because v19 is the generation that touches driver-token storage.

## The open automatable gate — issue #224

**`main` must not be described as having all automatable gates green.** The full Playwright suite
is not reliably green: `Cannot read properties of null (reading 'objectStoreNames')` at
`physicalFor`/`tx`, in specs that had already completed the harness readiness probe.

Work done on it, and its limits, are recorded in `tests/unit/harness-readiness.spec.mjs` and the
v24.0.16 section of `CLAUDE.md`. In summary:

- The failure **did not reproduce** in this environment. The full suite ran green on the first
  attempt, and targeted probes found no post-readiness re-bootstrap (idle page 0/8, weak-wait
  second tab 0/12, same under 20× CPU throttling 0/8). Per the issue this is **not** cleared by a
  rerun, so the root cause is unproven.
- 15 genuinely weak readiness waits were found and fixed — 13 of them a deliberate
  `page.reload()` followed by an `#appMeta`-only wait, which **is** the re-bootstrap-plus-weak-wait
  mechanism the issue deduces, written into the suite. Whether it is also the CI failure cannot be
  claimed: the CI failures were in specs that do not reload.
- Lifecycle diagnostics now print on any assertion failure, so the next CI occurrence arrives with
  evidence rather than prompting another rerun.

#224 stays OPEN. Nothing here should be read as closing it, and no release may be called
certifiable while it is open.

## The next candidate is not this one

**v24.0.16 is source-only: not deployed, not live-observed.** It carries the three trust-boundary
security repairs (#219, #221, #220) and Worker **v19 → v20**. When it deploys:

1. **Worker v20 goes first.** The app is unchanged in which endpoints it calls, but the CORS
   narrowing and the canonical-user token authority must be serving before the app generation
   lands — the same ordering v18 required for 24.0.13.
2. **Re-dispatch live parity after the deploy settles.** Do not cite the push-triggered run.
3. **Re-run `Verify Authenticated Worker`**, which carries B7, because v20 changes the driver
   auth path that B7 exercises. Do not dispatch it twice inside one clock hour — `/claim` is
   10/hr per IP and the gate spends up to 6 — and do not dispatch it while a Worker deploy is
   still landing. Both give UNOBSERVED, which is neither a pass nor a product failure.
4. **A superseding state document is due that day.** Not the day it merges.

## The push-triggered parity race — fifth recorded occurrence

A parity or production-SW run triggered by the **push** that merges a release fires seconds after
the merge and observes the *previous* generation still being served, because Cloudflare has not
finished deploying. Those FAILUREs are real evidence about the origin at that instant and are
**not** evidence about the release. Re-dispatch and record the later run; do not dismiss the
first one and do not cite it.

Recorded at 24.0.10, 24.0.12, 24.0.13 and twice since. It is a property of the pipeline, not a
defect to be fixed by ignoring it.

## Still HOLD — exactly two evidence gates, plus #224

Both evidence gates are **deferred by the operator's 2026-09-16 decision** to the final
post-v24.5 candidate, not queued against this one. HOLD here means deferred by decision, not
blocked on unfinished work — `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` records the rationale
and the conditions under which the deferral lifts. #224 is a separate, genuinely open gate and is
**not** covered by that deferral.

- **Private-history reconciliation (M6).** The five raw 2026-08-27 files are not in this
  repository and have not been mounted in any session. The instrument is committed and ready;
  only the data is missing. Reconstructing the bundle from summaries would test the summary, not
  the source, which is the one thing this gate exists to catch.
- **Physical iPhone A1-A12.** Safe-area insets, the software keyboard, background GPS across a
  real lock/unlock, iOS permission revocation mid-trip, installed-PWA update behaviour, a genuine
  Airplane Mode round trip including the offline navigation the production SW gate declines to
  claim, the iOS 27 / Safari 27 SVG and select pass (A11), and **A12** — whether a claim performed
  in Safari survives **Add to Home Screen** or whether that install is a separate storage
  partition. If it is separate, the re-claim path is the recovery and must be walked end to end,
  confirming the owner still sees **one** driver with their backup count intact.

  A field-certification runner for A1-A12 landed in PR #227 (`field-certification.html` /
  `field-certification.js`). It structures the evidence; it does not replace the device. No row
  may be promoted to PASS without the real iPhone observation it names.

Nothing in this document instructs a reinstall or a website-data clear. That would destroy local
IndexedDB evidence, and under DB16 it would also destroy the only copy of the retained legacy
`trips` store that makes the trip-identity migration reversible.

## The rule this document is bound by

If a shipped file changes, the candidate section above must be updated and the live gates
re-observed. A superseding document is due **the day that candidate deploys**. A document that
describes a candidate production no longer serves is not merely out of date — it actively
misdirects the one gate that still requires a human, which is the whole reason the release is on
HOLD.

This document is the second consecutive one written to correct that exact lapse. The lapse is not
inattention; it is that deploying leaves no commit. Until something in the pipeline writes the
observation down automatically, the superseding document is part of the deploy, not part of the
merge.
