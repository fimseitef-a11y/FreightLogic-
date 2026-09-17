# Certification deferral — physical-device gate (A1-A12) and M6 private history

Date: 2026-09-16
Decided by: the operator
Applies to: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-16.md` (app **24.0.14** /
DB **16** / Worker **v19** / SHA **`8f90725`**, deployed and live)

**24.0.14 is NOT the certification candidate.** The physical-device gate and the M6
private-history reconciliation are **deferred by an explicit operator decision** to the
final post-v24.5 candidate. Neither is awaiting imminent testing, and neither is a lapse,
an oversight, or work anyone has forgotten to schedule.

Read this document before acting on the HOLD in the 2026-09-16 certification state, or on
any A-section row in `FIELD_TEST_CHECKLIST.md`. Those documents remain accurate about
*what* is unobserved; this one is authoritative about *why*, and about **when** the gate
runs.

## The decision

1. The physical-iPhone gate **A1-A12** runs **once**, against the **final post-redesign
   candidate** — not against 24.0.14, and not against any intermediate generation.
2. The M6 private-history reconciliation is **unchanged**: still blocked on locating the
   five raw 2026-08-27 files, and still deferred to the same final candidate.
3. The release remains **HOLD**, truthfully. Here HOLD means *deferred by decision*, not
   *blocked on unfinished work*.

## Rationale — device evidence against 24.0.14 expires when the redesign merges

The v24.5 redesign (`UI_BRIEF_V24.5.md`, `FreightLogic_UI_Reference.html`) rewrites the
surfaces that five of the twelve A-rows exist to observe. This is not a guess about scope;
it is what those rows measure:

| Row | What it observes on the device | Rewritten by v24.5 |
|---|---|---|
| **A1** | Shell identity — that the primary shell is Today / Loads / Evaluate / Trips / Money and More still exposes the secondary surfaces | Yes — shell, navigation and screen composition |
| **A3** | Production opportunity intake through the shipped UI | Yes — the centre ⚡ action reuses Unified Load Intake, and its surface changes |
| **A9** | Doctrine / geography / cargo-fit / profit sanity **as rendered by the evaluator** | Yes — evaluator UI |
| **A10** | The pickup-feasibility gate's CAN'T TAKE card, ahead of economics, in the evaluator | Yes — evaluator UI |
| **A11** | The hand-built F31 SVG chart, the five tab-bar icons, every select, and zoom-on-focus at <16px computed size | Yes — chart, tab icons and selects are all in scope |

A device PASS is a statement about rendered pixels, real touch targets, a real software
keyboard and a real WebKit. It is not transferable across a redesign of the thing being
rendered. So A1, A3, A9, A10 and A11 gathered against 24.0.14 stop being evidence on the
day the redesign merges — which means running the gate now is committing to running it
twice, and asking the operator to certify a build that is already scheduled to be replaced.

The remaining rows (A2, A4-A8, A12) are less exposed to the redesign, but they are **not
split out and run early**. Three reasons, in order of weight:

- **A1 is a prerequisite in practice.** Every other row is performed against an installed
  app whose identity A1 establishes. A partial run records rows against a generation A1
  never certified.
- **The certification record is per-candidate, not per-row.** `FIELD_TEST_CHECKLIST.md`
  states plainly that source, deployment-build, preview, desktop, or older-generation
  evidence is never converted into a physical-device PASS. A half-filled A-section against
  a superseded generation is exactly the "evidence for the wrong candidate" failure this
  repository has already recorded against itself at 24.0.9, 24.0.11 and 24.0.12.
- **A12 cannot run early anyway on its own terms.** Its prerequisite is that both the
  Worker and the app carrying invite/claim are deployed, and its substance — whether a
  claim performed in Safari survives Add to Home Screen — is a storage-partition question
  about the *installed* app, which the redesign's install identity touches.

## What this does not change

- **The candidate is still real and still deployed.** Production serves 24.0.14 / DB16 /
  Worker v19. Every automatable and live-origin gate is observed and passing on it. The
  deferral is about the human gate, not about the build's health.
- **The rule that a superseding certification document is due the day a shipped file
  deploys is untouched.** Deferring the device gate is not permission to let the
  certification chain go stale again; that is a separate discipline and it still applies to
  every deploy between now and the final candidate.
- **The M6 instrument stays committed and untouched** — `scripts/m6-import.mjs`, its
  adapter, and `tests/integration/batch-b-m6-reconciliation.spec.mjs`. Only the data is
  missing. Reconstructing the bundle from summaries would test the summary, not the source,
  which is the one thing that gate exists to catch.
- **Nothing here instructs a reinstall or a website-data clear.** That would destroy local
  IndexedDB evidence, and under DB16 it would also destroy the only copy of the retained
  legacy `trips` store that makes the trip-identity migration reversible.

## What a future session must not conclude

- Do **not** read the current certification state document as a live test queue. Its
  "Still HOLD" section is accurate about the facts and silent about the schedule; this
  document supplies the schedule.
- **Superseded pointer (2026-09-17):** this document was written against
  `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-16.md` (app 24.0.14 / SHA
  `8f90725`). The current authority is
  `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-17.md` (production 24.0.15 /
  `ee07297`). **The deferral itself is unchanged** — the operator's decision is about the
  final post-v24.5 candidate, not about any particular interim generation, so a new
  production generation does not expire it. Only the document it points at moved.
- Do **not** read `FIELD_TEST_CHECKLIST.md`'s open A-rows as work due now. The instrument is
  ready and correct; it is deliberately not being run yet.
- Do **not** treat the deferral as closing either gate. A deferred gate is open. The release
  is not certifiable, and `scripts/m7-certify.mjs` reporting `NOT CERTIFIABLE` alongside
  clean automated gates remains the correct pairing.
- Do **not** open a partial device run to "make progress." A partial A-section against a
  superseded generation is worse than none: it reads as evidence and is not.

## When the deferral lifts

When the post-v24.5 redesign candidate is deployed and a superseding certification state
document names it. At that point:

1. `FIELD_TEST_CHECKLIST.md` is re-verified against the new shell before testing — A1, A3,
   A9, A10 and A11 describe surfaces that will have changed, and a checklist describing the
   old ones would send the tester to certify something that no longer exists.
2. A1-A12 runs once, end to end, on that candidate.
3. M6 runs if and only if the five raw files have been located.
