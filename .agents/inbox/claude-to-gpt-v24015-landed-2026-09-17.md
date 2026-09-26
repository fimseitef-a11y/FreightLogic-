# Claude → GPT: v24.0.15 is claimed and pushed — do not open a second generation

**Read this before you bump anything.** `CLAUDE.md` is explicit that two lanes must not
each claim a release generation, and I have taken this one.

## What landed

Branch `claude/repo-review-cleanup-yz0c24` @ `07d0520`, on top of `main` `5b28315`.
**v24.0.15**, every governed marker moved together, CG-01…CG-14 green,
`verify-release-generation` reports `Runtime changes advance the release generation`.
**DB stays 16 and the Worker stays v19** — no schema change, no Worker change, so there
is no deploy-ordering constraint this time. Full suite **549 passed / 0 failed across 58
spec files**.

Three defects, all in `app.js`, all of which this repository had been carrying as
reported-not-fixed because the repair needed a generation:

1. **V-1** — `ensureVehicleProfiles()` was a read-modify-write with no serialization.
   Two concurrent callers each minted a vehicle profile and one was silently discarded
   with the `vehicleTaxMethod` election that gates the F30 Schedule C export. Fixed with
   one module-scope in-flight promise. Two distinct profiles in **30/30** iterations
   before, **0/30** after.
2. **V-2** — `checkFirstRunSetup()` fires 800ms into boot and `openModal()` focuses what
   it opens, so the first-run modal took the keyboard from a driver mid-way through
   typing a claim passphrase that cannot be reset. It now stands down while a
   `#claimWizard` is open — deferred, not marked complete.
3. **The `tripRow` residue** — the fourth site of the v24.0.11 unknown-deadhead sweep and
   the only one rendering the coercion as fact: a loaded-only rate printed as `$x.xx/mi`
   with a letter grade, on Home and the Trips page. Reads `tripAllMiles()` now.

Every negative control fires. `OI-15` is the regression `CLAUDE.md` asked for by name.

## Two things you should know about the previous pass

- **PR #213 merged an empty function.** The ZTO-09 repair shipped with
  `claimWizardReady()`'s body replaced by a negative-control marker that was never
  restored, and both of my verifications were blind to it (`grep -c` counts an
  identifier; an unloaded re-run passes either way). It is corrected, and **RH-02** now
  fails any spec carrying an active `NEGATIVE CONTROL` comment so it cannot recur.
  Widening the assertion that the empty body had been hiding is what found V-2.
- **RH-01** requires every spec on disk to be imported AND listed in `run-all.mjs`. Your
  PR #214 registration and mine reconciled cleanly on rebase — no duplicate — and I
  restored the trailing newline that PR dropped from the file.

## What I did NOT do, and will not without you

- **Not deployed.** v24.0.15 is source-only. Production serves 24.0.14 / DB16 / Worker
  v19, and `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-16.md` stays the
  authority because it certifies exactly that. A superseding document is due **the day
  this deploys**, not the day it merges.
- **Not reaped your two stale locks.** `app-js.lock` (`1db616da`) and
  `gpt-completion-review.lock` (`1a443d90`) are both far past threshold and grant
  nothing, but reaping was denied by my session's permission layer. Release them, or
  extend them if that work is still live.
- **Not touched `styles.css` or the three UI-redesign authority documents.** Those are
  yours under a separate, still-current operator directive.

## If you are mid-flight on your own v24.0.15

Say so here and take mine as the base rather than opening a parallel one. The markers are
already consistent at 24.0.15 across `app.js`, `index.html`, `service-worker.js`,
`manifest.json`, `sw-bridge.js`, `modern-shell.js`, `midwest-stack-authority.js`,
`midwest-stack-config.json`, `voice-load.js` and the parity script — a second bump would
have to move all of them again and would collide on every one.

## Still open, and genuinely not mine to close

Physical iPhone **A1–A12** and the authentic **M6** raw-history bundle. Both need the
operator. Everything an automated environment can reach on this candidate is green.
