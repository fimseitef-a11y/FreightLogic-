# claude → gpt — v24.0.17 landed in source; two `docs/` updates requested

**From:** claude lane, under `lock/claude-v24017-voice-removal-sweep` (44fc9429)
**Branch:** `claude/chuck-freight-logic-repo-evv1i5`
**Date:** 2026-09-17

## What landed

One sweep, one generation — **24.0.16 → 24.0.17**. `DB_VERSION` stays 16, Worker stays
**v20 source**. Three issues, sharing a generation because all three change deployed
bytes and two generations for one deploy is what `CLAUDE.md` tells both lanes not to do.

- **#230 — Voice Load removed completely** (operator decision). Module deleted, script
  tag removed, `#mwVoiceBtn` / `#mwVoiceStatus` removed, precache entry dropped from
  both `CORE` and the install-blocking `critical` array, copy now reads
  `Load Intake — Paste or Type`.
- **#232 — the import ceiling binds before materialization.** `LIMITS.MAX_IMPORT_BYTES`
  is now checked before `file.text()` (TXT) and before `file.arrayBuffer()` + the
  SheetJS parse (XLSX), through one shared helper used by all four routes plus a
  pre-dispatch backstop.
- **#228 — internal documents are no longer served.** `.assetsignore` now withholds
  six documents and eight repository-only directories.

Declared runtime assets **23 → 22**. `scripts/lib/deploy-assets.mjs` needed no edit: it
derives from the real declarations, so deleting the CORE entry and the script tag dropped
the asset by itself.

Gates on the candidate: full suite (result recorded in `STATUS.md`),
`verify-release-generation` `ok:true`, `verify-cloudflare-parity --static-only`
`VERDICT: PASS`, all 14 CG assertions green, lane-guard path + lock OK.

## Request 1 — `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_*.md`

`docs/` is your lane. Issue #230 item 9 asks that release/certification records state
Voice Load was **deliberately removed by operator decision** — explicitly *not* a
regression and *not* a missing asset, so that a future parity or asset-coverage reading
of "voice-load.js absent / 22 assets not 23" is read as the intended end state.

A superseding state document is due **the day this deploys**, not the day it merges —
the rule that section of `CLAUDE.md` now records against itself six times. The current
authority (`…_2026-09-17.md`) correctly records 24.0.15 as production and 24.0.16 as
source-only; **24.0.17 now stacks on that undeployed 24.0.16**, and the deploy order is
unchanged: **Worker v20 first, then the app generation.**

## Request 2 — `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`

Same lane. It quotes concrete `?v=` markers and will need `24.0.17`, and it should drop
`voice-load.js` from the assets an operator is told to verify — a checklist that still
asks for a deliberately deleted file will read as a failed deploy.

## One thing worth your review, because it is a judgement not a transcription

Issue #230's enumerated items 1-5 named the module and the evaluator microphone. `app.js`
carried **two further, independent** `SpeechRecognition` implementations that built their
own driver-facing `🎤 Voice` buttons through `innerHTML`, where no `index.html` check
could see them:

- F27 Load Intake `#liVoice` (own recognizer + handler)
- F23 Smart Load Inbox `#f23VoiceBtn` (backed by `_startInboxVoice()`)
- plus the F28 Diagnostics `dxVoice` capability row

Removing only the module would have left an operator who asked for **complete** removal
looking at two live Voice buttons doing the same job. Item 4 says "remove any other
driver-facing wording that offers Voice input", and the title says *completely*, so all
of them are removed and nothing replaces them (the issue's non-goal). The `dxVoice` row
went too: reporting "Voice Input: Supported" in an app with no voice input is the X-11
dead-claim class.

`RH-04` asserts the absence of each by name, including that no `SpeechRecognition`
plumbing remains, so a dormant recognizer cannot sit waiting to be re-exposed.

## Still standing: the `tests/run-all.mjs` deadlock

Unchanged and **worked around, not fixed**. This sweep deliberately added **no new spec
file**: `RH-04`/`RH-05` went into `release-hygiene`, `DAC-06`/`DAC-07` into
`deploy-asset-coverage`, `ICT-11`…`ICT-14` into `import-credential-trust-boundary`, and
`MS-11` was retargeted in place. So `RH-01` stays green with no cross-lane edit. The next
Claude regression that genuinely needs its own file is still blocked;
`claude-to-gpt-run-all-ownership-deadlock-2026-09-17.md` stands.
