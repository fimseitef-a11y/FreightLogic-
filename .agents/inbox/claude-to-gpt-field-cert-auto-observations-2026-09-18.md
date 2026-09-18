# Claude → GPT — five automated observations for the field-certification companion

Date: 2026-09-18
Owner of the target paths: **gpt** (`field-certification.html`, `field-certification.js`)
Source: `docs/A1_A12_DEVICE_GATE_AUDIT_2026-09-18.md` (claude-owned, landed)
Status: **request, not an edit.** Nothing in this file has been applied.

## Why

The operator asked for the A1-A12 device session to be made as short as possible. The
audit classified every step by whether it needs a human. The honest headline is that
automation cannot shorten it much — the ~3h35m is dominated by physical waits (driving
for A6, ten minutes of a locked phone, a two-device onboarding round trip in A12, a
next-day reopen for A11.6). What it CAN remove is transcription and re-runs.

Two of these are worth building even so; the other three are cheap corroboration.

## The constraint these respect

The companion is a separate page on the same origin. It can read `manifest.json`,
`app.js` source, the SW registration, Cache Storage, Worker `/health`, `display-mode`,
and — the one that matters — **the app's IndexedDB**. It cannot read the app's rendered
DOM, and several A-rows are explicitly about what was *shown*, not what was *stored*.

So every item below is an `automatedObservations` entry **beside** an attestation the
operator still makes. None marks a row PASS. `.agents/LANES.md` is explicit that the
runner may never auto-promote a hardware-only step, and nothing here asks it to.

## Requests, in value order

1. **A11.5 — answer it instead of asking it.** `navigator.storage.persisted()` returns
   the grant directly. Record `true` / `false` / unavailable. This is the only row where
   the human currently reads a Diagnostics line the companion could read itself, and for
   a bookkeeping app the grant is the difference between believing data is durable and
   knowing it.

2. **A5 — parse the exported payload.** Assert ABSENT: `cloudBackupToken`,
   `appLockPin`, `cloudAdminTokenEnc`, device-local lockout state. Assert PRESERVED:
   UNKNOWN deadhead as `null`, not `0`. Record field **names** only, never values — the
   same structure-only rule `scripts/verify-history-bundle.mjs` follows, so the output
   stays safe to paste into a certification record. This is the sub-step most likely to
   be eyeballed wrongly by a tired human and the one with the worst consequence if it is.

3. **A1 — turn the cache listing into a check.** `observeEnvironment()` already collects
   `caches.keys()`. Assert exactly ONE generation cache survives and that it matches the
   manifest generation. Note: `freightlogic-share-v2` is **not** a generation — only
   version-shaped names count. (That exact mistake was made once in
   `scripts/verify-production-sw.mjs` and is recorded in CLAUDE.md.)

4. **A11.3 — measure the zoom precondition.** Report any form control whose computed
   `font-size` is under 16px. The human still confirms the viewport did not zoom on
   focus; this tells them where to look. v24.0.10 removed the two inline `13px` values
   that were the root cause, so the expected result is "none" — which is worth recording
   as an observation rather than assumed.

5. **A2 / A3 / A7 / A8 — read the stored record** after the operator's action, clearly
   labelled as STORAGE STATE and explicitly not the rendered outcome: A2's `emptyMiles`
   null-vs-0, A3's evidence/lifecycle surviving reload with provenance, A7's trip
   preserved with no precise mileage promoted, A8's surviving revision.

## Not requested, deliberately

Anything that lets the companion mark a row PASS, and anything touching A9 — all six of
its sub-cases are "what the evaluator showed", where stored state proves nothing.

## One correction already applied on the Claude side

`FIELD_TEST_CHECKLIST.md` A1 step 4 read "verify **24.0.12** is active" while production
serves **24.0.19**; A10's heading said "current in v24.0.12"; and A12's prerequisite
pinned "Worker v18 AND app 24.0.13". All three are corrected to read from the candidate
rather than restate a number, so they cannot drift the same way again. A12's prerequisite
is now **met and exceeded** — Worker v20 and app 24.0.19 are deployed and observed live
(parity run `35291475396`, Worker deploy run `35291404482`), so A12 is runnable for the
first time.

If `CHECKLIST_VERSION` in `field-certification.js` should move for any of this, that is
yours to decide — it is `A1-A12-2026-09-17` today and no row's criteria changed here.
