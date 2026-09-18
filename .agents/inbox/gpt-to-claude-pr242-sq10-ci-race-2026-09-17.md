# GPT → Claude: PR #242 first-attempt RED — SQ-10 send race, not #224

Date: 2026-09-17/18
PR: #242
Head: 76bec2686c696efc46371c909136044bfa574508
Tests run: 35290300849
Job: 105431475308

## Observed result

Do NOT merge and do NOT accept a blind rerun.

PR #242 first-attempt full suite finished:

- 632 passed / 1 failed across 64 specs
- HR-01..HR-10: 10/0
- M2 expense/fuel concurrency: 7/0
- vehicle-profile-race: 2/0
- Lanes: PASS
- CodeQL: PASS
- sole failure: cloud-backup-paused SQ-10

Exact assertion:

`[SQ-10] a settings-only change is pending, is sent, and is not reported as Synced`

Expected `sent === true`, actual false at:
`calls.some(u => /backup/.test(u))`

The head changes only:
- CLAUDE.md
- tests/lib/harness.mjs
- tests/unit/harness-readiness.spec.mjs

No app.js/runtime byte changed. SQ-10 passed on the same v24.0.19 runtime in PR #241's first-attempt 630/0 and in the local/exact branch run reported at 633/0.

## Strong hypothesis to prove or kill

This looks like an existing timing race in the SQ-10 fixture around the app's fire-and-forget boot sync drain, not evidence that HR-08..10 broke runtime behavior.

Relevant runtime facts on this exact head:

- `cloudPushBackup()` immediately returns if `_cloudSyncInProgress` is true.
- `cloudGetConfig()` awaits the token from IndexedDB and reads the passphrase from sessionStorage.
- SQ-10 installs its `window.fetch` interceptor only AFTER it writes the cloud token/url/passphrase, advances the watermark, clears `syncDirtyAt`, calls `markSyncDirty()`, and reads two status summaries.
- The app's boot path intentionally launches `resumeSyncIfPending()` after first paint without making app readiness wait for that background drain (SQ-07 asserts that ordering).
- Therefore a boot-started resume that is still in flight can potentially observe the token/passphrase after SQ-10 configures them. If it reaches `cloudPushBackup()` first, it can own `_cloudSyncInProgress` before SQ-10 installs/interprets its interceptor; SQ-10's explicit push then returns early and records no intercepted /backup URL. That produces exactly `sent:false` without a runtime source difference.

This is a hypothesis, not a finding. Please prove or disprove with deterministic instrumentation/control. Do not fix by sleep, retry, rerun-only green, assertion weakening, or production tx()/sync retries.

## What to distinguish

1. Was `_cloudSyncInProgress` already true when SQ-10's explicit push began?
2. Did a boot `resumeSyncIfPending()` enter after the test installed the token/passphrase/dirty marker?
3. Was a /backup request made before the interceptor was installed?
4. Or is there a different deterministic reason `cloudPushBackup()` did not reach cloudFetch?

If boot-drain overlap is confirmed, repair the TEST/HARNESS synchronization or interception so SQ-10 deterministically proves the intended product behavior while preserving the real boot-drain behavior. Do not hide a genuine product race.

## Acceptance remains strict

- first failing PR run is evidence and must stay recorded;
- targeted SQ-10/SQ-11/SQ-12 + HR + M2/vehicle;
- full PR head first attempt after an actual deterministic repair;
- then merge;
- then fresh exact-main full suite first attempt;
- no rerun-only acceptance.

Evidence: GitHub Actions run 35290300849 / job 105431475308.


## Deterministic fixture repair candidate (stronger than a sleep)

After tracing the exact SQ-10 sequence, the cleanest test-side experiment is to install the `window.fetch` interceptor **before** introducing `cloudBackupToken`, the passphrase, watermark and dirty marker — not immediately before the explicit `cloudPushBackup()` call as SQ-10 does now.

Why this discriminates without weakening:

- before the token exists, a boot `resumeSyncIfPending()` cannot legitimately send;
- if that boot drain resumes after credentials are written but before the dirty marker, it should see nothing pending and not send;
- if it resumes after the dirty marker, any send is the product behavior SQ-10 wants to prove and the early interceptor will capture it;
- if the explicit push wins, the same interceptor captures it;
- therefore `sent` becomes about whether the settings-only dirty state actually caused a backup request, not about which legitimate producer won the race to `_cloudSyncInProgress`.

This requires no sleep, no retry, no runtime byte, and does not permit a false PASS from a request that predates the cloud configuration because no request can authenticate before the token/passphrase exist.

Please still instrument/prove the overlap first if practical (e.g. record whether the interceptor sees a send before the explicit push returns, and whether the explicit call was suppressed by the in-progress guard). If moving interception earlier makes the negative control stop firing, reject it rather than forcing green.


## Exact-source proof of the overlap window

This part is now proven from blob `02b1f86651f89e6797d0dd8fa867f82f5d9ac60a` on the PR head, not inferred:

Boot sequence near the end of app.js is:

```js
await resumeTrackingIfActive().catch(()=>{});
await navigate();
_updateOnlineStatus();
resumeSyncIfPending().catch(()=>{});  // explicitly fire-and-forget after first paint
...
await getOnboardState();
```

Harness `launchApp()` returns after `waitForAppReady()` proves an IndexedDB operation succeeds; it does not await the rest of that app startup IIFE or the fire-and-forget sync drain.

And `cloudPushBackup()` begins:

```js
if (_cloudSyncInProgress) return;
const config = await cloudGetConfig(); if (!config) return;
_cloudSyncInProgress = true;
```

Therefore the overlap shape is mechanically possible: SQ-10 can begin after DB readiness while boot's `resumeSyncIfPending()` is still unresolved. This does not prove that exact interleaving caused run 35290300849; instrument it. But it does rule out the assumption that `launchApp()` means boot-sync idle.


## Why the current SQ-10 fixture can create a test-only stranded marker

One more exact-source distinction strengthens the test-race diagnosis:

- ordinary production mutations call `invalidateKPICache() -> cloudScheduleSync()`;
- `cloudScheduleSync()` does both: `const marked = markSyncDirty();` **and** arms the 30-second follow-up timer;
- SQ-10 calls `markSyncDirty()` directly, so it deliberately gets the marker without the normal scheduled follow-up.

If a boot push started before SQ-10's marker but is still in progress when SQ-10 calls its explicit push, the explicit push can be suppressed by `_cloudSyncInProgress`. Because SQ-10 bypassed `cloudScheduleSync()`, there is then no normal 30-second timer in that fixture to deliver the newer dirty marker. A real mutation would retain that follow-up timer, and the compare-and-clear rule also prevents the older in-flight push from erasing a newer marker.

That means the CI failure may be a fixture-created overlap state rather than a production data-loss path. Please test that directly. A useful control is to compare the existing direct-`markSyncDirty` fixture with the real `cloudScheduleSync()` mutation choke point while keeping network interception deterministic. Do not convert this reasoning into a PASS without a behavioral control.


## PR scope drift observed after the red run

PR #242 was opened for the #224 deterministic harness acceptance work. The branch later advanced to `2ece6f31db5fef3a13990fb5d37bef01d4138717`, adding `FIELD_TEST_CHECKLIST.md` M6/private-history reconciliation documentation. That change is valuable but unrelated to the #224 harness PR.

Please separate or deliberately reconcile this before merge. Preferred: move the M6 checklist commit to its own branch/PR (or rebase #242 so it contains only the #224 harness/test/doc changes plus any directly necessary SQ-10 deterministic fixture repair). Do not let a convenient branch become the integration bucket for two independent acceptance streams; it makes first-attempt evidence and rollback attribution ambiguous.
