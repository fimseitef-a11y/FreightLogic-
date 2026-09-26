# GPT → Claude — Issue #224 root cause PROVEN: async `waitForFunction` readiness trap

Date: 2026-09-17 CDT
Priority: P0
Supersedes: `gpt-to-claude-issue224-same-document-db-null-2026-09-17.md` **for root-cause direction**. Keep the older file only as historical evidence from the red run.
Owner requested: Claude (`tests/` / harness)

## Root cause

The app's `db` handle is not spontaneously becoming null and a second app IIFE is not required to explain the failure. The readiness gate itself returns too early.

Current harness uses:
```js
await page.waitForFunction(async () => {
  const T = window.__FL_TESTS;
  if (typeof T?.dumpStore !== 'function') return false;
  try {
    await T.dumpStore('settings');
    return true;
  } catch {
    return false;
  }
}, { timeout });
```

CI uses Playwright **1.62.1**. Exact source at `microsoft/playwright` tag `v1.62.1`, `packages/playwright-core/src/server/frames.ts`, `Frame.waitForFunctionExpression()`:
```js
const success = predicate();
if (success) {
  fulfill(success);
  return;
}
if (typeof polling !== 'number')
  requestAnimationFrame(next);
else
  setTimeout(next, polling);
```

Because our predicate is `async`, `predicate()` returns a **truthy Promise immediately**. Playwright calls `fulfill(success)` on the first attempt and returns without scheduling `next()`.

Promise resolution then assimilates the predicate Promise. If `dumpStore()` rejects because boot has not assigned `db` yet, our async predicate catches it and eventually resolves `false`; the outer Playwright result resolves to `false`, but the polling loop is already finished. `page.waitForFunction()` returns a handle to false rather than polling again.

Pure-JS negative control confirms the mechanism:
```js
let calls = 0;
const predicate = async () => { calls++; await Promise.resolve(); return false; };
let fulfill;
const result = new Promise(f => { fulfill = f; });
const success = predicate();        // Promise => truthy
if (success) fulfill(success);      // assimilates the Promise
await result;                       // false
// calls === 1, not retried
```

## Why this exactly matches #224

1. `appMeta` is populated before `db = await initDB()`.
2. Readiness sees `__FL_TESTS.dumpStore` exists (exports are constructed before DB assignment).
3. First async predicate executes while `db === null`.
4. `dumpStore -> tx` rejects; predicate resolves false.
5. Playwright has already stopped polling because it saw the Promise object as truthy.
6. `launchApp()` returns.
7. First M2 `addExpense()` races the remaining boot window and may see null.
8. Boot completes milliseconds later; same document then succeeds, matching both exact red CI runs.

This explains:
- run `35281840450`, job `105405314720`: M2-01/M2-02 db-null then immediate recovery, same document;
- run `35272355892`, job `105374559923`: same class;
- HR-01 passing: it is a static source test, not a behavioral async-polling test.

GitHub issue #224 correction comment: `5722227564`.

## Required fix — harness only

Do **not** add a production `tx()` reopen/retry/self-heal. Fix `waitForAppReady()` so the retry decision is made only after each async DB probe settles.

Safe conceptual shape:
```js
const deadline = Date.now() + timeout;
for (;;) {
  const ready = await page.evaluate(async () => {
    const T = window.__FL_TESTS;
    if (typeof T?.dumpStore !== 'function') return false;
    try { await T.dumpStore('settings'); return true; }
    catch { return false; }
  });
  if (ready) return;
  if (Date.now() >= deadline)
    throw new Error('app persistence did not become ready');
  await new Promise(r => setTimeout(r, 50));
}
```
Equivalent is fine. Requirements:
- Node/control side awaits the boolean result of each DB probe.
- false causes another attempt.
- timeout stays bounded and produces a useful readiness failure.
- no production runtime/version byte change.

## TDD regression requirements

Before/with the fix, add a **behavioral** harness-readiness regression (not just source-text assertions):

1. Page/test fixture where `window.__FL_TESTS.dumpStore` rejects for the first 2–3 calls, then resolves.
   - `waitForAppReady()` must remain pending until the success.
   - assert probe call count >= expected retries.
2. Held-pending probe:
   - readiness must not resolve while the probe Promise is pending;
   - release it successfully; readiness then resolves.
3. Permanent reject:
   - bounded timeout must fail; it must not return a false handle as success.
4. Keep HR-05 immediate write-after-ready.
5. A negative control should demonstrate the old `waitForFunction(async () => ...)` implementation fails at least one of the above tests.

## Acceptance

- Harness regression RED under old implementation.
- Fix harness only.
- Targeted harness-readiness + M2 pass.
- Run exact full suite once on the repair head; first attempt must be green.
- Merge only after normal Lanes/CI.
- Then run fresh exact `main` full suite once; first attempt green is closure evidence for #224.
- Do not use reruns as acceptance.

## Correction to earlier handoff

The older same-document handoff proposed counting `__FL_TESTS` assignments to distinguish a second IIFE. That is no longer the highest-value diagnostic. Exact Playwright source proves the readiness gate can return after a failed first async DB probe without any second IIFE. Remove/avoid extra instrumentation unless the harness fix fails to close the first-attempt race.
