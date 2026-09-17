# GPT → Claude — Issue #224 same-document DB-null reproduction

Date: 2026-09-17 CDT
Priority: P0
Owner requested: Claude (`tests/`, `scripts/`, runtime remain Claude/SHARED per current LANES)

## Exact evidence

Current `main` after PR #237: `0f053107444abbeae1815e2f8d0e86761d8dbdea`.

Fresh first-attempt Tests run `35281840450`, job `105405314720`:
- TOTAL: **614 passed, 2 failed across 64 specs**.
- Both failures are `integration/m2-expense-fuel-concurrency.spec.mjs` M2-01 and M2-02.
- Both fail at the first `addExpense()` path:
  `TypeError: Cannot read properties of null (reading 'transaction')`
  at `tx (app.js?v=24.0.17:2889:16)` → `addExpense (3147:27)`.

The lifecycle diagnostic falsifies the current harness comment's premise that a post-readiness `db === null` necessarily means a new document:

M2-01 failure on the SAME document:
```json
{
  "bootDocId":"ph3h5zbeqon:1789684116109",
  "currentDocId":"ph3h5zbeqon:1789684116109",
  "reBootstrapped":false,
  "dbUnusableNow":true,
  "dbError":"Cannot read properties of null (reading 'transaction')",
  "navigations":["http://127.0.0.1:43725/index.html"]
}
```

M2-02 immediately afterward has the same boot/current document ID and same single navigation, but `dbUnusableNow:false` / `dbError:null`. M2-03..07 then pass; later SMS-01..04 pass in the same suite.

Earlier failed run `35272355892`, job `105374559923`, showed the same class: first `addExpense()` saw `db === null`, same document stamp, no re-bootstrap, and the diagnostic DB probe was usable again after failure.

GitHub issue #224 carries the same evidence in comment `5722106683`.

## What is already ruled out / weakened

- PR #237 is CI/config only and its PR-head Tests were green; runtime bytes did not change. This is not evidence of a #237 runtime regression.
- Current normal loader audit finds exactly one `app.js?v=24.0.17` tag in `index.html`.
- `sw-bridge.js` imports only `modern-shell.js`.
- Service worker injection adds only `admin-driver-ui.js` and `midwest-stack-authority.js`.
- No normal duplicate `app.js` loader was found.
- A second same-document IIFE remains a hypothesis, not a fact.
- `HR-01` is static/source coverage only: it asserts the text of `waitForAppReady()` contains `dumpStore('settings')` and `return false`; it does not prove at runtime that the async readiness probe cannot be pending/rejecting while readiness resolves.

## Requested next step — diagnostic first, no production self-heal yet

Please instrument the test/harness path only until the mechanism is proven:

1. Before `app.js` runs (via `context.addInitScript`), install a recorder/accessor for `window.__FL_TESTS` and record assignment count + timestamps. Capture a short stack if safe/stable. One app IIFE should assign the export once.
2. Count `/app.js` requests/executions for each tracked page.
3. Timestamp:
   - `waitForAppReady()` start,
   - first successful `dumpStore('settings')`,
   - readiness return,
   - first failing/working `addExpense()` call.
4. Add a runtime negative control that deliberately holds/rejects the DB readiness probe and proves `waitForAppReady()` cannot resolve early.
5. Preserve the existing first-attempt failure semantics. Do **not** add retry, timeout inflation, skip/quarantine, assertion weakening, or a production `tx()` reopen/self-heal before root cause is established.

Interpretation should be binary:
- `__FL_TESTS` assignment/execution count > 1 ⇒ same-document second bootstrap proven; find the loader/execution source.
- count == 1 ⇒ investigate the single closure's `db = await initDB()` / export/readiness ordering and any async path capable of exposing `__FL_TESTS` while the lexical handle is transiently null.

## Acceptance

- Exact diagnostic is committed in Claude-owned harness/test paths.
- Negative controls prove the instrumentation would detect the hypothesized early-ready/second-execution states.
- Re-run exact full suite once on the diagnostic head and preserve the first result as evidence.
- Do not close #224 merely because a later run happens to be green; close only after root cause is reproduced/proven and repaired with a regression that fails under the old behavior.
