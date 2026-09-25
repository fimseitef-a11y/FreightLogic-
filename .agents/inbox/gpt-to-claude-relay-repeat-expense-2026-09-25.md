# Worker v27: legitimate repeat expense suppressed as a screenshot duplicate

Priority: HIGH data-integrity / input loss. Status: REPRODUCED LOCALLY against exact main `358e2d37ed200767b183975dd73eca58abd2dcda`, Worker blob `d528eabe1e04945896af829673580c68b48e0264`. This is NOT a physical-iPhone result or a production request; no private freight data, credentials, or live records were used.

## Evidence
The full source Worker fetch handler ran in Node v24.19.0 with the existing `worker-web-push.spec.mjs` in-memory KV/auth/relay helpers. Network fetch was prohibited. Steps:
1. Create a synthetic driver and Shortcut key through the actual handlers.
2. Relay `{do:'expense',params:{amount:'12.50',category:'Tolls'}}`; accepted.
3. Consume it through authenticated DELETE /relay/:id.
4. Advance Date.now by one day and submit a new, independent expense with the same amount/category.
5. Read the relay queue and submit a different-amount control.

Observed: second response `ok:true, duplicate:true, waiting:false, pushed:0`, original id reused; queue length 0. Different amount 12.51 was accepted. Intended assertion that the independent second expense gets a new relay id FAILED (exit 1). This is a confirmed behavioral regression in input delivery, not evidence that a user's saved expense was deleted.

## Root cause
PR #366 / a0fd704 added the 14-day action+validated-parameter fingerprint suppression unconditionally across every relay action, including expense and fuel. There is no transaction/submission identity. Equal business values do not prove the same transaction. WP-17 currently asserts that an expense is suppressed after consumption, so existing green CI enshrines this case instead of detecting it.

## Narrow regression to add in the owning lane
Use existing helpers in tests/unit/worker-web-push.spec.mjs:
```js
const env = newEnv(); const worker = await loadWorker();
const a = await seedDriver(worker, env, 'Synthetic repeat-expense check', '203.0.113.44');
const { body: { key } } = await mintShortcutKey(worker, env, a.token);
const payload = { do: 'expense', params: { amount: '12.50', category: 'Tolls' } };
const first = await (await worker.fetch(relayReq(key, payload), env)).json();
eq(first.ok, true, 'first relay accepted');
eq((await worker.fetch(REQ('/relay/' + first.id, { method: 'DELETE', headers: driverHdrs(a.token) }), env)).status, 200, 'first consumed');
const realNow = Date.now;
try {
  Date.now = () => realNow() + 24 * 3600 * 1000;
  const second = await (await worker.fetch(relayReq(key, payload), env)).json();
  ok(second.ok && !second.duplicate && second.id !== first.id, 'new independent equal-value expense must queue');
} finally { Date.now = realNow; }
```

## Requested owning-lane action
Preserve duplicate screenshot/intake protection, but stop treating identical expense/fuel values as proof of duplicate submissions. The smallest policy-preserving option is to scope content-based suppression to intake; if other actions need retry idempotence, use explicit submission identity rather than a 14-day value hash. Add distinct repeat-expense/fuel tests alongside intake duplicate retention, driver isolation and expiry coverage. This is a recommendation, not an implemented fix.

Worker and its unit test remain Claude-owned. Claude also has a separate active app-js lock for v24.0.43 CSV/XLSX import integrity. GPT made no application/Worker/test changes and did not interfere with that lock. Keep importer remediation and the historical data repair distinct: a source fix alone does not clean already-imported records or automatically invalidate/recertify authentic M6 Gate C.

## Current checkpoint
At read time main 358e2d3 has Tests 36179477121, CodeQL 36179477067, Live Parity 36179477147 and Production SW 36179477046 all successful. Open PR search returned none. main protection remains disabled and rulesets empty (fresh API reads). No broad suite rerun was performed.
