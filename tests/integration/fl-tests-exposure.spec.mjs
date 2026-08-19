// FINDING F-5 (Low/Informational) — window.__FL_TESTS is unconditionally
// exposed in production, contradicting its own comment.
//
// app.js:16021-16024:
//   "TEST EXPORTS — pure functions exposed for test harness
//    Only active when window.__FL_TESTS_ENABLED is set before load"
// app.js:16025: `if (typeof window !== 'undefined'){ window.__FL_TESTS = {...} }`
// There is no read of `window.__FL_TESTS_ENABLED` anywhere in app.js — the
// gate described in the comment does not exist in code. Every production
// page load exposes escapeHtml, sanitizeTrip/Expense/Fuel, hashPin,
// computeLoadScore, generateBidRange, and the full OMEGA_TIERS/MW pricing
// tables on window, reachable by any script running in the page (a
// same-origin XSS payload, a malicious browser extension, or anything
// pasted into DevTools) with zero setup.
//
// This test loads the app with NO init script at all (i.e. explicitly NOT
// setting __FL_TESTS_ENABLED, the opposite of what the comment says is
// required) and shows __FL_TESTS is present anyway.

import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/fl-tests-exposure.spec.mjs');
let app;

test('[FINDING F-5] window.__FL_TESTS must be ABSENT in a production load (no __FL_TESTS_ENABLED set)', async () => {
  const flagWasSet = await app.page.evaluate(() => window.__FL_TESTS_ENABLED);
  eq(flagWasSet, undefined, 'test setup sanity: __FL_TESTS_ENABLED must NOT have been set for this to be a valid proof');

  const state = await app.page.evaluate(() => ({
    present: typeof window.__FL_TESTS === 'object' && window.__FL_TESTS !== null,
    keyCount: Object.keys(window.__FL_TESTS || {}).length,
  }));
  console.log(`    [evidence] window.__FL_TESTS present=${state.present} (${state.keyCount} keys) with __FL_TESTS_ENABLED never set`);

  // Correct behavior per the code's own comment (app.js:16021-16024): __FL_TESTS should
  // only exist when __FL_TESTS_ENABLED is set before load. This is the intended-behavior
  // assertion — expected to fail until F-5 is fixed (no such gate exists in code today).
  ok(!state.present,
    `EXPECTED window.__FL_TESTS to be undefined in a plain production load (per app.js:16021-16024's documented gate), ` +
    `but it is unconditionally present with ${state.keyCount} internal functions/constants (including hashPin) reachable ` +
    `from any page-context script — the __FL_TESTS_ENABLED gate the comment describes does not exist anywhere in code.`);
});

test('[FINDING F-5b] window.__FL_TESTS IS present when the harness opts in via __FL_TESTS_ENABLED', async () => {
  // Once F-5 is fixed, the test harness itself needs a supported way to opt in —
  // this documents/enforces that contract so the fix doesn't just delete the export.
  await app.close();
  app = await launchApp({ enableTestExports: true });
  const state = await app.page.evaluate(() => ({
    flagSet: window.__FL_TESTS_ENABLED === true,
    present: typeof window.__FL_TESTS === 'object' && window.__FL_TESTS !== null,
    hasHashPin: typeof window.__FL_TESTS?.hashPin === 'function',
  }));
  ok(state.flagSet, 'harness did not actually set __FL_TESTS_ENABLED before navigation — check launchApp({enableTestExports:true})');
  ok(state.present, 'with __FL_TESTS_ENABLED set, window.__FL_TESTS should be present (this is how the rest of this suite exercises pure functions)');
  ok(state.hasHashPin, 'window.__FL_TESTS.hashPin should be reachable when explicitly enabled');
});

export async function runSpec() {
  // Genuine production load: do NOT opt in to __FL_TESTS_ENABLED.
  app = await launchApp({ enableTestExports: false });
  try {
    return await run();
  } finally {
    await app.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { stopServer } = await import('../lib/harness.mjs');
  const r = await runSpec();
  await stopServer();
  process.exit(r.fail > 0 ? 1 : 0);
}
