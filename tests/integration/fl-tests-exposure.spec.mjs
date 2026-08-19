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

test('[FINDING F-5] window.__FL_TESTS is present without window.__FL_TESTS_ENABLED ever being set', async () => {
  const flagWasSet = await app.page.evaluate(() => window.__FL_TESTS_ENABLED);
  eq(flagWasSet, undefined, 'test setup sanity: __FL_TESTS_ENABLED must NOT have been set for this to be a valid proof');

  const state = await app.page.evaluate(() => ({
    present: typeof window.__FL_TESTS === 'object' && window.__FL_TESTS !== null,
    hasHashPin: typeof window.__FL_TESTS?.hashPin === 'function',
    keyCount: Object.keys(window.__FL_TESTS || {}).length,
  }));

  ok(state.present, 'BUG (app.js:16021-16038): __FL_TESTS is exposed even though window.__FL_TESTS_ENABLED was never set — the documented gate does not exist in code.');
  ok(state.hasHashPin, 'the internal PIN-hashing primitive is reachable from any page-context script via window.__FL_TESTS.hashPin');
  console.log(`    [evidence] window.__FL_TESTS exposes ${state.keyCount} internal functions/constants unconditionally in production`);
});

export async function runSpec() {
  app = await launchApp();
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
