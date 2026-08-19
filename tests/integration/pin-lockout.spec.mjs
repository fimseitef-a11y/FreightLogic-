// FINDING F-4 (Medium/High) — App-Lock PIN has no brute-force lockout.
//
// requireAppUnlock() (app.js:5251-5277) shows a PIN input + Unlock button and
// calls verifyPin() on every click/Enter with no attempt counter, no
// exponential backoff, and no lockout state. The only cost per guess is the
// PBKDF2 work factor (310k iterations, app.js:167-174) baked into
// verifyPin() itself. This test sets a 4-digit PIN, then scripts N wrong
// guesses back-to-back exactly the way a console-injected loop would, and
// proves: (a) no lockout/backoff message ever appears, (b) the app never
// blocks further attempts, (c) per-attempt latency stays roughly flat
// (proving there's no growing throttle), all of which make the PIN a pure
// compute-bound brute-force target (~10,000 combinations for a 4-digit PIN).

import { launchApp, createSuite, ok } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/pin-lockout.spec.mjs');
let app;

test('set a 4-digit App Lock PIN through the real settings path', async () => {
  const pinHash = await app.page.evaluate(async () => {
    const hash = await window.__FL_TESTS.hashPin('4471');
    // Write through the same settings store the app itself uses.
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('settings', 'readwrite');
        txn.objectStore('settings').put({ key: 'appLockEnabled', value: true });
        txn.objectStore('settings').put({ key: 'appLockPin', value: hash });
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
    return hash;
  });
  ok(pinHash.startsWith('pbkdf2v1:'), 'PIN hash format sanity check');
});

test('[FINDING F-4] 15 consecutive wrong PIN guesses: no lockout, no backoff, no attempt cap', async () => {
  await app.page.reload({ waitUntil: 'load' });
  await app.page.waitForSelector('#unlockPin', { timeout: 10000 });

  const attempts = [];
  const wrongGuesses = ['0000','1111','2222','3333','4444','5555','6666','7777','8888','9999','1234','4321','0001','0002','0003'];
  for (const guess of wrongGuesses) {
    const t0 = Date.now();
    await app.page.fill('#unlockPin', guess);
    await app.page.click('#unlockNow');
    await app.page.waitForTimeout(50);
    const hint = await app.page.evaluate(() => document.getElementById('unlockHint')?.textContent || '');
    const stillPresent = await app.page.evaluate(() => !!document.getElementById('unlockPin'));
    attempts.push({ guess, ms: Date.now() - t0, hint, stillPresent, inputEnabled: await app.page.evaluate(() => !document.getElementById('unlockPin')?.disabled) });
  }

  const lockoutMentions = attempts.filter(a => /lock|wait|try again|too many|blocked/i.test(a.hint));
  const disabledAt = attempts.find(a => !a.inputEnabled);
  console.log('    [evidence] attempts: ' + JSON.stringify(attempts.map(a => ({ guess: a.guess, ms: a.ms, hint: a.hint })), null, 2));

  ok(lockoutMentions.length === 0 && !disabledAt,
    `informational baseline: confirms current behavior allows unlimited guesses (no lockout UI/state found across ${attempts.length} attempts)`);

  // This is the actual failing assertion: a PIN gate SHOULD lock out after a
  // small number of consecutive failures (e.g. 5), which app.js does not do.
  const MAX_REASONABLE_ATTEMPTS_BEFORE_LOCKOUT = 5;
  ok(attempts.length <= MAX_REASONABLE_ATTEMPTS_BEFORE_LOCKOUT || lockoutMentions.length > 0 || !!disabledAt,
    `BUG (app.js:5251-5277): requireAppUnlock() accepted ${attempts.length} consecutive wrong PIN guesses with no lockout, ` +
    `backoff, or attempt cap of any kind — only PBKDF2's fixed ~ms cost throttles a brute-force loop against a 4-digit ` +
    `(10,000-combination) PIN. verifyPin() (app.js:177-207) is called fresh on every guess with no shared attempt-counter state.`);
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
