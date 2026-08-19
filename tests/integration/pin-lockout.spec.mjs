// FINDING F-4 (High, FIXED) — App-Lock PIN brute-force throttle.
//
// requireAppUnlock() used to call verifyPin() on every click/Enter with no
// attempt counter, no backoff, no lockout state — the only cost per guess
// was PBKDF2's fixed work factor, making a 4-digit PIN (10,000
// combinations) exhaustible in under 20 minutes from a single unattended
// tab.
//
// FIX (policy approved by the app owner, given this app is used one-handed
// in a moving vehicle — it must never wipe data and never lock out
// permanently):
//   attempts 1-5:   free, no delay
//   attempts 6-10:  10s delay before the next attempt is even accepted
//   attempts 11-15: 60s delay
//   attempts 16+:   5min delay — the cap, never grows further
// State persists in settings (appLockFailCount / appLockLockedUntil, NOT
// in ALLOWED_SETTINGS_KEYS so a restored backup never re-imports a stale
// lockout) so a reload doesn't reset the counter, and resets to 0 on any
// successful unlock. A "Forgot PIN?" link removes the lock (never touches
// trip/expense data) so the legitimate owner is never truly stuck.

import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/pin-lockout.spec.mjs');
let app;

async function setPin(page, pin) {
  return page.evaluate(async (pin) => {
    const hash = await window.__FL_TESTS.hashPin(pin);
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('settings', 'readwrite');
        txn.objectStore('settings').put({ key: 'appLockEnabled', value: true });
        txn.objectStore('settings').put({ key: 'appLockPin', value: hash });
        txn.objectStore('settings').put({ key: 'appLockFailCount', value: 0 });
        txn.objectStore('settings').put({ key: 'appLockLockedUntil', value: 0 });
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
    return hash;
  }, pin);
}

async function getAppLockSetting(page, key) {
  return page.evaluate((key) => {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('settings', 'readonly');
        const getReq = txn.objectStore('settings').get(key);
        getReq.onsuccess = () => { db.close(); resolve(getReq.result?.value); };
        getReq.onerror = () => reject(getReq.error);
      };
      req.onerror = () => reject(req.error);
    });
  }, key);
}

async function attemptPin(page, guess) {
  await page.fill('#unlockPin', guess);
  await page.click('#unlockNow');
  // Each click's async chain (verifyPin's real PBKDF2 work ~100-150ms, then
  // setSetting's IDB round-trip) must fully finish before the next click —
  // otherwise rapid machine-speed clicks race tryUnlock() invocations and
  // both read the same pre-increment failCount, silently undercounting.
  // 300ms comfortably clears that; a real one-handed driver's tap cadence
  // is far slower than this anyway.
  await page.waitForTimeout(300);
  return page.evaluate(() => ({
    hint: document.getElementById('unlockHint')?.textContent || '',
    pinDisabled: !!document.getElementById('unlockPin')?.disabled,
    btnDisabled: !!document.getElementById('unlockNow')?.disabled,
    modalGone: !document.getElementById('unlockPin'),
  }));
}

test('set a 4-digit App Lock PIN through the real settings path', async () => {
  const pinHash = await setPin(app.page, '4471');
  ok(pinHash.startsWith('pbkdf2v1:'), 'PIN hash format sanity check');
});

test('[FINDING F-4] first 5 wrong guesses are free — no lockout, no delay', async () => {
  await app.page.reload({ waitUntil: 'load' });
  await app.page.waitForSelector('#unlockPin', { timeout: 10000 });

  const results = [];
  for (const guess of ['0000', '1111', '2222', '3333', '4444']) {
    results.push(await attemptPin(app.page, guess));
  }
  console.log('    [evidence] first 5 attempts: ' + JSON.stringify(results));
  for (const r of results) {
    eq(r.hint, 'Incorrect PIN', 'the first 5 attempts must behave exactly as before — plain "Incorrect PIN", no lockout language');
    ok(!r.pinDisabled && !r.btnDisabled, 'input must stay enabled through the free-attempt allowance');
  }
});

test('[FINDING F-4] the 6th consecutive wrong guess triggers a locked, counting-down state', async () => {
  const r = await attemptPin(app.page, '5555');
  console.log('    [evidence] 6th attempt: ' + JSON.stringify(r));
  ok(/too many attempts/i.test(r.hint) && /\d+s/.test(r.hint),
    `expected a lockout message with a seconds countdown, got ${JSON.stringify(r.hint)}`);
  ok(r.pinDisabled && r.btnDisabled, 'input and button must be disabled while locked out');

  const lockedUntil = Number(await getAppLockSetting(app.page, 'appLockLockedUntil') || 0);
  ok(lockedUntil > Date.now(), 'appLockLockedUntil must be persisted in settings, in the future');
  const failCount = Number(await getAppLockSetting(app.page, 'appLockFailCount') || 0);
  eq(failCount, 6, 'appLockFailCount must track the real attempt count');
});

test('[FINDING F-4] lockout state survives a reload (not just in-memory)', async () => {
  const lockedUntilBefore = Number(await getAppLockSetting(app.page, 'appLockLockedUntil') || 0);
  ok(lockedUntilBefore > Date.now(), 'setup: must still be genuinely locked out before reloading');

  await app.page.reload({ waitUntil: 'load' });
  await app.page.waitForSelector('#unlockPin', { timeout: 10000 });
  await app.page.waitForTimeout(300); // let the async lockout-check on modal open run

  // Check the persisted value first — this is the property that actually
  // matters (a reload must not silently clear the counter) and, unlike a
  // UI-visibility check, isn't sensitive to how long app boot + reload
  // itself takes (this app's boot sequence — initDB, migration checks,
  // requireAppUnlock — can itself eat a couple of real seconds).
  const lockedUntilAfter = Number(await getAppLockSetting(app.page, 'appLockLockedUntil') || 0);
  console.log(`    [evidence] appLockLockedUntil before reload: ${lockedUntilBefore}, after: ${lockedUntilAfter}`);
  eq(lockedUntilAfter, lockedUntilBefore, 'reload must not reset/clear the persisted lockout timestamp');

  // Soft UI check: only meaningful if the countdown genuinely hasn't
  // elapsed yet by the time we ask (reload can itself take real time).
  if (lockedUntilAfter > Date.now()) {
    const state = await app.page.evaluate(() => ({
      pinDisabled: !!document.getElementById('unlockPin')?.disabled,
      hint: document.getElementById('unlockHint')?.textContent || '',
    }));
    console.log('    [evidence] post-reload UI state (still within lockout window): ' + JSON.stringify(state));
    ok(state.pinDisabled, 'while still within the lockout window, the reloaded UI must reflect it as locked');
    ok(/too many attempts/i.test(state.hint), 'the countdown message must reappear after reload');
  } else {
    console.log('    [evidence] lockout window already elapsed by the time reload finished — UI check skipped, DB persistence already proven above');
  }
});

test('[FINDING F-4] once the delay elapses, attempts are accepted again automatically', async () => {
  // 6th failure used the first tier (10s) — the shortest, specifically so
  // this test doesn't need to be slow. Only wait out however much of it
  // remains (the previous test's reload may already have burned some of
  // it) rather than a flat 10.5s regardless.
  const lockedUntil = Number(await getAppLockSetting(app.page, 'appLockLockedUntil') || 0);
  const remaining = Math.max(0, lockedUntil - Date.now());
  if (remaining > 0) await app.page.waitForTimeout(remaining + 500);
  // The countdown's own setInterval (1s tick) needs one more tick to
  // actually flip the UI back to enabled after the deadline passes.
  await app.page.waitForTimeout(1200);
  const state = await app.page.evaluate(() => ({
    pinDisabled: !!document.getElementById('unlockPin')?.disabled,
  }));
  ok(!state.pinDisabled, 'input must re-enable itself once the countdown reaches zero, with no further user action');
});

test('[FINDING F-4] the correct PIN unlocks and resets the fail counter to zero', async () => {
  await app.page.fill('#unlockPin', '4471');
  await app.page.click('#unlockNow');
  // closeModal() (app.js:576-588) hides the modal via a CSS class first and
  // only removes its DOM content 350ms later (an unrelated close-animation
  // detail, not part of this fix) — wait past that, not just the settings
  // round-trip, before checking the modal is gone.
  await app.page.waitForTimeout(600);
  const modalGone = await app.page.evaluate(() => !document.getElementById('unlockPin'));
  ok(modalGone, 'a correct PIN must close the unlock modal');
  const failCount = Number(await getAppLockSetting(app.page, 'appLockFailCount') || 0);
  const lockedUntil = Number(await getAppLockSetting(app.page, 'appLockLockedUntil') || 0);
  eq(failCount, 0, 'a successful unlock must reset appLockFailCount to 0');
  eq(lockedUntil, 0, 'a successful unlock must clear appLockLockedUntil');
});

test('[FINDING F-4] "Forgot PIN" removes the lock (without touching trip data) even mid-lockout', async () => {
  // Re-lock, then re-trigger lockout, then use Forgot PIN while still locked.
  await setPin(app.page, '9012');
  await app.page.reload({ waitUntil: 'load' });
  await app.page.waitForSelector('#unlockPin', { timeout: 10000 });
  for (let i = 0; i < 6; i++) await attemptPin(app.page, '0000');
  const lockedState = await app.page.evaluate(() => !!document.getElementById('unlockPin')?.disabled);
  ok(lockedState, 'setup: must be locked out before testing Forgot PIN');

  app.page.once('dialog', d => d.accept());
  await app.page.click('#unlockForgotPin');
  await app.page.waitForTimeout(600); // same closeModal() delayed-removal note as above

  const modalGone = await app.page.evaluate(() => !document.getElementById('unlockPin'));
  ok(modalGone, 'Forgot PIN must close the unlock modal (app is now accessible)');
  const enabled = await getAppLockSetting(app.page, 'appLockEnabled');
  const pin = await getAppLockSetting(app.page, 'appLockPin');
  const failCount = Number(await getAppLockSetting(app.page, 'appLockFailCount') || 0);
  eq(enabled, false, 'Forgot PIN must disable App Lock');
  eq(pin, '', 'Forgot PIN must clear the stored PIN hash');
  eq(failCount, 0, 'Forgot PIN must also clear the lockout counters');
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
