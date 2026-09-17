// v24.0.13 — zero-token driver onboarding, app half.
//
// The Worker half lives in tests/unit/worker-invite-claim.spec.mjs. This file
// drives the REAL app in Chromium and asserts the four properties that make the
// feature worth having, each of which failed silently in some earlier form of
// this codebase:
//
//   ZTO-01/02  a rejected admin token leaves NOTHING on disk. "Verify before
//              persist" is easy to write and easy to get backwards.
//   ZTO-03/04  the admin token is absent from the export payload AND from the
//              checksum input — the X-05 class of bug, where the two disagreed
//              and every honest export failed its own integrity check.
//   ZTO-05/06  the `#i=` code is gone from the URL BEFORE the claim request
//              fires. Asserted by reading location.href inside the intercepted
//              request handler, which is the only moment that proves ordering
//              rather than merely eventual cleanup.
//   ZTO-07..10 the wizard refuses to continue until the passphrase is long
//              enough, confirmed, and acknowledged — and the acknowledgement
//              is not decorative, because the passphrase is unrecoverable.
//
// Every network call to the Worker is intercepted; no test here touches the
// production endpoint.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/zero-token-onboarding.spec.mjs');

const WORKER = 'https://freightlogic-backup.fimseitef.workers.dev';
const VALID_CODE = 'ABCDEFGHIJKLMNOPQRSTUVWX'; // 24 chars, base32 alphabet
const FAKE_TOKEN = 'flk_' + 'a1b2c3d4'.repeat(4);   // flk_ + 32 hex

/** Serve the Worker's API from the test process. `plan` maps a path suffix to a
 *  handler; anything unrouted 404s loudly rather than escaping to the network. */
async function routeWorker(page, plan, log) {
  await page.route(WORKER + '/**', async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const entry = { path: url.pathname, method: req.method(), headers: req.headers() };
    try { entry.body = req.postData(); } catch (_) { entry.body = null; }
    // The page URL AT THE MOMENT THE REQUEST IS MADE. This is the whole point
    // of ZTO-05: capturing it after the fact would pass even if the fragment
    // were stripped late.
    entry.pageUrl = page.url();
    if (log) log.push(entry);
    const handler = plan[url.pathname];
    if (!handler) return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ ok: false, error: 'unrouted ' + url.pathname }) });
    const out = await handler(entry);
    return route.fulfill({ status: out.status, contentType: 'application/json', body: JSON.stringify(out.body ?? {}) });
  });
}

/** Give the device an App Lock PIN, which admin access now requires: the admin
 *  token is stored as ciphertext keyed by the PIN, so without one there is no
 *  key and the only way to persist would be in the clear. */
async function setPin(page, pin = '4321') {
  await page.evaluate(async (p) => {
    await window.__FL_TESTS.setSetting('appLockEnabled', true);
    await window.__FL_TESTS.setSetting('appLockPin', await window.__FL_TESTS.hashPin(p));
  }, pin);
}

/** Drive the PIN modal that adminPinPrompt() opens. */
async function answerPinModal(page, pin = '4321') {
  await page.waitForSelector('#adminPinEntry', { timeout: 5000 });
  await page.fill('#adminPinEntry', pin);
  await page.click('#adminPinGo');
}

async function openApp(opts = {}) {
  const app = await launchApp(opts);
  await skipFirstRunWizard(app.page);
  return app;
}

/** Open the app at an invite link with a REAL document load.
 *
 *  page.goto('…/index.html#i=CODE') from '…/index.html' is a SAME-DOCUMENT
 *  navigation — the browser changes the hash and runs nothing. Boot never
 *  re-executes, flCaptureClaimCode() never runs, and the wizard never opens; an
 *  earlier version of this spec timed out waiting for it and looked like a
 *  product defect. Bouncing through about:blank forces a genuine load, which is
 *  what a driver tapping a link in Messages actually gets. */
async function openInviteLink(app, code) {
  await app.page.goto('about:blank');
  await app.page.goto(`${app.baseUrl}/index.html#i=${code}`, { waitUntil: 'load' });
}

/** Wait for the claim wizard AND for the app to have taken the focus it intends
 *  to take. Both halves are required, and the second half is not politeness.
 *
 *  `openClaimWizard()` ends with `setTimeout(() => pass.focus(), 120)` so a
 *  driver can start typing without reaching for the field. `waitForSelector`
 *  resolves the instant the host is appended — t≈0 of that timer — so a fill
 *  issued immediately is racing it. Playwright's `fill()` focuses its target and
 *  then inserts the text as an editing command against whatever is focused AT
 *  THAT MOMENT; if the app's timer fires in between, the text lands in
 *  `#claimPass` instead of where the locator pointed.
 *
 *  Observed, not theorised. Under CPU contention ZTO-09 failed with
 *  `#claimPass` holding 42 characters — 'correct-horse-battery' typed twice —
 *  and `#claimPass2` empty, so the confirmation never matched, Continue stayed
 *  disabled, and the click timed out 30s later reporting "element is not
 *  enabled". That reads exactly like a product defect in the enable logic, and
 *  it is not one: the same failure cleared on a re-run, which is how it reached
 *  `main` (Tests run 35084126731 attempt 1 hit the sibling case in
 *  tax-export-csv-corruption and went green on attempt 2).
 *
 *  Waiting weakens nothing. Every assertion in these tests is about what the
 *  wizard DOES with the values, never about how soon it can accept them; on a
 *  real phone no human types into the confirm field within 120ms of a
 *  full-screen wizard appearing. ZTO-15 pins the auto-focus itself, so if it is
 *  ever removed the cause of this wait is a failing assertion rather than five
 *  mysterious timeouts.
 *
 *  THIS BODY SHIPPED EMPTY ONCE. The first attempt at this repair was merged in
 *  PR #213 with the focus wait replaced by `/* NEGATIVE CONTROL: focus wait
 *  removed *​/` — the control edit was never restored, because the command that
 *  was supposed to restore it died on a `pkill` pattern that matched its own
 *  shell. Neither verification caught it: `grep -c claimWizardReady` counts an
 *  IDENTIFIER and returns the same number with the body empty, and re-running
 *  the spec unloaded passes either way, because unloaded is exactly the
 *  condition under which the race does not fire. Two green signals, both blind
 *  to the only thing that mattered — the same shape as OI-11 and as checklist
 *  item 15. Verify a repair by removing it and watching a test fail, under the
 *  conditions that make it fail, and never by counting a symbol. */
async function claimWizardReady(page) {
  await page.waitForSelector('#claimWizard', { timeout: 15000 });
  try {
    await page.waitForFunction(() => document.activeElement?.id === 'claimPass', null, { timeout: 15000 });
  } catch (_) {
    throw new Error('the claim wizard never focused #claimPass — see ZTO-15; these tests wait for that focus so it cannot land mid-fill');
  }
}

// ── Owner: admin access is verified before it is stored ──────────────────────

test('[ZTO-01] a REJECTED admin token is not persisted anywhere', async () => {
  const app = await openApp();
  try {
    await setPin(app.page);
    await routeWorker(app.page, { '/admin/users': async () => ({ status: 401, body: { ok: false, error: 'Unauthorized' } }) });

    const saved = await app.page.evaluate(async () => {
      document.querySelector('#adminToken').value = 'definitely-wrong-admin-token';
      const result = await window.__FL_TESTS.cloudAdminSaveAccess();
      return {
        result,
        stored: await window.__FL_TESTS.getSetting('cloudAdminTokenEnc', null),
        session: sessionStorage.getItem('fl_admin_tok'),
        local: localStorage.getItem('fl_admin_tok'),
        stateText: document.querySelector('#adminAccessState')?.textContent || '',
      };
    });

    eq(saved.result, false, 'saving a rejected token must report failure');
    eq(saved.stored, null, 'a rejected token must NOT be written to IndexedDB settings');
    eq(saved.session, null, 'a rejected token must not reach sessionStorage');
    eq(saved.local, null, 'a rejected token must never reach localStorage');
    ok(/rejected/i.test(saved.stateText), `the UI must say it was rejected, got "${saved.stateText}"`);
    ok(!saved.stateText.includes('definitely-wrong'), 'the rejected value must not be echoed back into the UI');
  } finally { await app.close(); }
});

test('[ZTO-02] an ACCEPTED admin token is stored as ciphertext, never as plaintext', async () => {
  const app = await openApp();
  try {
    await setPin(app.page);
    await routeWorker(app.page, { '/admin/users': async () => ({ status: 200, body: { ok: true, users: [] } }) });

    const done = app.page.evaluate(async () => {
      document.querySelector('#adminToken').value = 'real-admin-token-abc123';
      return await window.__FL_TESTS.cloudAdminSaveAccess();
    });
    await answerPinModal(app.page);
    eq(await done, true, 'a verified token must be saved');

    const after = await app.page.evaluate(async () => {
      const blob = await window.__FL_TESTS.getSetting('cloudAdminTokenEnc', null);
      // Dump the entire settings store, the way an attacker with the IndexedDB
      // file would see it.
      const all = await window.__FL_TESTS.dumpStore('settings');
      return {
        blob,
        rawDump: JSON.stringify(all),
        fieldValue: document.querySelector('#adminToken')?.value,
        stateText: document.querySelector('#adminAccessState')?.textContent || '',
        local: localStorage.getItem('fl_admin_tok'),
      };
    });

    ok(after.blob && after.blob.encrypted && after.blob.iv && after.blob.salt,
      'the stored value must be an AES-GCM envelope (encrypted/iv/salt)');
    ok(!after.rawDump.includes('real-admin-token-abc123'),
      'the PLAINTEXT admin token must not appear anywhere in the settings store');
    eq(after.fieldValue, '', 'the input must be cleared after saving');
    ok(/configured/i.test(after.stateText), `the panel must show the configured state, got "${after.stateText}"`);
    eq(after.local, null, 'the admin token must never be written to localStorage');
  } finally { await app.close(); }
});

test('[ZTO-03] admin access survives a browser restart and is re-usable with the PIN', async () => {
  const app = await openApp();
  try {
    await setPin(app.page);
    await routeWorker(app.page, { '/admin/users': async () => ({ status: 200, body: { ok: true, users: [] } }) });
    const save = app.page.evaluate(async () => {
      document.querySelector('#adminToken').value = 'real-admin-token-abc123';
      return await window.__FL_TESTS.cloudAdminSaveAccess();
    });
    await answerPinModal(app.page);
    eq(await save, true, 'setup must succeed');

    await app.page.reload({ waitUntil: 'load' });
    await app.page.waitForFunction(() => !!window.__FL_TESTS, null, { timeout: 15000 });
    await routeWorker(app.page, { '/admin/users': async () => ({ status: 200, body: { ok: true, users: [] } }) });

    // The ciphertext is what has to survive a reload, and does.
    const survived = await app.page.evaluate(async () => await window.__FL_TESTS.getSetting('cloudAdminTokenEnc', null));
    ok(survived && survived.encrypted, 'the encrypted envelope must survive a reload');

    // Now end the SESSION. A reload does not: sessionStorage is scoped to the
    // tab and outlives any number of reloads — only closing the tab or the
    // browser clears it. An earlier version of this test asserted that a reload
    // emptied it and "failed" against correct behaviour, which would have been
    // a real defect to chase. Clearing it explicitly is what a tab close does,
    // and it is the situation that used to force the owner to retype a
    // 36-character secret on every restart.
    await app.page.evaluate(() => sessionStorage.removeItem('fl_admin_tok'));
    const beforePin = await app.page.evaluate(() => sessionStorage.getItem('fl_admin_tok'));
    eq(beforePin, null, 'precondition: the session copy is gone, as after a browser restart');

    const resolved = app.page.evaluate(async () => await window.__FL_TESTS.cloudAdminResolveToken());
    await answerPinModal(app.page);
    eq(await resolved, 'real-admin-token-abc123', 'the PIN must decrypt the stored token back');
  } finally { await app.close(); }
});

test('[ZTO-04] a WRONG PIN does not yield the admin token', async () => {
  const app = await openApp();
  try {
    await setPin(app.page, '4321');
    await routeWorker(app.page, { '/admin/users': async () => ({ status: 200, body: { ok: true, users: [] } }) });
    const save = app.page.evaluate(async () => {
      document.querySelector('#adminToken').value = 'real-admin-token-abc123';
      return await window.__FL_TESTS.cloudAdminSaveAccess();
    });
    await answerPinModal(app.page, '4321');
    await save;

    await app.page.evaluate(() => sessionStorage.removeItem('fl_admin_tok'));
    const resolved = app.page.evaluate(async () => await window.__FL_TESTS.cloudAdminResolveToken());
    await app.page.waitForSelector('#adminPinEntry', { timeout: 5000 });
    await app.page.fill('#adminPinEntry', '9999');
    await app.page.click('#adminPinGo');
    // A wrong PIN must not close the modal into a success — it re-prompts.
    await app.page.waitForTimeout(300);
    const err = await app.page.textContent('#adminPinErr').catch(() => '');
    ok(/did not match/i.test(err || ''), `a wrong PIN must be reported, got "${err}"`);
    await app.page.click('#adminPinCancel');
    eq(await resolved, '', 'cancelling must yield no token');
  } finally { await app.close(); }
});

// ── The export guardrail (the X-05 class) ────────────────────────────────────

test('[ZTO-05] the admin token is absent from the export AND from its checksum input', async () => {
  const app = await openApp();
  try {
    const out = await app.page.evaluate(async () => {
      await window.__FL_TESTS.setSetting('cloudAdminTokenEnc', { encrypted: 'ADMIN-CIPHERTEXT-MARKER', iv: 'IVMARK', salt: 'SALTMARK' });
      await window.__FL_TESTS.setSetting('cloudBackupToken', 'flk_backuptokenmarker00000000000000');
      await window.__FL_TESTS.setSetting('weeklyGoal', 4000); // ordinary key, for contrast

      let captured = null;
      const orig = URL.createObjectURL.bind(URL);
      URL.createObjectURL = (blob) => { captured = blob.text(); return orig(blob); };
      await window.__FL_TESTS.exportJSON();
      const text = await captured;
      URL.createObjectURL = orig;

      const data = JSON.parse(text);
      // Recompute the checksum over the payload's OWN settings array. If the
      // export had checksummed an unfiltered dump while writing a filtered one,
      // this is where it would disagree — the exact X-05 failure.
      const verify = await window.__FL_TESTS.computeExportChecksumFull(
        data.trips, data.expenses, data.fuel, data.settings);
      return {
        text,
        keys: (data.settings || []).map(s => s.key),
        checksumFull: data.meta.checksumFull,
        verify,
        isSafe: window.__FL_TESTS.isSettingExportSafe('cloudAdminTokenEnc'),
      };
    });

    eq(out.isSafe, false, 'isSettingExportSafe must refuse cloudAdminTokenEnc');
    ok(!out.keys.includes('cloudAdminTokenEnc'), `the admin key must not be exported, saw ${out.keys.join(',')}`);
    ok(!out.keys.includes('cloudBackupToken'), 'the backup token must not be exported either');
    ok(out.keys.includes('weeklyGoal'), 'ordinary settings must still export — this is not a blanket drop');
    ok(!out.text.includes('ADMIN-CIPHERTEXT-MARKER'), 'no part of the admin envelope may appear in the payload');
    ok(!out.text.includes('flk_backuptokenmarker'), 'no bearer token may appear in the payload');
    eq(out.verify, out.checksumFull,
      'checksumFull must verify against the payload it ships with — filter FIRST, then checksum');
  } finally { await app.close(); }
});

// ── Driver: the claim flow ───────────────────────────────────────────────────

test('[ZTO-06] the #i= code is stripped from the URL BEFORE the claim request fires', async () => {
  const app = await openApp();
  try {
    const log = [];
    await routeWorker(app.page, {
      '/claim': async () => ({ status: 200, body: { ok: true, userId: 'u_test', name: 'Dana', token: FAKE_TOKEN } }),
      '/backup': async () => ({ status: 200, body: { ok: true } }),
      '/backup/delta': async () => ({ status: 200, body: { ok: true } }),
    }, log);

    await openInviteLink(app, VALID_CODE);
    await claimWizardReady(app.page);

    // Stripped at boot, before the wizard even renders.
    const urlAtWizard = app.page.url();
    ok(!urlAtWizard.includes(VALID_CODE), `the code must be gone from the URL, got ${urlAtWizard}`);
    ok(!urlAtWizard.includes('#i='), `the fragment must be removed entirely, got ${urlAtWizard}`);

    await app.page.fill('#claimPass', 'correct-horse-battery');
    await app.page.fill('#claimPass2', 'correct-horse-battery');
    await app.page.check('#claimAck');
    await app.page.click('#claimGo');
    await app.page.waitForFunction(() => !document.querySelector('#claimWizard'), null, { timeout: 15000 });

    const claim = log.find(e => e.path === '/claim');
    ok(claim, 'a /claim request must have been made');
    eq(JSON.parse(claim.body).code, VALID_CODE, 'the captured code must be sent in the POST body');
    // The assertion that proves ORDERING, not eventual cleanup.
    ok(!claim.pageUrl.includes(VALID_CODE),
      `the URL must already be clean when /claim fires, was ${claim.pageUrl}`);
    ok(!claim.headers['x-admin-token'], 'the admin token must never be sent to /claim');
    ok(!claim.headers['x-backup-token'], '/claim must not carry a backup token');
  } finally { await app.close(); }
});

test('[ZTO-07] a successful claim stores the token and never renders it', async () => {
  const app = await openApp();
  try {
    await routeWorker(app.page, {
      '/claim': async () => ({ status: 200, body: { ok: true, userId: 'u_test', name: 'Dana', token: FAKE_TOKEN } }),
      '/backup': async () => ({ status: 200, body: { ok: true } }),
      '/backup/delta': async () => ({ status: 200, body: { ok: true } }),
    });
    await openInviteLink(app, VALID_CODE);
    await claimWizardReady(app.page);
    await app.page.fill('#claimPass', 'correct-horse-battery');
    await app.page.fill('#claimPass2', 'correct-horse-battery');
    await app.page.check('#claimAck');
    await app.page.click('#claimGo');
    await app.page.waitForFunction(() => !document.querySelector('#claimWizard'), null, { timeout: 15000 });

    const after = await app.page.evaluate(async () => ({
      token: await window.__FL_TESTS.getSetting('cloudBackupToken', ''),
      pass: sessionStorage.getItem('fl_cloud_pass'),
      name: await window.__FL_TESTS.getSetting('driverDisplayName', ''),
      bodyText: document.body.innerText,
      bodyHtml: document.body.innerHTML,
    }));

    eq(after.token, FAKE_TOKEN, 'the claimed token must be stored');
    eq(after.pass, 'correct-horse-battery', 'the passphrase must be in sessionStorage only');
    eq(after.name, 'Dana', 'the invited name must be recorded');
    ok(!after.bodyText.includes(FAKE_TOKEN), 'the token must not be visible anywhere on screen');
    ok(!after.bodyHtml.includes(FAKE_TOKEN), 'the token must not be present in the DOM at all');
    ok(!after.bodyText.includes(VALID_CODE), 'the claim code must not be visible either');
  } finally { await app.close(); }
});

test('[ZTO-08] Continue is blocked until the passphrase is long enough, confirmed AND acknowledged', async () => {
  const app = await openApp();
  try {
    await routeWorker(app.page, { '/claim': async () => ({ status: 200, body: { ok: true, userId: 'u_x', name: 'D', token: FAKE_TOKEN } }) });
    await openInviteLink(app, VALID_CODE);
    await claimWizardReady(app.page);

    const disabled = () => app.page.isDisabled('#claimGo');
    eq(await disabled(), true, 'Continue must start disabled');

    // Too short, even though confirmed and acknowledged.
    await app.page.fill('#claimPass', 'short');
    await app.page.fill('#claimPass2', 'short');
    await app.page.check('#claimAck');
    eq(await disabled(), true, 'a passphrase under 10 characters must not be accepted');

    // Long enough and acknowledged, but the confirmation does not match.
    await app.page.fill('#claimPass', 'correct-horse-battery');
    await app.page.fill('#claimPass2', 'correct-horse-batteryX');
    eq(await disabled(), true, 'a mismatched confirmation must not be accepted');

    // Long enough and matching, but NOT acknowledged. The acknowledgement is
    // load-bearing: the passphrase cannot be reset, so a driver must not be
    // able to tap past this on momentum.
    await app.page.fill('#claimPass2', 'correct-horse-battery');
    await app.page.uncheck('#claimAck');
    eq(await disabled(), true, 'an unacknowledged passphrase must not be accepted');

    await app.page.check('#claimAck');
    eq(await disabled(), false, 'all three satisfied — Continue must enable');
  } finally { await app.close(); }
});

test('[ZTO-09] an expired invite (410) and a rate-limited one (429) each say so, and store nothing', async () => {
  for (const [status, needle] of [[410, /expired or was already used/i], [429, /too many attempts/i]]) {
    const app = await openApp();
    try {
      await routeWorker(app.page, { '/claim': async () => ({ status, body: { ok: false, error: 'x' } }) });
      await openInviteLink(app, VALID_CODE);
      await claimWizardReady(app.page);
      await app.page.fill('#claimPass', 'correct-horse-battery');
      await app.page.fill('#claimPass2', 'correct-horse-battery');
      await app.page.check('#claimAck');
      await app.page.click('#claimGo');
      await app.page.waitForFunction(() => (document.querySelector('#claimError')?.textContent || '').length > 0, null, { timeout: 10000 });

      const state = await app.page.evaluate(async () => ({
        err: document.querySelector('#claimError')?.textContent || '',
        token: await window.__FL_TESTS.getSetting('cloudBackupToken', ''),
        stillOpen: !!document.querySelector('#claimWizard'),
        canRetry: !document.querySelector('#claimGo')?.disabled,
      }));

      ok(needle.test(state.err), `${status} should explain itself, got "${state.err}"`);
      eq(state.token, '', `a failed claim must store no token (status ${status})`);
      eq(state.stillOpen, true, 'the wizard must stay open so the driver is not stranded');
      eq(state.canRetry, true, 'Continue must be re-enabled so a retry is possible');
    } finally { await app.close(); }
  }
});

test('[ZTO-10] a malformed #i= fragment is stripped and opens no wizard', async () => {
  const app = await openApp();
  try {
    await routeWorker(app.page, { '/claim': async () => ({ status: 200, body: { ok: true, userId: 'u_x', name: 'D', token: FAKE_TOKEN } }) });
    await openInviteLink(app, 'nope');
    await app.page.waitForFunction(() => !!window.__FL_TESTS, null, { timeout: 15000 });
    await app.page.waitForTimeout(500);

    const state = await app.page.evaluate(() => ({ url: location.href, wizard: !!document.querySelector('#claimWizard') }));
    eq(state.wizard, false, 'a malformed code must not open the claim wizard');
    // Stripped anyway: a value that never validates should still not sit in the
    // address bar, in history, or in whatever the next share sheet copies.
    ok(!state.url.includes('#i='), `a malformed fragment must still be stripped, got ${state.url}`);
  } finally { await app.close(); }
});

test('[ZTO-13] the claim wizard is a REAL credential form, so the keychain can save it', async () => {
  const app = await openApp();
  try {
    await routeWorker(app.page, { '/claim': async () => ({ status: 200, body: { ok: true, userId: 'u_x', name: 'D', token: FAKE_TOKEN } }) });
    await openInviteLink(app, VALID_CODE);
    await claimWizardReady(app.page);

    const shape = await app.page.evaluate(async () => {
      const form = document.querySelector('#claimForm');
      const acct = document.querySelector('#claimAcct');
      const pass = document.querySelector('#claimPass');
      const go = document.querySelector('#claimGo');
      const cs = acct ? getComputedStyle(acct) : null;
      return {
        isForm: form?.tagName,
        acctAutocomplete: acct?.getAttribute('autocomplete'),
        acctReadonly: acct?.hasAttribute('readonly'),
        acctValue: acct?.value,
        acctVisible: !!(cs && cs.display !== 'none' && cs.visibility !== 'hidden'),
        passAutocomplete: pass?.getAttribute('autocomplete'),
        submitType: go?.getAttribute('type'),
        localUserId: await window.__FL_TESTS.getSetting('localUserId', ''),
      };
    });

    // Every part of this is load-bearing, for the reasons v24.0.6 recorded: a
    // password manager keys its save prompt off a real submit event and ignores
    // a display:none username field.
    eq(shape.isForm, 'FORM', 'the wizard must submit a real <form>');
    eq(shape.submitType, 'submit', 'Continue must be a genuine submit button, not a click handler');
    eq(shape.acctAutocomplete, 'username', 'the account field must be autocomplete=username');
    eq(shape.passAutocomplete, 'new-password', 'the passphrase field must be autocomplete=new-password');
    eq(shape.acctReadonly, true, 'the account field is not for the driver to edit');
    eq(shape.acctVisible, true, 'a hidden username field is ignored by Safari — it must be visible');
    // The account MUST match what openCloudReconnect() later asks for, or the
    // credential saved here is not the one offered back and the driver retypes
    // the passphrase on every browser restart.
    eq(shape.acctValue, shape.localUserId, 'the account must be localUserId, the same value openCloudReconnect uses');
  } finally { await app.close(); }
});

test('[ZTO-14] claiming never writes the passphrase to disk', async () => {
  const app = await openApp();
  try {
    await routeWorker(app.page, {
      '/claim': async () => ({ status: 200, body: { ok: true, userId: 'u_x', name: 'Dana', token: FAKE_TOKEN } }),
      '/backup': async () => ({ status: 200, body: { ok: true } }),
      '/backup/delta': async () => ({ status: 200, body: { ok: true } }),
    });
    await openInviteLink(app, VALID_CODE);
    await claimWizardReady(app.page);
    await app.page.fill('#claimPass', 'correct-horse-battery');
    await app.page.fill('#claimPass2', 'correct-horse-battery');
    await app.page.check('#claimAck');
    await app.page.click('#claimGo');
    await app.page.waitForFunction(() => !document.querySelector('#claimWizard'), null, { timeout: 15000 });

    const where = await app.page.evaluate(async () => ({
      session: sessionStorage.getItem('fl_cloud_pass'),
      local: JSON.stringify(Object.entries(localStorage)),
      settings: JSON.stringify(await window.__FL_TESTS.dumpStore('settings')),
    }));

    // The passphrase is session-scoped by design. Persisting it would remove the
    // re-entry friction by weakening the encryption instead of by using the OS
    // keychain, which is exactly the trade CLAUDE.md forbids.
    eq(where.session, 'correct-horse-battery', 'the passphrase belongs in sessionStorage');
    ok(!where.local.includes('correct-horse-battery'), 'the passphrase must never reach localStorage');
    ok(!where.settings.includes('correct-horse-battery'), 'the passphrase must never reach the settings store');
  } finally { await app.close(); }
});

// ── Owner: the invite surface says nothing about tokens ──────────────────────

test('[ZTO-11] the Drivers surface never uses the word "token"', async () => {
  const app = await openApp();
  try {
    await setPin(app.page);
    await routeWorker(app.page, {
      '/admin/users': async () => ({ status: 200, body: { ok: true, users: [
        { userId: 'u_aaa', name: 'Dana', createdAt: '2026-09-01T00:00:00Z', active: true, backupCount: 12 },
      ] } }),
    });
    const save = app.page.evaluate(async () => {
      document.querySelector('#adminToken').value = 'real-admin-token-abc123';
      return await window.__FL_TESTS.cloudAdminSaveAccess();
    });
    await answerPinModal(app.page);
    await save;

    const listText = await app.page.evaluate(async () => {
      await window.__FL_TESTS.cloudAdminLoadUsers();
      return {
        list: document.querySelector('#adminUserList')?.innerText || '',
        drivers: document.querySelector('#adminDriversBlock')?.innerText || '',
      };
    });

    ok(/Dana/.test(listText.list), `the driver must be listed, got "${listText.list}"`);
    ok(/Re-invite/i.test(listText.list), 'the list must offer Re-invite');
    ok(!/token/i.test(listText.list), `the driver list must not say "token", got "${listText.list}"`);
    ok(!/token/i.test(listText.drivers), `the Drivers block must not say "token", got "${listText.drivers}"`);
  } finally { await app.close(); }
});

test('[ZTO-12] inviting a driver builds a #i= link and never requests /admin/users POST', async () => {
  const app = await openApp();
  try {
    await setPin(app.page);
    const log = [];
    await routeWorker(app.page, {
      '/admin/users': async () => ({ status: 200, body: { ok: true, users: [] } }),
      '/admin/invites': async () => ({ status: 201, body: { ok: true, name: 'Dana', code: VALID_CODE, expiresAt: new Date(Date.now() + 72 * 3600 * 1000).toISOString() } }),
    }, log);
    const save = app.page.evaluate(async () => {
      document.querySelector('#adminToken').value = 'real-admin-token-abc123';
      return await window.__FL_TESTS.cloudAdminSaveAccess();
    });
    await answerPinModal(app.page);
    await save;

    await app.page.evaluate(() => { window.prompt = () => 'Dana'; window.navigator.share = undefined; });
    await app.page.evaluate(async () => { await window.__FL_TESTS.cloudAdminInviteDriver('', false); });
    await app.page.waitForSelector('#adminInviteShare', { timeout: 10000 });

    const invite = await app.page.evaluate(() => {
      const sms = document.querySelector('#adminInviteSms')?.getAttribute('href') || '';
      return { sms, modalText: document.querySelector('#modalBody')?.innerText || '' };
    });

    ok(invite.sms.includes(encodeURIComponent('#i=' + VALID_CODE)) || invite.sms.includes('%23i%3D'),
      `the SMS fallback must carry the #i= link, got ${invite.sms.slice(0, 200)}`);
    ok(/Dana/.test(invite.modalText), 'the invite modal must name the driver');
    ok(!invite.modalText.includes(VALID_CODE), 'the raw code must not be displayed as a value to read out');
    ok(!/token/i.test(invite.modalText), `the invite modal must not say "token", got "${invite.modalText}"`);

    // The whole point: onboarding no longer mints a bearer token.
    const posts = log.filter(e => e.path === '/admin/users' && e.method === 'POST');
    eq(posts.length, 0, 'inviting must NOT call POST /admin/users — that is the raw-token path');
    const invites = log.filter(e => e.path === '/admin/invites' && e.method === 'POST');
    eq(invites.length, 1, 'inviting must call POST /admin/invites exactly once');
    ok(invites[0].headers['x-admin-token'] === 'real-admin-token-abc123', 'the admin token authorises /admin/invites');
  } finally { await app.close(); }
});

test('[ZTO-15] the wizard puts the cursor in the passphrase field', async () => {
  const app = await openApp();
  try {
    await routeWorker(app.page, { '/claim': async () => ({ status: 200, body: { ok: true, userId: 'u_x', name: 'D', token: FAKE_TOKEN } }) });
    await openInviteLink(app, VALID_CODE);
    await app.page.waitForSelector('#claimWizard', { timeout: 15000 });

    // A driver opening an invite link has exactly one thing to do, and the
    // wizard is full-screen with nothing else on it. Landing the cursor in the
    // passphrase field is the behaviour, not an implementation detail — and it
    // is the invariant `claimWizardReady()` waits on, so if this fails, that
    // helper is the thing to revisit rather than the six tests calling it.
    await app.page.waitForFunction(() => document.activeElement?.id === 'claimPass', null, { timeout: 15000 });

    // With the first-run wizard suppressed, focus must then STAY where it is put.
    // V-2 below is the same check without that suppression, and it does not pass.
    await app.page.focus('#claimPass2');
    await app.page.waitForTimeout(1500);
    const settled = await app.page.evaluate(() => document.activeElement?.id);
    eq(settled, 'claimPass2', 'with no first-run modal, nothing may take focus back');
  } finally { await app.close(); }
});

/* ── V-2: the first-run setup modal steals focus from an open claim wizard ────
 *
 * Deliberately `launchApp()` and NOT `openApp()` — the only invite test here
 * that does not suppress the F26 first-run wizard, because that wizard IS the
 * subject. `openClaimWizard()`'s own comment says the claim wizard "covers the
 * app at z-index 12000 while the rest of boot continues behind it". The rest of
 * boot includes `checkFirstRunSetup()`, armed on an 800ms `setTimeout`, and
 * `openModal()` focuses the first focusable element in whatever it opens.
 *
 * So ~800ms after a driver taps an invite link, while they are typing a
 * passphrase into a full-screen wizard, the keyboard focus jumps to a modal
 * behind it. Whatever they type next goes somewhere else — and in a field whose
 * value is masked, with a confirmation field that will then refuse to match,
 * against a passphrase that by design cannot be reset.
 *
 * OBSERVED, not inferred. This assertion was first written as part of ZTO-15
 * expecting focus to settle, and it failed with `document.activeElement.id`
 * equal to `modalClose` — the F26 modal's own close button.
 *
 * Tagged `/ NEW`: a green NEW test means the evidence is captured, not that the
 * defect is repaired. The fix is in `app.js` — `checkFirstRunSetup()` should
 * stand down while a claim wizard is open, which is one condition — and `app.js`
 * is SHARED and needs a release generation, so it is reported rather than taken
 * unilaterally. When it lands, this flips to asserting `claimPass2` and merges
 * back into ZTO-15. */
test('[FINDING V-2 / NEW] the first-run setup modal takes focus away from the claim wizard', async () => {
  const app = await launchApp();
  try {
    await routeWorker(app.page, { '/claim': async () => ({ status: 200, body: { ok: true, userId: 'u_x', name: 'D', token: FAKE_TOKEN } }) });
    await openInviteLink(app, VALID_CODE);
    await app.page.waitForSelector('#claimWizard', { timeout: 15000 });
    await app.page.waitForFunction(() => document.activeElement?.id === 'claimPass', null, { timeout: 15000 });

    // Stand where the driver stands: in the confirm field, mid-entry.
    await app.page.focus('#claimPass2');
    // 1500ms outlasts the 800ms checkFirstRunSetup() timer. A shorter window
    // would pass while leaving the hazard unobserved, which is the whole point.
    await app.page.waitForTimeout(1500);

    const state = await app.page.evaluate(() => ({
      focused: document.activeElement?.id || document.activeElement?.tagName,
      wizardStillOpen: !!document.querySelector('#claimWizard'),
      modalOpen: !!document.querySelector('#modal'),
    }));
    console.log(`    [evidence] focus after 1500ms in the confirm field: ${state.focused}` +
                ` (claim wizard open: ${state.wizardStillOpen}, first-run modal open: ${state.modalOpen})`);

    ok(state.wizardStillOpen, 'the claim wizard must still be open — otherwise this is a different defect');
    ok(state.focused !== 'claimPass2',
      'V-2 is reproduced when the driver loses the field they were typing in — if focus now STAYS, ' +
      'the app.js repair has landed and this test must be flipped to assert claimPass2 and retagged / FIXED');
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
