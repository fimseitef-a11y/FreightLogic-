// v24.0.13 — zero-token driver onboarding, app half.
//
// The Worker half lives in tests/unit/worker-invite-claim.spec.mjs. This file
// drives the REAL app in Chromium and asserts the four properties that make the
// feature worth having, each of which failed silently in some earlier form of
// this codebase:
//
//   ZTO-01/02  (Issue #231 Phase C) the driver app carries no admin surface,
//              and a leftover admin credential from an earlier build is deleted.
//   ZTO-05     a legacy admin key is absent from the export payload AND from the
//              checksum input — the X-05 class of bug.
//   ZTO-06     the `#i=` code is gone from the URL BEFORE the claim request
//              fires. Asserted by reading location.href inside the intercepted
//              request handler, which is the only moment that proves ordering
//              rather than merely eventual cleanup.
//   ZTO-07..10 the wizard refuses to continue until the passphrase is long
//              enough, confirmed, and acknowledged — and the acknowledgement
//              is not decorative, because the passphrase is unrecoverable.
//
// Every network call to the Worker is intercepted; no test here touches the
// production endpoint.
import { launchApp, skipFirstRunWizard, waitForAppReady, createSuite, ok, eq } from '../lib/harness.mjs';

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

// ── Issue #231 Phase C: the driver app carries no admin surface ─────────────
//
// v24.0.13–v24.0.32 shipped an owner/admin panel inside the driver app. Driver
// management now lives on the separate Admin Console origin, proven live before
// this removal. These replace the old in-app admin-token tests: absence is the
// contract now, and a leftover credential from an earlier build is DELETED.

test('[ZTO-01] the driver app has no admin UI, no admin exports and no admin API calls', async () => {
  const app = await openApp();
  try {
    const out = await app.page.evaluate(() => ({
      dom: ['#btnAdminToggle', '#adminPanel', '#adminToken', '#btnAdminSaveAccess', '#btnAdminCreate', '#adminUserList']
        .filter(sel => document.querySelector(sel)),
      exports: Object.keys(window.__FL_TESTS || {}).filter(k => k.startsWith('cloudAdmin') || k.includes('AdminAccess')),
      adminScript: [...document.scripts].some(sc => /admin-driver-ui/.test(sc.src || '')),
    }));
    eq(out.dom.length, 0, `admin controls must be absent, found ${out.dom.join(', ')}`);
    eq(out.exports.length, 0, `admin functions must be gone, found ${out.exports.join(', ')}`);
    eq(out.adminScript, false, 'admin-driver-ui.js must not be loaded');
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../../app.js', import.meta.url), 'utf8');
    ok(!/['"`]\/admin\//.test(src), 'app.js must not call any /admin/ endpoint');
  } finally { await app.close(); }
});

test('[ZTO-02] a leftover admin credential from an earlier build is DELETED at boot', async () => {
  const app = await openApp();
  try {
    await app.page.evaluate(async () => {
      await window.__FL_TESTS.setSetting('cloudAdminTokenEnc', { encrypted: 'LEFTOVER', iv: 'IV', salt: 'SALT' });
      sessionStorage.setItem('fl_admin_tok', 'leftover-session-admin');
      localStorage.setItem('fl_admin_tok', 'leftover-disk-admin');
    });
    await app.page.reload({ waitUntil: 'load' });
    await waitForAppReady(app.page);
    const after = await app.page.evaluate(async () => ({
      stored: await window.__FL_TESTS.getSetting('cloudAdminTokenEnc', null),
      session: sessionStorage.getItem('fl_admin_tok'),
      local: localStorage.getItem('fl_admin_tok'),
    }));
    eq(after.stored, null, 'the PIN-wrapped admin ciphertext must be deleted');
    eq(after.session, null, 'a session admin token must be deleted, never kept');
    eq(after.local, null, 'a legacy on-disk admin token must be deleted, never promoted');
  } finally { await app.close(); }
});

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

/** Issue #221 — a link may no longer INSTALL a bearer credential.
 *
 *  `cloudCheckSetupLink()` accepted `#token=<flk_…>` AND `?token=<flk_…>`, filled
 *  `#cloudBackupToken` and navigated to Settings. Both were the human credential
 *  transport that zero-token onboarding exists to eliminate, kept alive for
 *  compatibility with a flow that had already been deliberately retired — and
 *  the query-string form is strictly worse than the fragment, because a query
 *  string IS sent to the origin, so the token reaches the access log and any
 *  `Referer` before any client-side cleanup can run.
 *
 *  These assert the FIELD, not just the URL. Stripping the address bar while
 *  still loading the credential into the form would look identical in a
 *  URL-only assertion and would leave the whole defect in place. */
async function openLegacyTokenLink(app, suffix) {
  await app.page.goto('about:blank');
  await app.page.goto(`${app.baseUrl}/index.html${suffix}`, { waitUntil: 'load' });
  await app.page.waitForFunction(() => !!window.__FL_TESTS, null, { timeout: 15000 });
  await app.page.waitForTimeout(600);
  return await app.page.evaluate(() => ({
    url: location.href,
    field: document.querySelector('#cloudBackupToken')?.value ?? null,
    stored: null,
  }));
}

test('[ZTO-16] a legacy #token= setup link does not install the token', async () => {
  const app = await openApp();
  try {
    const s = await openLegacyTokenLink(app, `#token=${FAKE_TOKEN}`);
    eq(s.field, '', 'a legacy fragment token must NOT be loaded into the credential field');
    ok(!s.url.includes('token='), `the credential must be stripped from the URL, got ${s.url}`);
    ok(!s.url.includes(FAKE_TOKEN), 'the token must not remain anywhere in the address');

    const persisted = await app.page.evaluate(async () => await window.__FL_TESTS.getSetting('cloudBackupToken', ''));
    eq(persisted, '', 'a link must never persist a bearer token to the settings store');
  } finally { await app.close(); }
});

test('[ZTO-17] a legacy ?token= setup link does not install the token either', async () => {
  const app = await openApp();
  try {
    const s = await openLegacyTokenLink(app, `?token=${FAKE_TOKEN}`);
    eq(s.field, '', 'a legacy query-string token must NOT be loaded into the credential field');
    ok(!s.url.includes('token='), `the credential must be stripped from the URL, got ${s.url}`);

    const persisted = await app.page.evaluate(async () => await window.__FL_TESTS.getSetting('cloudBackupToken', ''));
    eq(persisted, '', 'a link must never persist a bearer token to the settings store');
  } finally { await app.close(); }
});

test('[ZTO-18] retiring token links did not break the #i= claim flow', async () => {
  // The paired control for ZTO-16/17: the replacement path must still work, or
  // "the link does nothing" would be satisfied by breaking onboarding outright.
  const app = await openApp();
  try {
    await routeWorker(app.page, {
      '/claim': async () => ({ status: 200, body: { ok: true, userId: 'u_zto18', name: 'Dana', token: FAKE_TOKEN } }),
    });
    await openInviteLink(app, 'ABCDEFGHJKMNPQRSTVWXYZ23');
    await app.page.waitForSelector('#claimWizard', { timeout: 15000 });
    const wizard = await app.page.evaluate(() => !!document.querySelector('#claimWizard'));
    ok(wizard, 'the claim-code flow must still open the wizard — it is the onboarding authority now');
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

/* ── V-2 (FIXED in v24.0.15): the first-run setup modal took focus from an open
 *    claim wizard ───────────────────────────────────────────────────────────
 *
 * Deliberately `launchApp()` and NOT `openApp()` — the only invite test here
 * that does not suppress the F26 first-run wizard, because that wizard IS the
 * subject. Suppressing it would make this test pass for the wrong reason, which
 * is the entire point of keeping it separate from ZTO-15.
 *
 * `openClaimWizard()`'s own comment says the claim wizard "covers the app at
 * z-index 12000 while the rest of boot continues behind it". The rest of boot
 * included `checkFirstRunSetup()`, armed on an 800ms `setTimeout`, and
 * `openModal()` ends by focusing the first focusable element in whatever it
 * opens. So ~800ms after a driver tapped an invite link, while they were typing
 * a passphrase into a full-screen wizard, the keyboard focus jumped to a modal
 * behind it — into a masked field, with a confirmation that would then refuse to
 * match, for a passphrase that by design cannot be reset.
 *
 * OBSERVED, not inferred. This assertion was first written as part of ZTO-15
 * expecting focus to settle, and it failed with `document.activeElement.id`
 * equal to `modalClose` — the F26 modal's own close button.
 *
 * THE REPAIR (v24.0.15): `checkFirstRunSetup()` returns early while a
 * `#claimWizard` is open. Deferred, not cancelled, and deliberately not marked
 * complete — if the driver abandons the claim, the next boot offers setup
 * normally. */
test('[FINDING V-2 / FIXED] the first-run setup modal leaves the claim wizard alone', async () => {
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
      // `#modal` is STATIC markup in index.html — it is always in the DOM and
      // openModal() merely sets display:block. Asserting on its existence would
      // fail forever and read as a product defect; visibility is the real signal.
      modalOpen: (() => {
        const md = document.querySelector('#modal');
        return !!md && getComputedStyle(md).display !== 'none';
      })(),
    }));
    console.log(`    [evidence] focus after 1500ms in the confirm field: ${state.focused}` +
                ` (claim wizard open: ${state.wizardStillOpen}, first-run modal open: ${state.modalOpen})`);

    ok(state.wizardStillOpen, 'the claim wizard must still be open — otherwise this is a different defect');
    eq(state.focused, 'claimPass2',
      'the driver must keep the field they were typing in — this read "modalClose" before the fix');
    // The stronger half: the first-run modal must not have OPENED at all behind
    // the wizard. Asserting only on focus would still pass if the modal appeared
    // and merely failed to steal focus, which is not the contract.
    eq(state.modalOpen, false,
      'checkFirstRunSetup() must stand down entirely while a claim wizard is open, not just lose the focus race');
  } finally { await app.close(); }
});

export async function runSpec() { return run(); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
