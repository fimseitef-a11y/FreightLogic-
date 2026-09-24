// v24.0.34 — Apple Shortcuts deep links, the relay, and the Notifications &
// Shortcuts settings panel (docs/SHORTCUTS_URL_CONTRACT.md,
// docs/WEB_PUSH_CONTRACT.md).
//
// Every assertion drives the REAL app in Chromium through the REAL router —
// either a fresh boot on a `#do=` URL or a `hashchange` while the app is open —
// and asserts what the driver actually sees: which form opened, what is in its
// fields, and whether anything was saved. Worker calls are intercepted at the
// network boundary, so the relay and push client code under test is shipped
// code.
import { launchApp, skipFirstRunWizard, waitForAppReady, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/shortcuts-deep-links.spec.mjs');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const TOKEN = 'flk_' + 'b'.repeat(32);
const IPHONE_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 27_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Mobile/15E148 Safari/604.1';

async function boot() {
  const app = await launchApp();
  await skipFirstRunWizard(app.page);
  return app;
}

/** Open a deep link. `fresh` = a cold start on the URL (a Shortcut's Open URLs),
 *  otherwise a hashchange in an app that is already open. */
async function openLink(app, frag, { fresh = false } = {}) {
  if (fresh) {
    await app.page.goto('about:blank');
    await app.page.goto(`${app.baseUrl}/index.html#${frag}`, { waitUntil: 'load' });
    await waitForAppReady(app.page);
  } else {
    await app.page.evaluate((f) => { location.hash = '#' + f; }, frag);
  }
  await sleep(700);
}

const modal = (page) => page.evaluate(() => ({
  open: document.getElementById('modal')?.style.display === 'block',
  title: document.getElementById('modalTitle')?.textContent || '',
}));
const val = (page, id) => page.evaluate((i) => document.getElementById(i)?.value ?? null, id);
const count = (page, store) => page.evaluate(async (s) => (await window.__FL_TESTS.dumpStore(s)).length, store);
const toastText = (page) => page.evaluate(() => document.getElementById('toast')?.textContent || '');

/** Intercept the relay endpoints. `items` is mutated by DELETE like the Worker. */
async function stubRelay(page, items) {
  const seen = { deletes: [], gets: 0 };
  await page.route(/\/relay(\/[^?]*)?(\?.*)?$/, async (route) => {
    const req = route.request();
    const u = new URL(req.url());
    if (req.method() === 'GET' && u.pathname.endsWith('/relay')) {
      seen.gets++;
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, items }) });
    }
    if (req.method() === 'DELETE') {
      const id = decodeURIComponent(u.pathname.split('/').pop());
      seen.deletes.push(id);
      const i = items.findIndex(x => x.id === id); if (i >= 0) items.splice(i, 1);
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, removed: 1 }) });
    }
    return route.fallback();
  });
  return seen;
}

test('[SDL-01] a cold-start evaluate link fills the canonical evaluator, scores it, and saves nothing', async () => {
  const app = await boot();
  try {
    await openLink(app, 'do=evaluate&revenue=1450&loaded=612&deadhead=38&origin=Columbus%2C%20OH&dest=Atlanta%2C%20GA', { fresh: true });
    const p = app.page;
    eq(await p.evaluate(() => location.hash), '#omega', 'the do= fragment is replaced by the evaluator route');
    eq(await val(p, 'mwRevenue'), '1450'); eq(await val(p, 'mwLoadedMi'), '612'); eq(await val(p, 'mwDeadMi'), '38');
    eq(await val(p, 'mwOrigin'), 'Columbus, OH'); eq(await val(p, 'mwDest'), 'Atlanta, GA');
    const out = await p.evaluate(() => document.getElementById('mwEvalOutput')?.innerText || '');
    ok(/True RPM/i.test(out), `the canonical evaluator must have scored the load, got: ${out.slice(0, 160)}`);
    eq(await count(p, 'trips'), 0, 'an evaluate link never saves a trip');
  } finally { await app.close(); }
});

test('[SDL-02] an absent deadhead stays UNKNOWN; deadhead=0 is a verified zero', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await openLink(app, 'do=evaluate&revenue=900&loaded=400');
    eq(await val(p, 'mwDeadMi'), '', 'absent deadhead must leave the field blank, not 0');
    ok(/Enter deadhead miles/.test(await p.evaluate(() => document.getElementById('mwEvalOutput')?.innerText || '')),
      'the evaluator must ask for deadhead rather than grade on an invented zero');
    await openLink(app, 'do=evaluate&revenue=900&loaded=400&deadhead=0');
    eq(await val(p, 'mwDeadMi'), '0', 'deadhead=0 is carried as a verified zero');
    ok(/True RPM/i.test(await p.evaluate(() => document.getElementById('mwEvalOutput')?.innerText || '')), 'and the load is graded');
  } finally { await app.close(); }
});

test('[SDL-03] an evaluate link replaces the whole load — no stale broker, weight or dimensions survive', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await openLink(app, 'do=evaluate&revenue=1200&loaded=500&deadhead=20&broker=Old%20Broker&weight=9000&length=200&width=40&height=40');
    eq(await val(p, 'mwBroker'), 'Old Broker');
    await openLink(app, 'do=evaluate&revenue=800&loaded=300&deadhead=10');
    for (const id of ['mwBroker', 'mwLoadWeightLbs', 'mwLoadLengthIn', 'mwLoadWidthIn', 'mwLoadHeightIn', 'mwOrigin', 'mwDest']) {
      eq(await val(p, id), '', `${id} must be cleared by a link that does not carry it`);
    }
  } finally { await app.close(); }
});

test('[SDL-04] an expense link opens Add Expense prefilled, and only Save writes the record', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await openLink(app, 'do=expense&amount=45.10&category=Tolls&note=Ohio%20Turnpike&date=2026-09-20');
    const m = await modal(p);
    ok(m.open && m.title === 'Add Expense', `Add Expense must be open, got ${JSON.stringify(m)}`);
    eq(await val(p, 'f_amt'), '45.1'); eq(await val(p, 'f_cat'), 'Tolls'); eq(await val(p, 'f_notes'), 'Ohio Turnpike');
    eq(await val(p, 'f_date'), '2026-09-20');
    ok(!(await p.$('#f_del')), 'a prefilled form is an ADD form: no Delete button');
    eq(await count(p, 'expenses'), 0, 'nothing is saved before the driver taps Save');
    await p.click('#f_save'); await sleep(500);
    const rows = await p.evaluate(async () => window.__FL_TESTS.dumpStore('expenses'));
    eq(rows.length, 1, 'Save writes exactly one expense'); eq(rows[0].amount, 45.1); eq(rows[0].category, 'Tolls');
  } finally { await app.close(); }
});

test('[SDL-05] a fuel link opens Add Fuel prefilled', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await openLink(app, 'do=fuel&gallons=18.5&total=72.40&state=oh');
    const m = await modal(p);
    ok(m.open && m.title === 'Add Fuel', `Add Fuel must be open, got ${JSON.stringify(m)}`);
    eq(await val(p, 'f_gal'), '18.5'); eq(await val(p, 'f_amt'), '72.4'); eq(await val(p, 'f_state'), 'OH');
    eq(await count(p, 'fuel'), 0, 'nothing is saved before Save');
  } finally { await app.close(); }
});

test('[SDL-06] a trip link opens Add Trip in add mode with every field, and an absent deadhead stays blank', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await openLink(app, 'do=trip&order=7781&pay=1450&loaded=612&customer=ACME%20Logistics&origin=Columbus%2C%20OH&dest=Atlanta%2C%20GA&pickup=2026-09-24&delivery=2026-09-25');
    const m = await modal(p);
    ok(m.open && m.title === 'Add Trip', `Add Trip must be open, got ${JSON.stringify(m)}`);
    eq(await val(p, 'f_orderNo'), '7781'); eq(await val(p, 'f_pay'), '1450'); eq(await val(p, 'f_loaded'), '612');
    eq(await val(p, 'f_empty'), '', 'absent deadhead stays blank (UNKNOWN)');
    eq(await val(p, 'f_customer'), 'ACME Logistics'); eq(await val(p, 'f_origin'), 'Columbus, OH'); eq(await val(p, 'f_dest'), 'Atlanta, GA');
    eq(await val(p, 'f_pickup'), '2026-09-24'); eq(await val(p, 'f_delivery'), '2026-09-25');
    ok(/From a link/.test(await p.evaluate(() => document.getElementById('modalBody')?.innerText || '')), 'the form names its source');
    ok(!(await p.$('#delTrip')), 'no Delete button on a prefilled add form');
    eq(await count(p, 'trips'), 0, 'nothing is saved before Save');
  } finally { await app.close(); }
});

test('[SDL-07] an intake link lands on the Load Intake review draft with the text parsed', async () => {
  const app = await boot();
  try {
    const p = app.page;
    const text = 'Pickup: Columbus, OH\nDeliver: Atlanta, GA\nRate: $1,450\nLoaded miles: 612\nDeadhead: 38 miles';
    await openLink(app, 'do=intake&text=' + encodeURIComponent(text));
    const m = await modal(p);
    ok(m.open && m.title === 'Load Intake', `Load Intake must be open, got ${JSON.stringify(m)}`);
    eq(await val(p, 'liRawText'), text, 'the captured text is in the paste box');
    const stage2 = await p.evaluate(() => { const b = document.getElementById('liSaveTrip'); return !!b && b.offsetParent !== null; });
    ok(stage2, 'the parse ran and the driver is on the review draft');
    eq(await count(p, 'trips'), 0, 'nothing is scored or saved');
  } finally { await app.close(); }
});

test('[SDL-08] refusals: credentials, unknown actions, oversized links; unusable values are dropped and named', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await openLink(app, 'do=expense&amount=5&token=flk_' + 'c'.repeat(32));
    ok(!(await modal(p)).open, 'a link carrying a credential opens nothing');
    ok(/credentials/i.test(await toastText(p)), 'and says why');
    ok(!(await p.evaluate(() => location.href)).includes('flk_'), 'the credential does not stay in the address bar');

    await openLink(app, 'do=wipe-everything');
    ok(!(await modal(p)).open, 'an unknown action opens nothing');
    ok(/not recognized/i.test(await toastText(p)), 'unknown action is explained');

    await openLink(app, 'do=intake&text=' + 'x'.repeat(9000));
    ok(!(await modal(p)).open, 'an oversized link opens nothing');

    await openLink(app, 'do=expense&amount=7&__proto__%5Bpolluted%5D=1&__proto__=x&constructor=y');
    eq(await p.evaluate(() => ({}).polluted), undefined, 'a link cannot write to Object.prototype');
    eq((await modal(p)).title, 'Add Expense', 'the link still opens normally');
    eq(await val(p, 'f_amt'), '7', 'with its real parameters');
    await p.evaluate(() => { document.getElementById('modalClose')?.click(); }); await sleep(400);

    await openLink(app, 'do=expense&amount=999999&category=Tolls');
    ok((await modal(p)).title === 'Add Expense', 'the form still opens');
    eq(await val(p, 'f_amt'), '', 'an out-of-range amount is dropped, not clamped');
    eq(await val(p, 'f_cat'), 'Tolls', 'usable values survive');
    ok(/amount/.test(await toastText(p)), 'the dropped field is named');
  } finally { await app.close(); }
});

test('[SDL-09] a link runs once: the fragment is replaced and a reload does not replay it', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await openLink(app, 'do=expense&amount=12', { fresh: true });
    eq((await modal(p)).title, 'Add Expense');
    eq(await p.evaluate(() => location.hash), '#expenses', 'fragment replaced by the landing route');
    await p.reload({ waitUntil: 'load' }); await waitForAppReady(p); await sleep(600);
    ok(!(await modal(p)).open, 'a reload must not reopen the prefilled form');
  } finally { await app.close(); }
});

test('[SDL-10] iPhone Safari tab: saving actions warn first; the installed app does not', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await app.context.addInitScript((ua) => { Object.defineProperty(navigator, 'userAgent', { get: () => ua }); }, IPHONE_UA);
    await openLink(app, 'do=expense&amount=30', { fresh: true });
    eq((await modal(p)).title, 'Opened in Safari', 'the Safari handoff warning comes first');
    await p.click('#dlSafariCancel'); await sleep(500);
    ok(!(await modal(p)).open, 'Cancel opens nothing');
    await openLink(app, 'do=expense&amount=31');
    eq((await modal(p)).title, 'Opened in Safari');
    await p.click('#dlSafariGo'); await sleep(500);
    eq((await modal(p)).title, 'Add Expense', 'Continue opens the form');
    eq(await val(p, 'f_amt'), '31');

    await app.context.addInitScript(() => { Object.defineProperty(navigator, 'standalone', { get: () => true }); });
    await openLink(app, 'do=expense&amount=32', { fresh: true });
    eq((await modal(p)).title, 'Add Expense', 'the installed Home Screen app goes straight to the form');
  } finally { await app.close(); }
});

test('[SDL-11] a relay link fetches the item, consumes it, and opens it — also via a tapped notification', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await p.evaluate(async (t) => { await window.__FL_TESTS.setSetting('cloudBackupToken', t); }, TOKEN);
    const items = [
      { id: 'rl_aaaa1111bbbb', do: 'expense', params: { amount: 45.1, category: 'Tolls' }, createdAt: 1 },
      { id: 'rl_cccc2222dddd', do: 'fuel', params: { gallons: 10, total: 40 }, createdAt: 2 },
    ];
    const seen = await stubRelay(p, items);
    await openLink(app, 'do=relay&id=rl_aaaa1111bbbb');
    eq((await modal(p)).title, 'Add Expense', 'the relayed expense opens');
    eq(await val(p, 'f_amt'), '45.1'); eq(await val(p, 'f_cat'), 'Tolls');
    ok(seen.deletes.includes('rl_aaaa1111bbbb'), 'the item is consumed');
    eq(await count(p, 'expenses'), 0, 'and still nothing is saved before Save');

    await p.evaluate(() => { document.getElementById('modalClose')?.click(); });
    await sleep(400);
    // The service worker hands a tapped notification's URL to an open window.
    await p.evaluate(() => navigator.serviceWorker.dispatchEvent(new MessageEvent('message',
      { data: { type: 'FL_OPEN_URL', url: location.origin + '/index.html#do=relay&id=rl_cccc2222dddd' } })));
    await sleep(800);
    eq((await modal(p)).title, 'Add Fuel', 'a notification tap opens the fuel item');
    ok(seen.deletes.includes('rl_cccc2222dddd'), 'and consumes it');

    await p.evaluate(() => navigator.serviceWorker.dispatchEvent(new MessageEvent('message',
      { data: { type: 'FL_OPEN_URL', url: 'https://evil.example/#do=expense&amount=9' } })));
    await sleep(500);
    ok(!/evil/.test(await p.evaluate(() => location.href)), 'a foreign URL in the message is ignored');

    await openLink(app, 'do=relay&id=rl_gone0000gone');
    ok(/already used or has expired/.test(await toastText(p)), 'a spent id is explained');
  } finally { await app.close(); }
});

test('[SDL-12] Today shows items waiting from Shortcuts; dismiss consumes one', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await p.evaluate(async (t) => { await window.__FL_TESTS.setSetting('cloudBackupToken', t); }, TOKEN);
    const items = [
      { id: 'rl_eeee3333ffff', do: 'intake', params: { text: 'load text' }, createdAt: 1 },
      { id: 'rl_gggg4444hhhh', do: 'expense', params: { amount: 20, category: 'Parking' }, createdAt: 2 },
    ];
    const seen = await stubRelay(p, items);
    await p.evaluate(() => { location.hash = '#home'; }); await sleep(600);
    await p.evaluate(() => window.__FL_TESTS.renderRelayInbox(true)); await sleep(400);
    const card = await p.evaluate(() => {
      const c = document.getElementById('homeRelayInbox');
      const rows = [...(c?.querySelectorAll('.relay-row') || [])];
      return { shown: !!c && c.style.display !== 'none' && c.getBoundingClientRect().height > 0,
        text: c?.innerText || '', visibleRows: rows.filter(r => r.getBoundingClientRect().height >= 44).length };
    });
    ok(card.shown, 'the From Shortcuts card is visible on Today');
    ok(/2 waiting/i.test(card.text) && /Parking/.test(card.text), `card lists the items, got ${card.text}`);
    eq(card.visibleRows, 2, 'each waiting item is a visible row with a road-sized target');
    await p.click('[data-relay-drop="rl_eeee3333ffff"]'); await sleep(500);
    ok(seen.deletes.includes('rl_eeee3333ffff'), 'dismiss consumes the item');
    ok(/1 waiting/i.test(await p.evaluate(() => document.getElementById('homeRelayInbox')?.innerText || '')), 'and the card updates');
  } finally { await app.close(); }
});

test('[SDL-13] Load Intake "Save as Trip" carries destination, miles and deadhead, and never invents an order number', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await p.evaluate(() => window.__FL_TESTS.openLoadIntake({ text: 'Columbus, OH to Atlanta, GA $1450 612 miles' }));
    await sleep(500);
    await p.evaluate(() => {
      const set = (id, v) => { const el = document.getElementById(id); el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); };
      set('liOrigin', 'Columbus, OH'); set('liDest', 'Atlanta, GA'); set('liMiles', '612'); set('liDead', '38');
      set('liRevenue', '1450'); set('liOrderNo', ''); set('liBroker', 'ACME');
    });
    await p.click('#liSaveTrip'); await sleep(700);
    eq((await modal(p)).title, 'Add Trip', 'the trip form opens directly');
    eq(await val(p, 'f_orderNo'), '', 'an unknown order number stays blank — no DRAFT-<timestamp>');
    eq(await val(p, 'f_dest'), 'Atlanta, GA', 'destination survives (it was dropped before)');
    eq(await val(p, 'f_loaded'), '612', 'loaded miles survive (they were dropped before)');
    eq(await val(p, 'f_empty'), '38', 'deadhead survives (it was dropped before)');
    eq(await val(p, 'f_origin'), 'Columbus, OH'); eq(await val(p, 'f_pay'), '1450'); eq(await val(p, 'f_customer'), 'ACME');
    ok(/From Load Intake/.test(await p.evaluate(() => document.getElementById('modalBody')?.innerText || '')), 'the form names its source');
  } finally { await app.close(); }
});

test('[SDL-14] Settings: the panel explains that it needs cloud backup, and offers nothing it cannot do', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await p.evaluate(() => { location.hash = '#insights'; }); await sleep(800);
    const s = await p.evaluate(() => ({
      card: !!document.getElementById('pushShortcutsCard'),
      hint: document.getElementById('pushShortcutsHint')?.textContent || '',
      on: document.getElementById('btnPushEnable')?.disabled, key: document.getElementById('btnShortcutKeyCreate')?.disabled,
    }));
    ok(s.card, 'Notifications & Shortcuts card exists');
    ok(/cloud backup/i.test(s.hint), `hint explains the requirement, got "${s.hint}"`);
    eq(s.on, true, 'Turn on is disabled without an account'); eq(s.key, true, 'Create Shortcut key is disabled without an account');
  } finally { await app.close(); }
});

test('[SDL-15] a Shortcut key is shown once and never stored on the device', async () => {
  const app = await boot();
  try {
    const p = app.page;
    const KEY = 'fls_' + '9'.repeat(48);
    await p.evaluate(async (t) => { await window.__FL_TESTS.setSetting('cloudBackupToken', t); }, TOKEN);
    let exists = false;
    await p.route(/\/shortcut-key$/, (route) => {
      const m = route.request().method();
      if (m === 'POST') { exists = true; return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ ok: true, key: KEY, createdAt: 'now' }) }); }
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, exists, createdAt: null }) });
    });
    await p.route(/\/push\/key$/, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"publicKey":"x"}' }));
    await p.evaluate(() => { location.hash = '#insights'; }); await sleep(900);
    eq(await p.evaluate(() => document.getElementById('shortcutKeyStatus')?.textContent), 'None');
    await p.click('#btnShortcutKeyCreate'); await sleep(600);
    eq((await modal(p)).title, 'Your Shortcut key', 'the key is shown');
    eq(await val(p, 'sckValue'), KEY, 'exactly the minted key');
    const stored = await p.evaluate(async () => JSON.stringify({
      ls: { ...localStorage }, ss: { ...sessionStorage }, settings: await window.__FL_TESTS.dumpStore('settings'),
    }));
    ok(!stored.includes(KEY), 'the Shortcut key must not be written to localStorage, sessionStorage or the settings store');
    await p.click('#sckDone'); await sleep(400);
    eq(await p.evaluate(() => document.getElementById('shortcutKeyStatus')?.textContent), 'Active');
  } finally { await app.close(); }
});

test('[SDL-16] Turn on subscribes through PushManager and registers the device; Turn off undoes both', async () => {
  const app = await boot();
  try {
    const p = app.page;
    // Headless Chromium has no push service to hand out a real subscription and
    // reports notification permission as denied, so both are stood in for here.
    // What is under test is the app's use of them: that the Turn on tap asks for
    // permission, which key it subscribes with, and what it sends to the Worker.
    await p.evaluate(() => {
      window.__perm = 'default';
      Object.defineProperty(Notification, 'permission', { configurable: true, get: () => window.__perm });
      Notification.requestPermission = async () => { window.__asked = true; window.__perm = 'granted'; return 'granted'; };
      window.__fakeSub = null;
      const make = (opts) => ({
        endpoint: 'https://web.push.apple.com/test-endpoint', options: opts,
        toJSON() { return { endpoint: this.endpoint, keys: { p256dh: 'BPUB', auth: 'AUTH' } }; },
        async unsubscribe() { window.__fakeSub = null; return true; },
      });
      PushManager.prototype.subscribe = async function (opts) { window.__subscribeKeyLen = opts.applicationServerKey.length; window.__fakeSub = make(opts); return window.__fakeSub; };
      PushManager.prototype.getSubscription = async function () { return window.__fakeSub; };
    });
    await p.evaluate(async (t) => { await window.__FL_TESTS.setSetting('cloudBackupToken', t); }, TOKEN);
    const VAPID = 'B' + 'A'.repeat(86); // 87 base64url chars → 65 bytes
    const sent = { subscribe: null, unsubscribe: null };
    await p.route(/\/push\/key$/, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, publicKey: VAPID }) }));
    await p.route(/\/push\/subscribe$/, (r) => {
      const body = JSON.parse(r.request().postData() || '{}');
      if (r.request().method() === 'POST') sent.subscribe = body; else sent.unsubscribe = body;
      return r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
    });
    await p.route(/\/shortcut-key$/, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true,"exists":false}' }));
    await p.evaluate(() => { location.hash = '#insights'; }); await sleep(900);
    eq(await p.evaluate(() => document.getElementById('pushStatusText')?.textContent), 'Off', 'status before turning on');
    await p.click('#btnPushEnable'); await sleep(900);
    eq(await p.evaluate(() => window.__asked), true, 'permission is requested from the Turn on tap');
    eq(await p.evaluate(() => window.__subscribeKeyLen), 65, 'subscribes with the 65-byte VAPID key from /push/key');
    ok(sent.subscribe && sent.subscribe.subscription.endpoint === 'https://web.push.apple.com/test-endpoint', 'registers the subscription with the Worker');
    eq(sent.subscribe.publicKey, VAPID, 'and records which key it used');
    eq(await p.evaluate(() => document.getElementById('pushStatusText')?.textContent), 'On');
    eq(await p.evaluate(() => localStorage.getItem('fl_push_vapid')), VAPID, 'device-local key record');
    await p.click('#btnPushDisable'); await sleep(900);
    eq(sent.unsubscribe && sent.unsubscribe.endpoint, 'https://web.push.apple.com/test-endpoint', 'Turn off removes the device from the Worker');
    eq(await p.evaluate(() => document.getElementById('pushStatusText')?.textContent), 'Off');
    eq(await p.evaluate(() => localStorage.getItem('fl_push_vapid')), null, 'and clears the local record');
  } finally { await app.close(); }
});

test('[SDL-17] open links route to the named screen while the app is running', async () => {
  const app = await boot();
  try {
    const p = app.page;
    await openLink(app, 'do=open&to=money');
    eq(await p.evaluate(() => location.hash), '#money');
    ok(await p.evaluate(() => document.getElementById('view-money')?.style.display !== 'none'), 'Money is visible');
    await openLink(app, 'do=open&to=nowhere');
    ok(/does not exist/i.test(await toastText(p)), 'an unknown screen is explained');
    for (const inherited of ['__proto__', 'constructor', 'toString']) {
      await openLink(app, 'do=open&to=' + inherited);
      ok(/does not exist/i.test(await toastText(p)), `an inherited property name (${inherited}) is not a screen`);
      ok(!/object/i.test(await p.evaluate(() => location.hash)), 'and never lands on a bogus route');
    }
  } finally { await app.close(); }
});

test('[SDL-18] boot never asks for notification permission; only the Turn on tap does', async () => {
  // docs/WEB_PUSH_CONTRACT.md: permission is requested ONLY from the Turn on
  // tap. v24.0.34 shipped that for push, while a legacy boot task still called
  // Notification.requestPermission() ~2 s after start for any driver with a
  // trip. Seed the precondition that path needed (a saved trip, permission still
  // "default"), reboot, and let the deferred boot tasks run in full.
  const app = await boot();
  try {
    const p = app.page;
    await p.evaluate(async () => {
      const t = window.__FL_TESTS.sanitizeTrip({ orderNo: 'SDL18', pay: 500, loadedMiles: 400, emptyMiles: 20, pickupDate: '2026-09-20', deliveryDate: '2026-09-21', origin: 'Columbus, OH', destination: 'Atlanta, GA' });
      await window.__FL_TESTS.upsertTrip(t);
    });
    ok(await count(p, 'trips') >= 1, 'precondition: a saved trip exists');
    await p.addInitScript(() => {
      window.__permAsks = 0;
      try {
        Object.defineProperty(Notification, 'permission', { configurable: true, get: () => 'default' });
        Notification.requestPermission = () => { window.__permAsks++; return Promise.resolve('default'); };
      } catch (_) {}
    });
    await p.reload({ waitUntil: 'load' });
    await waitForAppReady(p);
    await sleep(3500); // the deferred boot block runs at +2000 ms
    eq(await p.evaluate(() => window.__permAsks), 0, 'no permission prompt without a user gesture');
  } finally { await app.close(); }

  // The only call site left is the Turn on handler.
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../app.js', import.meta.url), 'utf8');
  const sites = src.split('\n').filter(l => /requestPermission\s*\(/.test(l) && !/^\s*(\/\/|\*|\/\*)/.test(l));
  eq(sites.length, 1, `exactly one requestPermission call site, got ${sites.length}`);
});

export async function runSpec() {
  return await run();
}
