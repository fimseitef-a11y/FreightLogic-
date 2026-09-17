// v24.0.8 — the five-surface driver shell, driven as a driver drives it.
//
// PR #168 landed Today / Loads / Evaluate / Trips / Money and the full suite was
// green, because NOTHING in the suite touched the shell. The Loads tab — the
// central new surface of that pass — was dead on arrival:
//
//   * `modern-shell.js` created `#view-loads` itself, at import time. `app.js`
//     builds its `views` map at PARSE time from markup that already exists, so
//     the canonical router had no `loads` entry. `navigate()` resolves an
//     unknown hash to `home`, so tapping Loads showed the Today screen while the
//     Loads tab highlighted itself. `#view-loads` stayed `display:none` forever.
//   * The Smart Load Inbox (F23) had been RELOCATED out of Evaluate into that
//     surface, so the feature became unreachable from anywhere in the app.
//   * `renderLoads()` called `window.renderLoadInbox` / `window.renderOmega` and
//     the More button called `window.navigate`. `app.js` is one IIFE — none of
//     those are globals, so every one of those paths was permanently dead, and
//     silently so: no throw, no console error.
//
// Every assertion here reads COMPUTED VISIBILITY and rendered content rather
// than the hash or the highlighted tab, because the hash and the highlight were
// both correct while the surface was dead. That is precisely how this shipped.
import { launchBlank, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/modern-shell-routing.spec.mjs');

/**
 * Boots the real app with the F26 wizard already suppressed IN THE DATABASE, so
 * no full-screen modal can intercept a tab tap mid-test.
 */
async function bootShell() {
  const app = await launchBlank();
  await app.page.evaluate(async () => {
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings', { keyPath: 'key' });
      };
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('settings', 'readwrite');
        txn.objectStore('settings').put({ key: 'f26SetupComplete', value: true });
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
  });
  await app.bootApp();
  // sw-bridge.js reaches modern-shell.js by dynamic import, so the tab bar is
  // built one microtask-turn after load rather than synchronously with app.js.
  await app.page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout: 10000 });
  await app.page.waitForTimeout(400);
  return app;
}

/** What is actually on screen — not what the hash or the tab bar claims. */
async function surface(page) {
  return await page.evaluate(() => {
    const visible = [];
    document.querySelectorAll('main.app > section.view').forEach((v) => {
      if (getComputedStyle(v).display !== 'none') visible.push(v.id);
    });
    return {
      hash: location.hash,
      visible,
      activeTabs: [...document.querySelectorAll('.bottom .nav a.active')].map((a) => a.dataset.modernRoute),
    };
  });
}

async function tapTab(page, modernRoute) {
  await page.click(`.bottom .nav a[data-modern-route="${modernRoute}"]`);
  await page.waitForTimeout(500);
}

test('[MS-01] the tab bar is the five driver surfaces, in order', async () => {
  const app = await bootShell();
  try {
    const tabs = await app.page.$$eval('.bottom .nav a', (els) => els.map((e) => ({
      label: e.querySelector('.nl').textContent.trim(),
      route: e.dataset.modernRoute,
      nav: e.dataset.nav,
      href: e.getAttribute('href'),
    })));
    eq(tabs.map((t) => t.label).join('/'), 'Today/Loads/Evaluate/Trips/Money',
      'primary navigation must be Today / Loads / Evaluate / Trips / Money in that order');
    // data-nav carries the CANONICAL route name so app.js setActiveNav() drives
    // the highlight. Before 24.0.8 the centre tab declared data-nav="evaluate",
    // a label the router never produces.
    eq(tabs.map((t) => t.nav).join(','), 'home,loads,omega,trips,money',
      'each tab must declare the canonical route name in data-nav');
    eq(tabs.map((t) => t.href).join(','), '#home,#loads,#omega,#trips,#money',
      'each tab must link to its canonical hash');
  } finally { await app.close(); }
});

test('[MS-02] tapping Loads shows the Loads surface, not the Today screen', async () => {
  const app = await bootShell();
  try {
    await tapTab(app.page, 'loads');
    const s = await surface(app.page);
    eq(s.hash, '#loads', 'the Loads tab must route to #loads');
    eq(s.visible.join(','), 'view-loads',
      'THE DEFECT: #view-loads must be the visible section. Before 24.0.8 `views` had no ' +
      '`loads` entry, navigate() fell through to home, and the driver saw view-home here ' +
      'with the Loads tab highlighted — the hash and the highlight were both already right.');
    eq(s.activeTabs.join(','), 'loads', 'the Loads tab must be the highlighted tab');
  } finally { await app.close(); }
});

test('[MS-03] the Smart Load Inbox is reachable and renders on the Loads surface', async () => {
  const app = await bootShell();
  try {
    // Reachable from nowhere else: the inbox mount point moved out of Evaluate
    // in PR #168, so if Loads cannot display it, F23 is gone from the product.
    await tapTab(app.page, 'loads');
    const inbox = await app.page.evaluate(() => {
      const card = document.getElementById('loadInboxCard');
      if (!card) return null;
      const view = card.closest('section.view');
      return {
        inView: view ? view.id : null,
        cardVisible: getComputedStyle(card).display !== 'none' && card.offsetParent !== null,
        hasTextarea: !!card.querySelector('#f23Textarea'),
        hasScoreBtn: !!card.querySelector('#f23ScoreBtn'),
      };
    });
    ok(inbox, '#loadInboxCard must exist');
    eq(inbox.inView, 'view-loads', 'the inbox must be mounted inside the Loads surface');
    ok(inbox.cardVisible, 'the inbox card must actually be on screen when Loads is open');
    ok(inbox.hasTextarea, 'renderLoadInbox() must have run — the paste textarea must be present');
    ok(inbox.hasScoreBtn, 'the Score This Load action must be present');
  } finally { await app.close(); }
});

test('[MS-04] the Loads intake button opens the canonical Load Intake, not a second one', async () => {
  const app = await bootShell();
  try {
    await tapTab(app.page, 'loads');
    await app.page.click('#btnLoadsIntake');
    await app.page.waitForTimeout(700);
    const modal = await app.page.evaluate(() => {
      const m = document.getElementById('modal');
      return {
        open: !!m && m.classList.contains('open'),
        title: document.getElementById('modalTitle')?.textContent?.trim() || null,
      };
    });
    ok(modal.open, 'the Loads intake button must open the modal');
    eq(modal.title, 'Load Intake',
      'it must open F27 openLoadIntake() — the canonical intake — not a parallel surface');
  } finally { await app.close(); }
});

test('[MS-05] every primary tab displays its own surface and nothing else', async () => {
  const app = await bootShell();
  try {
    const expected = [
      ['home', '#home', 'view-home'],
      ['loads', '#loads', 'view-loads'],
      ['evaluate', '#omega', 'view-omega'],
      ['trips', '#trips', 'view-trips'],
      ['money', '#money', 'view-money'],
    ];
    for (const [route, hash, viewId] of expected) {
      await tapTab(app.page, route);
      const s = await surface(app.page);
      eq(s.hash, hash, `${route} must route to ${hash}`);
      eq(s.visible.join(','), viewId,
        `${route} must display exactly ${viewId}; got ${JSON.stringify(s.visible)}`);
      eq(s.activeTabs.join(','), route, `${route} must be the highlighted tab`);
    }
  } finally { await app.close(); }
});

test('[MS-06] Loads survives a reload and a cold direct deep link', async () => {
  const app = await bootShell();
  try {
    // A cold load straight to #loads is the harder case: app.js routes once at
    // boot, before sw-bridge.js has even imported the adapter.
    await app.page.goto(`${app.baseUrl}/index.html#loads`, { waitUntil: 'load' });
    await app.page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout: 10000 });
    await app.page.waitForTimeout(700);
    const s = await surface(app.page);
    eq(s.hash, '#loads', 'the deep link must stay on #loads');
    eq(s.visible.join(','), 'view-loads', 'a cold #loads deep link must display the Loads surface');
    ok(await app.page.evaluate(() => !!document.querySelector('#loadInboxCard #f23Textarea')),
      'the inbox must render on a cold deep link too');
  } finally { await app.close(); }
});

test('[MS-07] driver-facing aliases normalize to canonical routes', async () => {
  const app = await bootShell();
  try {
    for (const [alias, hash, viewId] of [['today', '#home', 'view-home'], ['evaluate', '#omega', 'view-omega']]) {
      await app.page.evaluate((a) => { location.hash = a; }, alias);
      await app.page.waitForTimeout(600);
      const s = await surface(app.page);
      eq(s.hash, hash, `#${alias} must normalize to ${hash} rather than fall through to home`);
      eq(s.visible.join(','), viewId, `#${alias} must display ${viewId}`);
    }
  } finally { await app.close(); }
});

test('[MS-08] secondary tools stay reachable through More', async () => {
  const app = await bootShell();
  try {
    // More left the tab bar in PR #168. Everything behind it — Intel, Settings,
    // Diagnostics, import/export — is reachable only through this one control.
    ok(await app.page.$('#modernMoreBtn'), 'the More entry must exist in the header');
    await app.page.click('#modernMoreBtn');
    await app.page.waitForTimeout(700);
    const s = await surface(app.page);
    eq(s.visible.join(','), 'view-more', 'the More entry must display the More surface');
    const tiles = await app.page.$$eval('#moreMenu .menu-tile', (els) => els.length);
    ok(tiles > 0, 'the More surface must render its tiles');
  } finally { await app.close(); }
});

test('[MS-12] no canonical route is orphaned by the tab bar that replaced the old one', async () => {
  const app = await bootShell();
  try {
    // PR #168 replaced a Home/Trips/Omega/Intel/More bar with the five driver
    // surfaces. `index.html`'s nav anchor was the ONLY link to `#intel` anywhere
    // in the app, so the whole Market Intel surface — route, renderer and all
    // five of its tabs intact — became reachable only by typing the hash.
    //
    // Assert reachability structurally: every route app.js can render must be
    // reachable from the tab bar or from a More tile, with no exceptions list.
    const routes = await app.page.evaluate(() => {
      // `views` is private to app.js's IIFE, so read the routes off the DOM the
      // same way a driver's browser resolves them: every #view-* section present.
      return [...document.querySelectorAll('main.app > section.view')]
        .map((v) => v.id.replace(/^view-/, ''));
    });
    ok(routes.includes('intel'), 'the intel surface must still exist');

    const tabHrefs = await app.page.$$eval('.bottom .nav a', (els) => els.map((e) => e.getAttribute('href')));
    await app.page.click('#modernMoreBtn');
    await app.page.waitForTimeout(700);
    // Open the collapsed Advanced group so its tiles are in the DOM too.
    await app.page.evaluate(() => {
      document.querySelectorAll('#moreMenu .menu-grid').forEach((g) => { g.style.display = ''; });
    });
    const tileTitles = await app.page.$$eval('#moreMenu .menu-tile .tt', (els) => els.map((e) => e.textContent.trim()));
    ok(tileTitles.includes('Market Intel'),
      `More must expose a Market Intel entry; found ${JSON.stringify(tileTitles)}`);

    // `more` is reached by the header control, not by a hash link; everything
    // else must be reachable by a tab or a tile.
    const reachable = new Set(tabHrefs.map((h) => h.replace(/^#/, '')).concat(['more']));
    const tileRoutes = await app.page.evaluate(() => {
      // MORE_TILES is private too; assert via the rendered tiles' click targets
      // by matching on title, which is what a driver actually reads.
      const map = { 'Money / AR': 'money', 'Expenses': 'expenses', 'Fuel Log': 'fuel',
        'Settings': 'insights', 'Tax & Reports': 'insights', 'Market Intel': 'intel' };
      return [...document.querySelectorAll('#moreMenu .menu-tile .tt')]
        .map((e) => map[e.textContent.trim()]).filter(Boolean);
    });
    tileRoutes.forEach((r) => reachable.add(r));

    const orphans = routes.filter((r) => !reachable.has(r));
    eq(orphans.join(','), '',
      `every route must be reachable from the tab bar or More; orphaned: ${JSON.stringify(orphans)}. ` +
      'A route whose only link was the replaced nav anchor is invisible to the driver even ' +
      'though its renderer still works.');
  } finally { await app.close(); }
});

test('[MS-09] the unpaid-trips badge app.js writes to survives the tab-bar rebuild', async () => {
  const app = await bootShell();
  try {
    // The adapter replaces the whole <nav>. #navUnpaidBadge is app.js's node,
    // looked up by id from refreshUnpaidBadge(); a rebuild that minted a fresh
    // copy would discard a count already rendered.
    const badge = await app.page.evaluate(() => {
      const el = document.getElementById('navUnpaidBadge');
      if (!el) return null;
      const tab = el.closest('a');
      return { inTab: tab ? tab.dataset.modernRoute : null, count: document.querySelectorAll('#navUnpaidBadge').length };
    });
    ok(badge, '#navUnpaidBadge must still exist after the tab bar is rebuilt');
    eq(badge.count, 1, 'exactly one #navUnpaidBadge — a duplicate id means app.js writes to the wrong node');
    eq(badge.inTab, 'trips', 'the badge must live on the Trips tab');
  } finally { await app.close(); }
});

test('[MS-10] booting the app raises no uncaught error', async () => {
  // voice-load.js threw a TypeError on EVERY fresh session before 24.0.8:
  // sessionStorage.getItem() returns null for an unwritten key, JSON.parse(null)
  // is valid JSON yielding null (it does not throw), so safeJSONParse's catch
  // never ran, getDraftStore() returned null, and loadLatestDraft() died on
  // `store.length`. That aborted init() before its first renderReview() and
  // before the no-speech-recognition fallback was applied.
  const app = await launchBlank();
  const errors = [];
  app.page.on('pageerror', (e) => errors.push(e.message));
  try {
    await app.bootApp();
    await app.page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout: 10000 });
    await app.page.waitForTimeout(1200);
    eq(errors.length, 0, `boot must raise no uncaught error; got ${JSON.stringify(errors)}`);
  } finally { await app.close(); }
});

test('[MS-11] the removed Voice Load module leaves no runtime trace (Issue #230)', async () => {
  // This assertion used to prove voice-load.js's safeJSONParse hydrated a fresh
  // session instead of throwing (the v24.0.8 repair: sessionStorage.getItem()
  // returns null for an unwritten key, JSON.parse(null) is valid JSON yielding
  // null, so the catch never ran and every array consumer got null). Voice Load
  // was removed completely by operator decision, so the module it guarded is
  // gone and the guard is retargeted rather than deleted: what matters now is
  // that the removal is CLEAN at runtime, which is the half a static file check
  // cannot see. MS-10 above still fails if the removal broke boot.
  const app = await launchBlank();
  const failed = [];
  app.page.on('requestfailed', (r) => failed.push(r.url()));
  app.page.on('response', (r) => { if (r.status() === 404) failed.push(`404 ${r.url()}`); });
  try {
    await app.bootApp();
    await app.page.waitForFunction(() => !!window.FreightLogicModernShell, null, { timeout: 10000 });
    await app.page.waitForTimeout(800);

    const state = await app.page.evaluate(() => ({
      globalGone: typeof window.FreightLogicVoiceLoad === 'undefined',
      btnGone: !document.getElementById('mwVoiceBtn'),
      statusGone: !document.getElementById('mwVoiceStatus'),
      scriptGone: ![...document.scripts].some((s) => (s.src || '').includes('voice-load')),
      // The surviving intake path must still be mounted.
      revenueField: !!document.getElementById('mwRevenue'),
      intakeButton: !!document.getElementById('btnLoadIntake'),
    }));

    eq(state.globalGone, true, 'no Voice Load global may remain on window');
    eq(state.btnGone, true, 'the evaluator microphone control must not be in the live DOM');
    eq(state.statusGone, true, 'the voice status region must not be in the live DOM');
    eq(state.scriptGone, true, 'no script element may still point at voice-load.js');
    eq(state.revenueField, true, 'the evaluator fields the surviving intake path binds to must be present');
    eq(state.intakeButton, true, 'paste/type Load Intake must still be reachable');

    const voiceFailures = failed.filter((u) => u.includes('voice-load'));
    eq(voiceFailures.length, 0,
      `the removal must not leave a request for the deleted module; got ${JSON.stringify(voiceFailures)}`);
  } finally { await app.close(); }
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
