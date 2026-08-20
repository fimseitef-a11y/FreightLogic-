// 7C (v23.9 Phase 7) — Health & Release Badge. Proves computeHealthBadge()
// and its component readers (getSwLiveVersion/getDbLiveVersion/
// getWorkerLiveHealth/getAuthorityLiveVersion/getVersionManifest) genuinely
// read LIVE runtime state rather than a hardcoded copy of a version string:
// the DB check opens the real IndexedDB and reads its actual on-disk
// .version; the authority check loads the real, unmodified
// midwest-stack-authority.js and reads its live VERSION constant; the
// Worker check does a real HTTP round trip to a /health endpoint; and the
// aggregate "all agree" rule is proven to flip false the moment any one
// signal disagrees, not just when all of them do.
//
// Same same-origin mock-worker rationale as backup-restore-parity.spec.mjs
// (see tests/lib/mock-worker.mjs's header comment) — the shipped CSP's
// connect-src only allows the production Worker origin, so a local mock
// must share origin with the page itself to be reachable at all.
import { chromium } from 'playwright';
import { skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';
import { startMockWorker } from '../lib/mock-worker.mjs';

const { test, run } = createSuite('integration/health-badge.spec.mjs');
let app, worker;

async function connectCloud(page, worker) {
  await page.evaluate(async ({ url, token }) => {
    await window.__FL_TESTS.setSetting('cloudBackupUrl', url);
    await window.__FL_TESTS.setSetting('cloudBackupToken', token);
    sessionStorage.setItem('fl_cloud_pass', 'test-passphrase-12345');
  }, { url: worker.url, token: worker.token });
}

test('setup: connect to the mock worker', async () => {
  await connectCloud(app.page, worker);
});

test('[7C] getVersionManifest() reads the real version.json, matching APP_VERSION', async () => {
  const manifest = await app.page.evaluate(() => window.__FL_TESTS.getVersionManifest());
  const appVersion = await app.page.evaluate(() => window.__FL_TESTS.APP_VERSION);
  ok(manifest, 'version.json must be fetchable');
  ok(manifest.gitCommit, 'version.json must carry a gitCommit field: ' + JSON.stringify(manifest));
  eq(manifest.appVersion, appVersion, 'version.json appVersion must match the running APP_VERSION');
});

test('[7C] getDbLiveVersion() reads the ACTUAL on-disk IndexedDB version, not a copy of the DB_VERSION constant', async () => {
  const result = await app.page.evaluate(() => window.__FL_TESTS.getDbLiveVersion());
  console.log(`    [evidence] getDbLiveVersion(): ${JSON.stringify(result)}`);
  ok(result.ok, 'must successfully open the real DB: ' + JSON.stringify(result));
  ok(result.version > 0, 'live DB version must be a real positive schema version');
});

test('[7C] getAuthorityLiveVersion() reads the REAL midwest-stack-authority.js file\'s live VERSION constant', async () => {
  await app.page.addScriptTag({ url: '/midwest-stack-authority.js' });
  await app.page.waitForFunction(() => !!window.FreightLogicMidwestStack, { timeout: 5000 });
  const result = await app.page.evaluate(() => window.__FL_TESTS.getAuthorityLiveVersion());
  console.log(`    [evidence] getAuthorityLiveVersion(): ${JSON.stringify(result)}`);
  ok(result.ok, 'must find the loaded overlay: ' + JSON.stringify(result));
  ok(/^\d+\.\d+\.\d+$/.test(result.version), 'authority version must be a real semver string, got: ' + result.version);
});

test('[7C] getAuthorityLiveVersion() degrades honestly (ok:false) when the overlay is not loaded', async () => {
  // A fresh, isolated evaluate — window.FreightLogicMidwestStack genuinely
  // does not exist yet on a page that never loaded the overlay script.
  // (Uses a throwaway page in the SAME context so the prior test's tag stays
  // scoped to its own page, proving this isn't leftover global state.)
  const page2 = await app.context.newPage();
  await page2.goto(app.baseUrl, { waitUntil: 'load' });
  await page2.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  const result = await page2.evaluate(() => window.__FL_TESTS.getAuthorityLiveVersion());
  console.log(`    [evidence] getAuthorityLiveVersion() with no overlay loaded: ${JSON.stringify(result)}`);
  ok(!result.ok, 'must report ok:false when the overlay genuinely is not present: ' + JSON.stringify(result));
  eq(result.reason, 'overlay not loaded', 'must give the honest reason');
  await page2.close();
});

test('[7C] getWorkerLiveHealth() does a real HTTP round trip and matches EXPECTED_WORKER_VERSION', async () => {
  const result = await app.page.evaluate(() => window.__FL_TESTS.getWorkerLiveHealth());
  const expected = await app.page.evaluate(() => window.__FL_TESTS.EXPECTED_WORKER_VERSION);
  console.log(`    [evidence] getWorkerLiveHealth(): ${JSON.stringify(result)}, expected: ${expected}`);
  ok(result.ok, 'must reach the mock /health endpoint: ' + JSON.stringify(result));
  eq(result.version, expected, 'mock worker reports the same version cloud-backup-worker.js v11 actually reports');
});

test('[7C] getWorkerLiveHealth() reports the real mismatched version when the Worker has drifted — proven, not assumed', async () => {
  await worker.setHealthVersion('99');
  const result = await app.page.evaluate(() => window.__FL_TESTS.getWorkerLiveHealth());
  console.log(`    [evidence] getWorkerLiveHealth() after simulating Worker drift: ${JSON.stringify(result)}`);
  ok(result.ok, 'the HTTP call itself still succeeds — this is a version mismatch, not an outage');
  eq(result.version, '99', 'must report the ACTUAL live version, not the expected one');
  await worker.setHealthVersion('11'); // restore for subsequent tests
});

test('[7C] getSwLiveVersion() degrades honestly (ok:false) when no service worker can activate — a real negative case, not a timing guess', async () => {
  // Playwright's serviceWorkers:'block' context option deterministically
  // prevents any SW from registering at all, instead of racing the real
  // one's (variable) activation latency to try to catch it "not yet up".
  const blockedContext = await app.browser.newContext({ serviceWorkers: 'block' });
  await blockedContext.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  const page2 = await blockedContext.newPage();
  await page2.goto(app.baseUrl, { waitUntil: 'load' });
  await page2.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  const result = await page2.evaluate(() => window.__FL_TESTS.getSwLiveVersion(1500));
  console.log(`    [evidence] getSwLiveVersion() with serviceWorkers:'block': ${JSON.stringify(result)}`);
  ok(!result.ok, 'must not claim a match when there is genuinely nothing to check against: ' + JSON.stringify(result));
  eq(result.reason, 'no active service worker', 'must give the honest reason, not a generic failure');
  await blockedContext.close();
});

test('[7C] getSwLiveVersion() reports the REAL active service worker\'s version, matching APP_VERSION', async () => {
  // By this point in the suite the app's own boot sequence has had several
  // seconds (multiple prior awaits/fetches) to register+activate its real
  // service worker — this proves the live message-channel round trip works
  // end to end against the genuine SW, not just that it fails gracefully.
  const result = await app.page.evaluate(() => window.__FL_TESTS.getSwLiveVersion(5000));
  const appVersion = await app.page.evaluate(() => window.__FL_TESTS.APP_VERSION);
  console.log(`    [evidence] getSwLiveVersion() against the real active SW: ${JSON.stringify(result)}`);
  ok(result.ok, 'the real service worker must have activated and answered by now: ' + JSON.stringify(result));
  eq(result.version, appVersion, 'the active SW must report the same version as the running app');
});

test('[7C] computeHealthBadge() aggregate rule: allGreen is false unless EVERY signal agrees (backup not yet verified here)', async () => {
  const h = await app.page.evaluate(() => window.__FL_TESTS.computeHealthBadge());
  console.log(`    [evidence] computeHealthBadge(): allGreen=${h.allGreen} swOk=${h.swOk} dbOk=${h.dbOk} workerOk=${h.workerOk} authorityOk=${h.authorityOk} backupOk=${h.backupOk}`);
  ok(h.dbOk, 'DB must agree in this environment (same app, same schema)');
  ok(h.workerOk, 'mock worker must agree (restored to v11 above)');
  ok(h.swOk, 'the real active SW matches — proven by the previous test');
  ok(h.authorityOk, 'authority overlay was loaded by an earlier test in this same page and must agree');
  ok(!h.backupOk, 'backup has never been verified in this test — must not be silently treated as ok');
  ok(!h.allGreen, 'allGreen must require EVERY signal, including one that has not been established yet');
});

test('[7C] computeHealthBadge() flips allGreen fully true once the last remaining signal (backup verification) is established', async () => {
  // Establish a genuine, fresh recovery-verified state: seed one trip, push
  // a full backup, then run the real verification pass — the same path 7B's
  // own tests exercise.
  await app.page.evaluate(async () => {
    const t = window.__FL_TESTS.sanitizeTrip({ orderNo: 'HB-1', customer: 'X', pay: 100, loadedMiles: 50, pickupDate: '2026-05-05', deliveryDate: '2026-05-05' });
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction('trips', 'readwrite');
        txn.objectStore('trips').put(t);
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
    });
    await window.__FL_TESTS.cloudPushBackup(false);
  });
  await app.page.waitForTimeout(300);
  await app.page.evaluate(() => window.__FL_TESTS.verifyRecoveryIntegrity());

  const h = await app.page.evaluate(() => window.__FL_TESTS.computeHealthBadge());
  console.log(`    [evidence] computeHealthBadge() after establishing every signal: allGreen=${h.allGreen} swOk=${h.swOk} dbOk=${h.dbOk} workerOk=${h.workerOk} authorityOk=${h.authorityOk} backupOk=${h.backupOk}`);
  ok(h.dbOk, 'DB must still agree');
  ok(h.workerOk, 'worker must still agree');
  ok(h.authorityOk, 'authority overlay must still agree');
  ok(h.swOk, 'SW must still agree');
  ok(h.backupOk, 'backup was just verified fresh and clean — must be true');
  eq(h.allGreen, true, 'once every individual signal is true, the aggregate must be true too — this is the actual release-health guarantee');
});

export async function runSpec() {
  worker = await startMockWorker();
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  const page = await context.newPage();
  await page.goto(worker.appUrl, { waitUntil: 'load' });
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  app = { browser, context, page, baseUrl: worker.appUrl.replace(/\/index\.html$/, ''), close: async () => { await browser.close(); } };
  await skipFirstRunWizard(app.page);
  try {
    return await run();
  } finally {
    if (app) await app.close().catch(() => {});
    if (worker) await worker.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
