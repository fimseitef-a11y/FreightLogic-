// X-01 + X-07 (v23.9 Phase 4) — E2E: full backup -> 3 delta syncs -> wipe
// local -> restore -> assert parity of every contracted store
// (docs/BACKUP_CONTRACT.md). Drives the REAL app.js client code
// (cloudPushBackup/cloudPullBackup/mergeRestoreData, real cloudEncrypt/
// cloudDecrypt via the browser's crypto.subtle, real IndexedDB) against a
// local mock of the Worker's KV-backed endpoints — see
// tests/lib/mock-worker.mjs for why a mock stands in for the (unreachable
// from this environment) live Cloudflare Worker.
import { chromium } from 'playwright';
import { skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';
import { startMockWorker } from '../lib/mock-worker.mjs';

const { test, run } = createSuite('integration/backup-restore-parity.spec.mjs');
let app, worker;

async function connectCloud(page, worker) {
  await page.evaluate(async ({ url, token }) => {
    await window.__FL_TESTS.setSetting('cloudBackupUrl', url);
    await window.__FL_TESTS.setSetting('cloudBackupToken', token);
    sessionStorage.setItem('fl_cloud_pass', 'test-passphrase-12345');
  }, { url: worker.url, token: worker.token });
}

async function dumpAllStores(page) {
  return page.evaluate(async () => {
    const names = ['trips', 'expenses', 'fuel', 'settings', 'receipts', 'gpsLogs'];
    const out = {};
    for (const name of names) {
      out[name] = await new Promise((resolve, reject) => {
        const req = indexedDB.open('FreightLogic_v18');
        req.onsuccess = () => {
          const db = req.result;
          const txn = db.transaction(name, 'readonly');
          const getAll = txn.objectStore(name).getAll();
          getAll.onsuccess = () => { db.close(); resolve(getAll.result); };
          getAll.onerror = () => reject(getAll.error);
        };
        req.onerror = () => reject(req.error);
      });
    }
    return out;
  });
}

async function wipeAllStores(page) {
  await page.evaluate(async () => {
    const names = ['trips', 'expenses', 'fuel', 'settings', 'receipts', 'gpsLogs', 'auditLog', 'laneHistory', 'weeklyReports', 'reloadOutcomes', 'bidHistory', 'documents'];
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction(names, 'readwrite');
        for (const n of names) txn.objectStore(n).clear();
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
  });
}

async function seedRecord(page, storeName, record) {
  await page.evaluate(async ({ storeName, record }) => {
    await new Promise((resolve, reject) => {
      const req = indexedDB.open('FreightLogic_v18');
      req.onsuccess = () => {
        const db = req.result;
        const txn = db.transaction(storeName, 'readwrite');
        txn.objectStore(storeName).put(record);
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => reject(txn.error);
      };
      req.onerror = () => reject(req.error);
    });
  }, { storeName, record });
}

test('setup: connect to the mock worker', async () => {
  await connectCloud(app.page, worker);
});

test('[X-01/X-07] full backup, then 3 delta syncs, each adding a new record', async () => {
  // Base full backup: one trip, one setting, one receipts entry, one gpsLog.
  const baseTrip = await app.page.evaluate(() =>
    window.__FL_TESTS.sanitizeTrip({ orderNo: 'BASE-1', customer: 'Base Broker', pay: 1000, loadedMiles: 300, pickupDate: '2026-05-01', deliveryDate: '2026-05-01' }));
  await seedRecord(app.page, 'trips', baseTrip);
  await app.page.evaluate(async () => { await window.__FL_TESTS.setSetting('weeklyGoal', 4000); });
  await seedRecord(app.page, 'gpsLogs', { tripTrackingId: 'trk-base', lat: 41.8, lng: -87.6, accuracy: 10, speed: 0, timestamp: Date.now() - 100000 });
  await seedRecord(app.page, 'receipts', { tripOrderNo: 'BASE-1', files: [{ id: 'f1', name: 'base-receipt.jpg', type: 'image/jpeg', size: 1000, added: Date.now(), thumbDataUrl: '', cached: false, status: 'imported' }] });

  await app.page.evaluate(async () => { await window.__FL_TESTS.cloudPushBackup(false); });
  await app.page.waitForTimeout(300);

  // Three delta syncs, each adding one more trip (small enough to stay under
  // the 50-changed-record delta threshold — cloudPushBackup.js:isDelta).
  for (const orderNo of ['DELTA-1', 'DELTA-2', 'DELTA-3']) {
    const t = await app.page.evaluate((orderNo) =>
      window.__FL_TESTS.sanitizeTrip({ orderNo, customer: 'Delta Broker', pay: 500, loadedMiles: 150, pickupDate: '2026-05-02', deliveryDate: '2026-05-02' }), orderNo);
    await seedRecord(app.page, 'trips', t);
    await app.page.evaluate(async () => { await window.__FL_TESTS.cloudPushBackup(false); });
    await app.page.waitForTimeout(300);
  }

  // Sanity: the pre-wipe local state has all 4 trips.
  const preWipe = await dumpAllStores(app.page);
  eq(preWipe.trips.length, 4, 'sanity: 1 base + 3 delta trips exist locally before wipe');
});

test('[X-01/X-07] wipe local data, restore, and assert parity of every contracted store', async () => {
  const preWipe = await dumpAllStores(app.page);

  await wipeAllStores(app.page);
  await app.page.reload({ waitUntil: 'load' });
  await app.page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  await skipFirstRunWizard(app.page);

  const postWipe = await dumpAllStores(app.page);
  eq(postWipe.trips.length, 0, 'sanity: wipe actually cleared trips');
  // Boot re-seeds a few of its own defaults (uiMode, localUserId, ...) on a
  // fresh empty DB — that's expected, not a leftover. The load-bearing fact
  // is that the cloud CONNECTION specifically was wiped, same as a genuine
  // device loss (the token/passphrase are not recoverable from local state).
  ok(!postWipe.settings.some(s => s.key === 'cloudBackupToken'), 'sanity: wipe actually cleared the cloud backup token');

  // Reconnect — a real device-loss recovery re-enters the token/passphrase,
  // it doesn't recover them from local storage (which is exactly what was wiped).
  await connectCloud(app.page, worker);

  let dialogSeen = false;
  app.page.once('dialog', async (dialog) => { dialogSeen = true; await dialog.accept(); });

  await app.page.evaluate(async () => { await window.__FL_TESTS.cloudPullBackup(); });
  await app.page.waitForTimeout(500);
  ok(dialogSeen, 'cloudPullBackup() must prompt for confirmation before restoring');

  const restored = await dumpAllStores(app.page);

  eq(restored.trips.length, 4, `all 4 trips (1 base + 3 delta) must be restored — got ${restored.trips.length}: ${JSON.stringify(restored.trips.map(t=>t.orderNo))}`);
  const orderNos = restored.trips.map(t => t.orderNo).sort();
  eq(JSON.stringify(orderNos), JSON.stringify(['BASE-1', 'DELTA-1', 'DELTA-2', 'DELTA-3']), 'exact set of trips must match what was pushed across the base + 3 deltas');

  // X-07: settings, receipts, gpsLogs must now also be restorable (previously
  // silently dropped by mergeRestoreData).
  const weeklyGoalSetting = restored.settings.find(s => s.key === 'weeklyGoal');
  ok(weeklyGoalSetting && weeklyGoalSetting.value === 4000, 'X-07: settings must be restored — weeklyGoal missing or wrong: ' + JSON.stringify(weeklyGoalSetting));

  const receipt = restored.receipts.find(r => r.tripOrderNo === 'BASE-1');
  ok(receipt && receipt.files.some(f => f.id === 'f1'), 'X-07: receipts must be restored — BASE-1 receipt missing: ' + JSON.stringify(receipt));

  ok(restored.gpsLogs.some(g => g.tripTrackingId === 'trk-base'), 'X-07: gpsLogs must be restored — trk-base entry missing: ' + JSON.stringify(restored.gpsLogs));

  console.log(`    [evidence] restored trips: ${JSON.stringify(orderNos)}`);
  console.log(`    [evidence] restored settings count: ${restored.settings.length}, receipts: ${restored.receipts.length}, gpsLogs: ${restored.gpsLogs.length}`);
});

test('[X-01] a confirmed delta gap (pruned deltas) surfaces a visible partial-restore warning, never a silent success', async () => {
  // Force the mock worker to simulate every delta but the newest having
  // expired/been evicted (totalCreated > retainedCount on the next fetch).
  await worker.forceGap();
  app.page.once('dialog', async (dialog) => { await dialog.accept(); });

  await app.page.evaluate(async () => { await window.__FL_TESTS.cloudPullBackup(); });
  await app.page.waitForTimeout(400);
  const toastText = await app.page.textContent('#toast').catch(() => '');

  ok(/partial restore/i.test(toastText), `expected a visible "partial restore" warning toast when deltas were pruned, got: ${JSON.stringify(toastText)}`);
  console.log(`    [evidence] gap-warning toast: ${JSON.stringify(toastText)}`);
});

// This spec does NOT use harness.mjs's launchApp()/shared http-server: it
// needs the page and the mock Worker API on the exact same origin (see
// tests/lib/mock-worker.mjs's top comment for why), so it launches its own
// browser pointed at the mock server's combined static+API port instead.
export async function runSpec() {
  worker = await startMockWorker();
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  await context.addInitScript(() => { window.__FL_TESTS_ENABLED = true; });
  const page = await context.newPage();
  await page.goto(worker.appUrl, { waitUntil: 'load' });
  await page.waitForFunction(() => !!document.getElementById('appMeta')?.textContent, { timeout: 15000 });
  app = { browser, context, page, close: async () => { await browser.close(); } };
  await skipFirstRunWizard(app.page);
  try {
    return await run();
  } finally {
    if (worker) await worker.close();
    await app.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
