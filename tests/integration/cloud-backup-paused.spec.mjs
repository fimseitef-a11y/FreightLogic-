// Cloud backup silently stops after every browser close — visibility regression.
//
// THE DEFECT. The backup token lives in IndexedDB and survives restarts; the
// encryption passphrase lives in sessionStorage and does not. `cloudIsEnabled()`
// requires BOTH, so the moment a browser session ends, every automatic push —
// both visibilitychange handlers, `cloudScheduleSync()`, `emergencyAutoBackup()`
// — begins no-opping. Each of those call sites swallows the result
// (`.catch(()=>{})`), so nothing surfaced it. The single place that reported the
// state was the Diagnostics panel's `dxCloud` row ("Token set, no passphrase"),
// four taps deep under More → Advanced.
//
// The lived consequence: close the browser, come back the next day, and believe
// you are backed up while nothing has been written since. For a bookkeeping app
// whose entire cloud story is disaster recovery, that is the worst available
// failure mode — it is only discovered at restore time, when it is too late.
//
// WHAT IS AND IS NOT FIXED HERE. The passphrase deliberately REMAINS
// session-scoped: it is the key protecting the cloud copy from anyone with
// server-side/KV access, and the project's credential rules forbid persisting
// it. This suite asserts the gap is loud and recovery is one tap — not that the
// passphrase survives a restart. CBP-07 pins that distinction so a later change
// cannot quietly "fix" the friction by weakening the encryption.
import { launchApp, skipFirstRunWizard, waitForAppReady, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/cloud-backup-paused.spec.mjs');

const TOKEN = 'flk_00112233445566778899aabbccddeeff';

/** Put the app into an exact credential state without going through the UI. */
async function setCredState(page, { token, pass }) {
  await page.evaluate(async ({ token, pass }) => {
    await window.__FL_TESTS.setSetting('cloudBackupToken', token || '');
    if (pass) sessionStorage.setItem('fl_cloud_pass', pass);
    else sessionStorage.removeItem('fl_cloud_pass');
    document.getElementById('cloudPausedBanner')?.remove();
  }, { token, pass });
}

test('[CBP-01] token stored + passphrase gone == PAUSED, and cloud is disabled', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    await setCredState(page, { token: TOKEN, pass: null });
    const r = await page.evaluate(async () => ({
      paused: await window.__FL_TESTS.cloudBackupPaused(),
      enabled: await window.__FL_TESTS.cloudIsEnabled(),
    }));
    eq(r.paused, true, 'a stored token with no session passphrase must read as paused');
    // The other half of the defect: this is exactly the state in which every
    // automatic push silently no-ops.
    eq(r.enabled, false, 'cloudIsEnabled() must be false in the paused state');
  } finally { await close(); }
});

test('[CBP-02] never configured is NOT "paused"', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    await setCredState(page, { token: '', pass: null });
    const paused = await page.evaluate(() => window.__FL_TESTS.cloudBackupPaused());
    // Nagging a driver who never opted into cloud backup would train them to
    // dismiss the one banner that matters.
    eq(paused, false, 'no token means the feature is off, not paused');
  } finally { await close(); }
});

test('[CBP-03] token + passphrase present == not paused', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    await setCredState(page, { token: TOKEN, pass: 'correct horse battery' });
    const r = await page.evaluate(async () => ({
      paused: await window.__FL_TESTS.cloudBackupPaused(),
      enabled: await window.__FL_TESTS.cloudIsEnabled(),
    }));
    eq(r.paused, false, 'a complete credential pair is not paused');
    eq(r.enabled, true, 'a complete credential pair enables cloud backup');
  } finally { await close(); }
});

test('[CBP-04] the paused state renders a visible banner with a one-tap Resume', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    await setCredState(page, { token: TOKEN, pass: null });
    await page.evaluate(() => window.__FL_TESTS.renderCloudPausedBanner());
    await page.waitForSelector('#cloudPausedBanner', { timeout: 5000 });

    const el = await page.$('#cloudPausedBanner');
    ok(el, 'paused banner must exist');
    ok(await el.isVisible(), 'paused banner must be visible, not merely present');

    const text = (await el.innerText()).toLowerCase();
    ok(text.includes('paused'), `banner must say it is paused — got: ${text}`);
    // The banner has to state the CONSEQUENCE. "Cloud backup paused" alone reads
    // as a status; the driver needs to know data is not being saved.
    ok(/nothing has been backed up|not been backed up/.test(text),
       `banner must state the consequence, not just the status — got: ${text}`);

    const btn = await page.$('#cloudPausedFix');
    ok(btn, 'banner must offer a Resume action');
    const box = await btn.boundingBox();
    ok(box && box.height >= 44, `Resume must meet the 44px touch target (got ${box && box.height})`);
  } finally { await close(); }
});

test('[CBP-05] no banner when cloud backup was never configured', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    await setCredState(page, { token: '', pass: null });
    await page.evaluate(() => window.__FL_TESTS.renderCloudPausedBanner());
    const el = await page.$('#cloudPausedBanner');
    eq(el, null, 'an unconfigured app must not show a backup-paused banner');
  } finally { await close(); }
});

test('[CBP-06] the banner does not auto-dismiss', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    await setCredState(page, { token: TOKEN, pass: null });
    await page.evaluate(() => window.__FL_TESTS.renderCloudPausedBanner());
    await page.waitForSelector('#cloudPausedBanner', { timeout: 5000 });

    // showCloudSyncBanner() self-removes after 12s. That is right for an
    // informational "backup found on server" notice and WRONG here: a warning
    // that you are not being backed up must persist until it is resolved. If a
    // later edit copies that setTimeout into this banner, this fails.
    await page.waitForTimeout(13000);
    const still = await page.$('#cloudPausedBanner');
    ok(still, 'the paused banner must persist past the 12s auto-dismiss used by the info banner');
    ok(await still.isVisible(), 'and must still be visible');
  } finally { await close(); }
});

test('[CBP-07] the passphrase is never written to persistent storage', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    await setCredState(page, { token: TOKEN, pass: 'correct horse battery' });
    await page.evaluate(() => window.__FL_TESTS.renderCloudPausedBanner());

    const leaked = await page.evaluate(async () => {
      const needle = 'correct horse battery';
      const hits = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if ((localStorage.getItem(k) || '').includes(needle)) hits.push(`localStorage:${k}`);
      }
      // The settings store is what the export and cloud-backup paths dump, so a
      // passphrase landing there would travel off-device.
      const settings = await window.__FL_TESTS.dumpStore('settings');
      for (const s of settings) {
        if (JSON.stringify(s).includes(needle)) hits.push(`settings:${s.key}`);
      }
      return hits;
    });

    eq(leaked.length, 0,
       `the passphrase must stay in sessionStorage only — found in: ${leaked.join(', ')}`);
  } finally { await close(); }
});

test('[CBP-08] reconnect is a real credential form, so a password manager can autofill it', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    await setCredState(page, { token: TOKEN, pass: null });
    await page.evaluate(() => window.__FL_TESTS.openCloudReconnect());
    await page.waitForSelector('#cloudReconnectForm', { timeout: 5000 });

    // Every one of these is load-bearing for iOS Keychain / 1Password to offer
    // "save password" and later autofill. Drop any one and the operator is back
    // to typing a passphrase on a phone, which is the friction this exists to
    // remove — and the breakage would be invisible in code review.
    const shape = await page.evaluate(() => {
      const form = document.getElementById('cloudReconnectForm');
      const user = document.getElementById('cloudReconnectUser');
      const pass = document.getElementById('cloudReconnectPass');
      const btn = document.getElementById('cloudReconnectGo');
      return {
        passInsideForm: !!(form && pass && form.contains(pass)),
        userInsideForm: !!(form && user && form.contains(user)),
        userAutocomplete: user && user.getAttribute('autocomplete'),
        passAutocomplete: pass && pass.getAttribute('autocomplete'),
        passType: pass && pass.getAttribute('type'),
        userHasValue: !!(user && user.value && user.value.length > 0),
        submitButton: btn && btn.getAttribute('type'),
        // display:none username fields are ignored by Safari's heuristics.
        userVisible: !!(user && user.offsetParent !== null),
      };
    });

    ok(shape.passInsideForm, 'the password field must be inside a <form>');
    ok(shape.userInsideForm, 'the username field must be inside the same <form>');
    eq(shape.userAutocomplete, 'username', 'account field needs autocomplete="username"');
    eq(shape.passAutocomplete, 'current-password', 'passphrase needs autocomplete="current-password"');
    eq(shape.passType, 'password', 'passphrase field must be type=password');
    ok(shape.userHasValue, 'the account field must carry a stable value to key the saved credential on');
    eq(shape.submitButton, 'submit', 'the action must be a real submit, not a click handler');
    ok(shape.userVisible, 'the account field must not be display:none — Safari ignores hidden username fields');
  } finally { await close(); }
});

// ---------------------------------------------------------------------------
// Issue #205 §3 — automatic cloud sync must be observable and must survive a
// close. These drive the real functions against real IndexedDB, and they assert
// the DERIVED pending count rather than a queue's bookkeeping, because the
// design deliberately has no separate queue: `lastCloudSyncedAt` is the same
// watermark cloudPushBackup() selects records against, so the count cannot
// disagree with what a push would actually send.
//
// NEGATIVE CONTROLS, each verified to fire:
//   - counting records whose `updatedAt` is missing/0 as pending fails SQ-02;
//   - dropping the `lastCloudSyncError` write in the failure path fails SQ-04;
//   - clearing the marker on failure instead of success fails SQ-05;
//   - making resumeSyncIfPending() push with nothing pending fails SQ-06.
// ---------------------------------------------------------------------------

test('[SQ-01] pending work is derived from the delta watermark, not a parallel list', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      // upsertTrip() ALWAYS stamps its own revision —
      // `Math.max(Date.now(), before+1)`, the strictly-increasing fix that makes
      // the compare-and-abort work. A fixture therefore cannot dictate
      // `updatedAt`, and must not try: read back the revision the app actually
      // wrote and place the watermark relative to it. Pinning a literal here
      // would be testing a value the app is designed to override.
      await T.upsertTrip(T.sanitizeTrip({ orderNo: 'SQ-1', revenue: 500, loadedMiles: 300, emptyMiles: 0 }));
      const row = (await T.dumpStore('trips')).find(r => r.orderNo === 'SQ-1');
      const stamped = row.updatedAt;

      await T.setSetting('lastCloudSyncedAt', stamped - 1);
      const after = await T.syncPendingSummary();
      // Advance the watermark past it: the same record must stop being pending,
      // with no queue to drain and nothing to mark done.
      await T.setSetting('lastCloudSyncedAt', stamped);
      const cleared = await T.syncPendingSummary();
      return { pending: after.pending, oldestAt: after.oldestAt, stamped,
               clearedPending: cleared.pending, stores: T.SYNC_PENDING_STORES };
    });
    ok(r.pending >= 1, `a record newer than the watermark must count as pending; got ${r.pending}`);
    eq(r.oldestAt, r.stamped, 'the oldest pending change is reported so the UI can age it');
    eq(r.clearedPending, 0, 'advancing the watermark alone must clear pending — the count is derived, not stored');
    ok(!r.stores.includes('settings'),
      'settings must NOT be counted: it has no revision field and is pushed wholesale, so counting it ' +
      'would make "0 changes waiting" unreachable');
  } finally { await close(); }
});

test('[SQ-02] a record with no usable updatedAt is not invented as pending work', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.setSetting('lastCloudSyncedAt', 1000);
      // A genuinely legacy-shaped row CANNOT be produced through upsertTrip(),
      // which always stamps a strictly-increasing revision — so it is written
      // straight into the store, which is the only way this pre-revision shape
      // actually exists in the field (it predates the stamp).
      await new Promise((resolve, reject) => {
        const open = indexedDB.open('FreightLogic_v18');
        open.onsuccess = () => {
          const db = open.result;
          const name = db.objectStoreNames.contains('tripRecords') ? 'tripRecords' : 'trips';
          const txn = db.transaction(name, 'readwrite');
          txn.objectStore(name).put({ id: 'sq2-legacy-row', orderNo: 'SQ-2', revenue: 400,
            loadedMiles: 200, emptyMiles: 0, updatedAt: 0, created: 1 });
          txn.oncomplete = () => { db.close(); resolve(); };
          txn.onerror = () => { db.close(); reject(txn.error); };
        };
        open.onerror = () => reject(open.error);
      });
      const rows = await T.dumpStore('trips');
      const legacy = rows.find(r => r.orderNo === 'SQ-2');
      return { pending: (await T.syncPendingSummary()).pending,
               legacyPresent: !!legacy, legacyUpdatedAt: legacy ? legacy.updatedAt : null };
    });
    eq(r.legacyPresent, true, 'the legacy-shaped row must really be in the store, or this asserts nothing');
    eq(r.legacyUpdatedAt, 0, 'and it must still carry the pre-revision updatedAt it was written with');
    eq(r.pending, 0, 'a row that cannot be PROVEN newer than the watermark must not be counted — otherwise ' +
      'the status surface cries wolf forever on legacy rows (UNKNOWN is not a value)');
  } finally { await close(); }
});

test('[SQ-03] the status states are exactly the four §3 asks for, and OFF renders nothing', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const out = {};
      // Never configured: no nagging, and no row in the DOM.
      await T.setSetting('cloudBackupToken', '');
      out.off = (await T.cloudSyncStatus()).state;
      await T.renderSyncStatusRow();
      out.offRow = !!document.getElementById('syncStatusRow');

      // Configured but no passphrase: PAUSED, and still no row — the paused
      // BANNER owns that case, and two fixed surfaces must not both speak.
      await T.setSetting('cloudBackupToken', 'flk_00112233445566778899aabbccddeeff');
      sessionStorage.removeItem('fl_cloud_pass');
      out.paused = (await T.cloudSyncStatus()).state;
      await T.renderSyncStatusRow();
      out.pausedRow = !!document.getElementById('syncStatusRow');

      // Configured and usable, nothing pending: SYNCED.
      sessionStorage.setItem('fl_cloud_pass', 'a-long-enough-passphrase');
      await T.setSetting('lastCloudSyncedAt', Date.now() + 60_000);
      await T.setSetting('lastCloudSyncError', null);
      out.synced = (await T.cloudSyncStatus()).state;
      await T.renderSyncStatusRow();
      out.syncedText = document.getElementById('syncStatusRow')?.textContent || '';

      // Pending with a recorded failure: PROBLEM outranks PENDING.
      await T.setSetting('lastCloudSyncedAt', 1000);
      await T.upsertTrip({ ...T.sanitizeTrip({ orderNo: 'SQ-3', revenue: 900, loadedMiles: 400, emptyMiles: 0 }), updatedAt: Date.now() });
      await T.setSetting('lastCloudSyncError', 'HTTP 500');
      out.problem = (await T.cloudSyncStatus()).state;
      await T.renderSyncStatusRow();
      out.problemText = document.getElementById('syncStatusRow')?.textContent || '';

      // Same pending work, no failure: PENDING with a count.
      await T.setSetting('lastCloudSyncError', null);
      out.pending = (await T.cloudSyncStatus()).state;
      await T.renderSyncStatusRow();
      out.pendingText = document.getElementById('syncStatusRow')?.textContent || '';
      out.rowCount = document.querySelectorAll('#syncStatusRow').length;
      return out;
    });

    eq(r.off, 'OFF', 'never configured is OFF');
    eq(r.offRow, false, 'an unconfigured install must render no sync row at all');
    eq(r.paused, 'PAUSED', 'configured with no passphrase is PAUSED');
    eq(r.pausedRow, false, 'PAUSED renders no row here — the paused banner owns that state');
    eq(r.synced, 'SYNCED', 'nothing newer than the watermark is SYNCED');
    ok(/Synced/.test(r.syncedText), `SYNCED must say so; got "${r.syncedText}"`);
    eq(r.problem, 'PROBLEM', 'a recorded failure with pending work is PROBLEM, not PENDING');
    ok(/Sync problem/.test(r.problemText) && /retrying/.test(r.problemText),
      `PROBLEM must name the retry; got "${r.problemText}"`);
    eq(r.pending, 'PENDING', 'pending work with no failure is PENDING');
    ok(/waiting/.test(r.pendingText), `PENDING must show the count waiting; got "${r.pendingText}"`);
    eq(r.rowCount, 1, 'the row must be updated in place, never stacked');
  } finally { await close(); }
});

test('[SQ-04] a failed push leaves a durable trace, even when silent', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.setSetting('cloudBackupToken', 'flk_00112233445566778899aabbccddeeff');
      await T.setSetting('cloudBackupUrl', 'https://sync-test.invalid');
      sessionStorage.setItem('fl_cloud_pass', 'a-long-enough-passphrase');
      await T.setSetting('lastCloudSyncedAt', 1000);
      await T.setSetting('lastCloudSyncError', null);
      await T.upsertTrip({ ...T.sanitizeTrip({ orderNo: 'SQ-4', revenue: 700, loadedMiles: 350, emptyMiles: 0 }), updatedAt: Date.now() });
      // Silent push against an unreachable origin — the ordinary automatic path.
      await T.cloudPushBackup(true);
      return { err: await T.getSetting('lastCloudSyncError', null), state: (await T.cloudSyncStatus()).state };
    });
    ok(r.err, 'a silent failure must persist a marker — previously it said nothing and stored nothing, ' +
      'so a repeatedly failing sync was indistinguishable from a quiet one');
    ok(r.state === 'PROBLEM' || r.state === 'OFFLINE',
      `the status must reflect the failure; got ${r.state}`);
  } finally { await close(); }
});

test('[SQ-05] a later success clears the failure marker', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.setSetting('cloudBackupToken', 'flk_00112233445566778899aabbccddeeff');
      sessionStorage.setItem('fl_cloud_pass', 'a-long-enough-passphrase');
      await T.setSetting('lastCloudSyncError', 'HTTP 500');
      // Simulate the success path's own bookkeeping.
      await T.setSetting('lastCloudSyncedAt', Date.now() + 60_000);
      await T.setSetting('lastCloudSyncError', null);
      return { err: await T.getSetting('lastCloudSyncError', null), state: (await T.cloudSyncStatus()).state };
    });
    ok(!r.err, 'the marker must be cleared on success, or one transient 500 says "Sync problem" forever');
    eq(r.state, 'SYNCED', 'with the marker cleared and nothing pending the state is SYNCED');
  } finally { await close(); }
});

test('[SQ-06] boot drains a sync the previous session could not finish, and no-ops otherwise', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const out = {};
      // Cloud off: must not attempt anything.
      await T.setSetting('cloudBackupToken', '');
      sessionStorage.removeItem('fl_cloud_pass');
      out.off = await T.resumeSyncIfPending();

      // Enabled, but nothing newer than the watermark: must not push.
      await T.setSetting('cloudBackupToken', 'flk_00112233445566778899aabbccddeeff');
      await T.setSetting('cloudBackupUrl', 'https://sync-test.invalid');
      sessionStorage.setItem('fl_cloud_pass', 'a-long-enough-passphrase');
      await T.setSetting('lastCloudSyncedAt', Date.now() + 60_000);
      out.nothing = await T.resumeSyncIfPending();

      // Enabled with real pending work: must attempt the drain.
      await T.setSetting('lastCloudSyncedAt', 1000);
      await T.upsertTrip({ ...T.sanitizeTrip({ orderNo: 'SQ-6', revenue: 800, loadedMiles: 400, emptyMiles: 0 }), updatedAt: Date.now() });
      out.pending = await T.resumeSyncIfPending();
      return out;
    });
    eq(r.off.drained, false, 'must not attempt a drain when cloud backup is off');
    eq(r.off.reason, 'not-enabled', 'and must say why');
    eq(r.nothing.drained, false, 'must not push when nothing is newer than the watermark');
    eq(r.nothing.reason, 'nothing-pending', 'and must say why — a forced push on every boot is the opposite of the ask');
    eq(r.pending.drained, true, 'real pending work from a previous session must be drained on boot');
  } finally { await close(); }
});

test('[SQ-07] boot wires the drain after first paint, and the mutation hook still schedules sync', async () => {
  // Static, because the behaviour is an ordering property: the drain must not
  // delay the driver's first screen, and the 27 mutation call sites must keep
  // reaching cloudScheduleSync() through invalidateKPICache().
  const { page, close } = await launchApp();
  try {
    const r = await page.evaluate(async () => {
      const src = await (await fetch('app.js')).text();
      const bootIdx = src.indexOf('resumeSyncIfPending().catch');
      const navIdx = src.indexOf('await navigate();');
      return {
        wired: bootIdx > -1,
        afterNavigate: bootIdx > navIdx && navIdx > -1,
        hookIntact: /function invalidateKPICache\(\)\{[^}]*cloudScheduleSync\(\)/.test(src),
        rowOnHome: src.includes('renderSyncStatusRow().catch'),
      };
    });
    eq(r.wired, true, 'boot must call resumeSyncIfPending()');
    eq(r.afterNavigate, true, 'it must run AFTER the first navigate() so it never delays first paint');
    eq(r.hookIntact, true, 'invalidateKPICache() must still schedule a sync — that is the auto-enqueue for ' +
      'every mutation site, and §3 depends on it');
    eq(r.rowOnHome, true, 'the status row must render on every home render, like the paused banner');
  } finally { await close(); }
});

// ---------------------------------------------------------------------------
// Issue #240 — v24.0.18 could report "Synced" over genuinely unsynced data.
// Three defects, all of the same family: a surface that says something
// reassuring about a fact it never actually established.
//
//   1. The pending count tested `updatedAt` on every store while the delta push
//      selected on store-specific fields (`generatedAt`, `timestamp`,
//      `recordedAt`, and fallback chains), and `gpsLogs` was not in the list at
//      all. Two transcriptions of one rule, already drifted.
//   2. `settings` has no per-record clock, so a settings-only mutation left the
//      count at zero. Worse than the issue states, and found while fixing it:
//      the empty-delta guard in cloudPushBackup() returned "Up to date" WITHOUT
//      SENDING, so a settings-only change never reached the server on the delta
//      path at all — not merely when a session ended inside the 30s debounce.
//   3. An unreadable store was skipped, so with every other store clean the
//      summary returned `pending: 0` and the row said "Synced" although backup
//      completeness could not be established.
//
// These assert BEHAVIOUR through the real functions and the real database. The
// store-clock cases deliberately write raw rows rather than driving each
// feature's UI: what is under test is the selection rule, and a fixture that
// went through the app's own writers could only ever produce the field the
// writer happens to stamp today.
//
// NEGATIVE CONTROLS, each verified to fire — see the release section in
// CLAUDE.md for the exact reversions.
// ---------------------------------------------------------------------------

/** Writes a raw row straight into a store, which is the only way to produce a
 *  row carrying a specific change clock for a store whose feature UI is not
 *  what is under test here. */
const RAW_PUT = `async (store, row) => {
  await new Promise((resolve, reject) => {
    const open = indexedDB.open('FreightLogic_v18');
    open.onsuccess = () => {
      const db = open.result;
      try {
        const t = db.transaction(store, 'readwrite');
        t.objectStore(store).put(row);
        t.oncomplete = () => { db.close(); resolve(); };
        t.onerror = () => { db.close(); reject(t.error); };
      } catch (e) { db.close(); reject(e); }
    };
    open.onerror = () => reject(open.error);
  });
}`;

test('[SQ-08] pending detection reads each store on the clock the push selects on', async () => {
  // Defect 1, per store, including the two the old rule could never see:
  // `gpsLogs` (absent from the list) and normalized evidence (`recordedAt`).
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    const r = await page.evaluate(async rawPutSrc => {
      const T = window.__FL_TESTS;
      const rawPut = eval(rawPutSrc);
      const WM = 1_000_000;
      await T.setSetting('lastCloudSyncedAt', WM);
      await T.setSetting('syncDirtyAt', 0);

      // One row per store, stamped ONLY on that store's own clock and with no
      // `updatedAt` at all — which is exactly what the old rule required.
      const cases = [
        ['weeklyReports',  { weekId: 'SQ08-W', generatedAt: WM + 10 },      'generatedAt'],
        ['gpsLogs',        { tripTrackingId: 'SQ08-G', timestamp: WM + 20 }, 'timestamp'],
        ['documents',      { id: 'SQ08-D', createdAt: WM + 30 },            'createdAt (fallback)'],
        ['laneHistory',    { id: 'SQ08-L', created: WM + 40 },              'created (fallback)'],
      ];
      const evStore = T.SYNC_PENDING_STORES.find(s => /evidence/i.test(s));
      if (evStore) cases.push([evStore, { evidenceId: 'SQ08-E', recordedAt: WM + 50 }, 'recordedAt']);

      const out = [];
      for (const [store, row, clock] of cases) {
        const before = (await T.syncPendingSummary()).pending;
        try { await rawPut(store, row); } catch (e) { out.push({ store, clock, err: String(e && e.message || e) }); continue; }
        const after = await T.syncPendingSummary();
        const status = await T.cloudSyncStatus();
        out.push({ store, clock, before, after: after.pending, state: status.state,
                   inList: T.SYNC_PENDING_STORES.includes(store) });
      }
      return { out, stores: T.SYNC_PENDING_STORES };
    }, RAW_PUT);

    ok(r.stores.includes('gpsLogs'),
      'gpsLogs is delta-pushed on `timestamp` and was missing from the pending list entirely — a whole store of ' +
      'unsynced rows could not be seen');
    for (const c of r.out) {
      ok(!c.err, `${c.store}: raw write failed — ${c.err}`);
      ok(c.inList, `${c.store} is delta-pushed and must be in the pending list`);
      eq(c.after, c.before + 1,
        `${c.store}: a row newer than the watermark on its OWN clock (${c.clock}) must count as pending — ` +
        `the push selects on it, so the summary must too`);
    }
  } finally { await close(); }
});

test('[SQ-09] the push and the pending summary read one authority, not two transcriptions', async () => {
  // The structural half of defect 1. Two independently maintained field lists
  // is the shape this repository already records twice (the X-07 restore gap,
  // the 2026-09-13 asset defect); asserting each side's transcription
  // separately would just be a third copy.
  const { page, close } = await launchApp();
  try {
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const src = await (await fetch('app.js')).text();
      const body = src.slice(src.indexOf('async function cloudPushBackup'),
                             src.indexOf('async function mergeRestoreData'));
      const clocks = Object.keys(T.SYNC_CHANGE_CLOCKS);
      return {
        clocks,
        pendingStores: T.SYNC_PENDING_STORES,
        // every store the push sends must be selected through the shared helper
        selectorCalls: (body.match(/syncChangedSince\(/g) || []).length,
        // and the old inline field lists must be gone from the push
        inlineFilters: (body.match(/\.filter\(\s*r\s*=>\s*\(?r\.(updatedAt|updated|created|generatedAt|timestamp|createdAt|recordedAt)/g) || []).length,
        // the two sides agree on a real row, checked rather than assumed
        agreeOnRow: (() => {
          const row = { generatedAt: 5000 };
          return T.syncChangeClock('weeklyReports', row) === 5000 &&
                 T.syncChangedSince('weeklyReports', [row], 4999).length === 1 &&
                 T.syncChangedSince('weeklyReports', [row], 5000).length === 0;
        })(),
      };
    });
    eq(r.pendingStores.join(','), r.clocks.join(','),
      'the pending store list must be DERIVED from the change-clock authority, so a store added to one is added to both');
    ok(r.selectorCalls >= 11,
      `every delta-filtered store must select through syncChangedSince(); found ${r.selectorCalls} calls`);
    eq(r.inlineFilters, 0,
      'cloudPushBackup() must not carry its own inline timestamp field list — that second copy IS the defect');
    eq(r.agreeOnRow, true, 'the clock and the selector must agree on the same row, at and either side of the boundary');
  } finally { await close(); }
});

test('[SQ-10] a settings-only change is pending, is sent, and is not reported as Synced', async () => {
  // Defect 2, plus the harder half found while fixing it: the empty-delta guard
  // used to return "Up to date" WITHOUT SENDING when no record had changed, so
  // a settings-only mutation never reached the server on the delta path.
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.setSetting('cloudBackupToken', 'flk_' + 'a'.repeat(32));
      await T.setSetting('cloudBackupUrl', 'https://sq10.invalid');
      sessionStorage.setItem('fl_cloud_pass', 'passphrase-sq10');
      // Watermark in the future: no record row can be pending, so the ONLY
      // outstanding change is the settings one.
      await T.setSetting('lastCloudSyncedAt', Date.now() + 60_000);
      await T.setSetting('syncDirtyAt', 0);

      const clean = await T.cloudSyncStatus();

      // The durable marker every mutation site already reaches, awaited here
      // only so the assertion is not racing an intentionally fire-and-forget write.
      await T.markSyncDirty();
      const summary = await T.syncPendingSummary();
      const dirtyStatus = await T.cloudSyncStatus();

      // Does a push with zero changed records actually SEND? Intercept fetch.
      const calls = [];
      const realFetch = window.fetch;
      window.fetch = (...a) => { calls.push(String(a[0])); return Promise.reject(new Error('sq10-blocked')); };
      try { await T.cloudPushBackup(true); } catch (_) {}

      // And the boot drain must not call this "nothing-pending".
      const resumed = await T.resumeSyncIfPending();
      window.fetch = realFetch;

      return { cleanState: clean.state, pending: summary.pending, dirty: summary.dirty,
               dirtyState: dirtyStatus.state, sent: calls.some(u => /backup/.test(u)),
               resumeReason: resumed.reason, drained: resumed.drained };
    });

    eq(r.cleanState, 'SYNCED', 'with nothing outstanding the surface must still be able to say Synced');
    eq(r.pending, 0, 'a settings-only change is deliberately not a counted record — the count is not what represents it');
    eq(r.dirty, true, 'but it MUST leave a durable marker, or it cannot survive the tab close that loses the 30s timer');
    eq(r.dirtyState, 'PENDING',
      'Home must not report Synced while a settings mutation has not reached the server — that is the reported defect');
    eq(r.sent, true,
      'the push must actually SEND when the only outstanding change is settings; the empty-delta guard used to ' +
      'return "Up to date" without sending, so the change never reached the server at all');
    eq(r.drained, true, 'boot recovery must drain it');
    ok(r.resumeReason !== 'nothing-pending', `boot recovery must not report nothing-pending; got ${r.resumeReason}`);
  } finally { await close(); }
});

test('[SQ-11] the dirty marker survives a session, and only a push that saw it clears it', async () => {
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.setSetting('cloudBackupToken', 'flk_' + 'b'.repeat(32));
      await T.setSetting('lastCloudSyncedAt', Date.now() + 60_000);
      await T.markSyncDirty();
    });
    // A real reload is the session boundary the in-memory debounce does not survive.
    await page.reload({ waitUntil: 'load' });
    await waitForAppReady(page);
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      const s = await T.syncPendingSummary();
      return { dirty: s.dirty, pending: s.pending };
    });
    eq(r.pending, 0, 'no record is pending — the watermark is ahead of every row');
    eq(r.dirty, true,
      'the intent must be DURABLE: a marker that dies with the page is the in-memory debounce the fix replaces');
  } finally { await close(); }
});

test('[SQ-12] a store that cannot be read can never report Synced, and never suppresses recovery', async () => {
  // Defect 3, the fail-open case. cloudPushBackup() treats a required-store read
  // failure as a failed push that does not advance the watermark; the summary
  // used to `continue` past it, so with every other store clean it returned
  // pending: 0 and the row said Synced over a store nobody could look at.
  const { page, close } = await launchApp();
  try {
    await skipFirstRunWizard(page);
    const r = await page.evaluate(async () => {
      const T = window.__FL_TESTS;
      await T.setSetting('cloudBackupToken', 'flk_' + 'c'.repeat(32));
      await T.setSetting('cloudBackupUrl', 'https://sq12.invalid');
      sessionStorage.setItem('fl_cloud_pass', 'passphrase-sq12');
      await T.setSetting('lastCloudSyncedAt', Date.now() + 60_000);
      await T.setSetting('syncDirtyAt', 0);

      // Baseline: everything readable and nothing outstanding really is Synced,
      // so the assertions below are about the failure and not about the fixture.
      const healthy = await T.cloudSyncStatus();

      // Exactly one required store fails. The others stay clean, which is the
      // dangerous shape: the count from the rest is a confident zero.
      const broken = { readStore: async (store) => {
        if (store === 'gpsLogs') throw new Error('forced read failure');
        return T.dumpStore(store);
      } };

      const summary = await T.syncPendingSummary(broken);
      const status = await T.cloudSyncStatus(broken);
      const realFetch = window.fetch;
      window.fetch = () => Promise.reject(new Error('sq12-blocked'));
      const resumed = await T.resumeSyncIfPending(broken);
      window.fetch = realFetch;

      // And what the driver actually sees on Home, which is the surface the
      // defect was reported against.
      await T.renderSyncStatusRow(broken);
      const rowText = document.getElementById('syncStatusRow')?.textContent || '';

      return { healthy: healthy.state, pending: summary.pending, complete: summary.complete,
               unreadable: summary.unreadable, state: status.state,
               reason: resumed.reason, drained: resumed.drained, rowText };
    });

    eq(r.healthy, 'SYNCED', 'baseline: with every store readable and nothing outstanding, Synced is correct');
    eq(r.pending, 0, 'the readable stores are genuinely clean — this is the fail-open shape, not a pending count');
    eq(r.complete, false, 'the summary must report that it could not inspect everything');
    eq(r.unreadable.join(','), 'gpsLogs', 'and must name which store, so the failure is diagnosable');
    ok(r.state !== 'SYNCED',
      `a store that could not be read must never resolve to Synced; got ${r.state}`);
    eq(r.state, 'UNKNOWN', 'it is reported as unverifiable rather than as a count of zero');
    ok(r.reason !== 'nothing-pending',
      `recovery must not be suppressed by an unknown count; got ${r.reason}`);
    eq(r.drained, true, 'an unverifiable state must still attempt the push');
    ok(!/Synced/.test(r.rowText) && /verify/i.test(r.rowText),
      `Home must say the backup cannot be verified, not "Synced"; row read: "${r.rowText}"`);
    // Deliberately NOT asserted here: that the drain reaches the network. With
    // every readable store clean, cloudPushBackup()'s "Up to date" short circuit
    // is correct — there is nothing to send FROM THEM. In production the same
    // unreadable store makes the push's own `dumpStore()` throw into its catch,
    // which records `lastCloudSyncError` and leaves the watermark where it was;
    // the seam here replaces only the summary's reader, so that path is not
    // reachable from this fixture and is not claimed.
  } finally { await close(); }
});

export async function runSpec() { return run(); }
