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
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

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

export async function runSpec() { return run(); }
