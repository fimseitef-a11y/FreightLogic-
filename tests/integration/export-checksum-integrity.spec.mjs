// X-05 (v23.9 Phase 3) — exportJSON()'s checksumFull used to be computed over
// the UNFILTERED settings dump (including fmcsaApiKey/eiaApiKey) but the
// payload's `settings` field was the FILTERED array with those two keys
// stripped — so a genuine, untampered export never matched its own checksum
// on import, and every normal import showed a false "this file has been
// tampered with" warning. Fixed by building `exportableSettings` once (keys
// already stripped) and using that exact array as both the checksumFull
// input and the payload. This spec proves the round-trip: export with the
// two secret keys present in settings -> the checksum matches on import (no
// integrity dialog) -> the two keys are genuinely absent from the export.
import { launchApp, skipFirstRunWizard, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/export-checksum-integrity.spec.mjs');
let app;

async function captureExport(page) {
  return page.evaluate(async () => {
    let captured = null;
    const orig = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (blob) => {
      // synchronous capture path: read the blob text via a FileReader-free
      // trick isn't available sync, so stash the promise and await it below.
      captured = blob.text();
      return orig(blob);
    };
    await window.__FL_TESTS.exportJSON();
    const text = await captured;
    URL.createObjectURL = orig;
    return text;
  });
}

test('[X-05] export with secret API keys present in settings produces a self-consistent checksum and strips the keys', async () => {
  await app.page.evaluate(async () => {
    await window.__FL_TESTS.setSetting('fmcsaApiKey', 'fmcsa-secret-should-not-export');
    await window.__FL_TESTS.setSetting('eiaApiKey', 'eia-secret-should-not-export');
    await window.__FL_TESTS.setSetting('weeklyGoal', 4000); // an ordinary, exportable key for contrast
  });

  const exportedText = await captureExport(app.page);
  ok(exportedText, 'exportJSON() did not produce a captured Blob');
  const data = JSON.parse(exportedText);

  const settingsKeys = (data.settings || []).map(s => s.key);
  ok(!settingsKeys.includes('fmcsaApiKey'), 'exported settings must NOT include fmcsaApiKey: ' + JSON.stringify(settingsKeys));
  ok(!settingsKeys.includes('eiaApiKey'), 'exported settings must NOT include eiaApiKey: ' + JSON.stringify(settingsKeys));
  ok(settingsKeys.includes('weeklyGoal'), 'an ordinary settings key must still export normally');

  // Recompute checksumFull the same way importJSON's verify step does, over
  // the file's OWN settings array — this is the exact mismatch X-05 caused.
  const recomputed = await app.page.evaluate((d) =>
    window.__FL_TESTS.computeExportChecksumFull(d.trips, d.expenses, d.fuel, d.settings), data);
  eq(recomputed, data.meta.checksumFull,
    'checksumFull must be self-consistent with the payload it ships in — X-05 was exactly this mismatch');

  // Full round-trip through the real importJSON(): no integrity dialog should
  // appear at all, since the checksum now genuinely matches.
  let dialogFired = false;
  app.page.once('dialog', async (dialog) => { dialogFired = true; await dialog.dismiss(); });

  await app.page.evaluate(async (text) => {
    const file = new File([text], 'export.json', { type: 'application/json' });
    await window.__FL_TESTS.importJSON(file);
  }, exportedText);
  await app.page.waitForTimeout(300);

  ok(!dialogFired, 'importing a genuine, untampered export must NOT show the "INTEGRITY WARNING" confirm() dialog (X-05)');
});

export async function runSpec() {
  app = await launchApp();
  await skipFirstRunWizard(app.page);
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
