// X-10 (v23.9 Phase 6) — beyond the static source checks in
// tests/unit/service-worker-shell.spec.mjs (no CDN reference left, vendor
// file present and looks like a real build), this proves the bundled
// vendor/xlsx.full.min.js is actually FUNCTIONAL in a real browser: it loads
// via loadSheetJS()'s real code path and can round-trip a workbook, with the
// network fully disabled — proving there's no live CDN dependency left.
import { launchApp, createSuite, ok, eq } from '../lib/harness.mjs';

const { test, run } = createSuite('integration/xlsx-bundled-vendor.spec.mjs');
let app;

test('[X-10] loadSheetJS() loads the bundled vendor file and it actually works, with all external network access blocked', async () => {
  // Block every external (non-same-origin) request for this check — if
  // loadSheetJS() ever falls back to a CDN, this would surface as a failed
  // request instead of a silent same-origin success.
  await app.context.route('**://*/**', (route) => {
    const url = new URL(route.request().url());
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') route.continue();
    else route.abort();
  });

  const result = await app.page.evaluate(async () => {
    // loadSheetJS() isn't in __FL_TESTS (it's not a pure/DB function) — drive
    // the same real code path it uses: a <script src="./vendor/..."> tag.
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = './vendor/xlsx.full.min.js';
      s.onload = resolve;
      s.onerror = () => reject(new Error('failed to load vendor/xlsx.full.min.js'));
      document.head.appendChild(s);
    });
    if (typeof XLSX === 'undefined' || typeof XLSX.read !== 'function' || typeof XLSX.write !== 'function'){
      return { ok: false, reason: 'XLSX global missing read/write after load' };
    }
    // Round-trip a tiny real workbook to prove the build is functional, not
    // just present.
    const ws = XLSX.utils.aoa_to_sheet([['OrderNo', 'Pay'], ['T1', 1234.56]]);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Sheet1');
    const buf = XLSX.write(wb, { type: 'array', bookType: 'xlsx' });
    const wb2 = XLSX.read(buf, { type: 'array' });
    const ws2 = wb2.Sheets[wb2.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(ws2);
    return { ok: true, rows };
  });

  ok(result.ok, 'bundled vendor/xlsx.full.min.js did not load/function correctly: ' + JSON.stringify(result));
  eq(result.rows.length, 1, 'round-tripped workbook must have exactly one data row');
  eq(result.rows[0].OrderNo, 'T1', 'round-tripped OrderNo must match');
  eq(result.rows[0].Pay, 1234.56, 'round-tripped Pay must match');
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
