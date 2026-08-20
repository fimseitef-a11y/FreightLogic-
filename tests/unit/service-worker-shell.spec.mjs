// X-08 (v23.9 Phase 6) + Amendment 4 — the service worker's install-blocking
// `critical` shell array must include midwest-stack-authority.js (X-08) and
// the bundled SheetJS vendor file (X-10), not just the broader, non-blocking
// CORE list — otherwise a first offline install can complete and serve the
// app shell before either asset is actually cached, with no error surfaced.
// Pure static-source check — no browser needed, so this doesn't use
// launchApp()/the shared http-server at all.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');

const { test, run } = createSuite('unit/service-worker-shell.spec.mjs');

function readServiceWorker() {
  return readFileSync(path.join(REPO_ROOT, 'service-worker.js'), 'utf8');
}

test('[X-08/X-10] the install-blocking critical shell includes midwest-stack-authority.js and vendor/xlsx.full.min.js', () => {
  const text = readServiceWorker();
  const m = text.match(/const critical = \[([^\]]*)\]/);
  ok(m, 'could not find `const critical = [...]` in service-worker.js — has the install handler been restructured?');
  const contents = m[1];
  ok(contents.includes('midwest-stack-authority.js'), `X-08: critical shell must include midwest-stack-authority.js — got: ${contents}`);
  ok(contents.includes('vendor/xlsx.full.min.js'), `X-10: critical shell must include vendor/xlsx.full.min.js — got: ${contents}`);
});

test('[X-10] loadSheetJS() in app.js has no CDN fallback left — only the bundled vendor file', () => {
  const appJs = readFileSync(path.join(REPO_ROOT, 'app.js'), 'utf8');
  const fnMatch = appJs.match(/async function loadSheetJS\(\)\{[\s\S]*?\n\}/);
  ok(fnMatch, 'could not find loadSheetJS() in app.js');
  const body = fnMatch[0];
  ok(!body.includes('cdn.jsdelivr.net'), `loadSheetJS() must not reference cdn.jsdelivr.net (X-10 drops the CDN fallback) — got:\n${body}`);
  ok(body.includes('./vendor/xlsx.full.min.js'), 'loadSheetJS() must load the bundled vendor file');
});

test('[X-10] the vendor file itself exists and is a real SheetJS build, not a placeholder', () => {
  const vendorPath = path.join(REPO_ROOT, 'vendor', 'xlsx.full.min.js');
  const contents = readFileSync(vendorPath, 'utf8');
  ok(contents.length > 100000, `vendor/xlsx.full.min.js looks too small to be a real SheetJS build (${contents.length} bytes)`);
  ok(/SheetJS/i.test(contents.slice(0, 200)), 'vendor/xlsx.full.min.js does not look like a genuine SheetJS build (no SheetJS banner in the first 200 bytes)');
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
