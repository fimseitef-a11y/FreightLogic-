// v24.0.3 "Cache Generation" — static release-identity checks, no browser needed.
//
// Why this spec exists. PR #134 repaired the service-worker update handshake and
// PR #136 added the Diagnostics install-identity readout. Both changed `app.js`
// (and #134 changed `sw-bridge.js`), and both shipped with every version marker
// still reading `24.0.2` — including `SW_VERSION`. That is the failure mode:
//
//   * A browser installs a new service worker only when the WORKER SCRIPT'S OWN
//     BYTES differ from the installed copy. Changing `app.js` does not change
//     `service-worker.js`.
//   * `CACHE_NAME` is derived from `SW_VERSION`, so an unchanged `SW_VERSION`
//     means the same cache name, and the precached shell is reused wholesale.
//   * The `?v=` query strings are the only other cache identity the child
//     assets have, and they were unchanged too.
//
// So a client already holding the pre-repair `24.0.2` shell had no new identity
// to fetch on any axis, and could keep serving the broken bridge indefinitely.
// The repair is only actually DELIVERED by moving the generation.
//
// These assertions are deliberately static and source-derived rather than
// pinned to a hardcoded version string: they enforce the INVARIANT (everything
// moves together) so the suite keeps working at 24.0.4 and beyond without
// edits, and fails the moment one marker is left behind again.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');

const { test, run } = createSuite('unit/cache-generation.spec.mjs');

/** The one generation string every governed marker must agree on. */
function appVersion() {
  const m = read('app.js').match(/^const APP_VERSION = '([0-9]+\.[0-9]+\.[0-9]+)';/m);
  ok(m, 'could not read APP_VERSION from app.js');
  return m[1];
}
function swVersion() {
  const m = read('service-worker.js').match(/^const SW_VERSION = '([0-9]+\.[0-9]+\.[0-9]+)';/m);
  ok(m, 'could not read SW_VERSION from service-worker.js');
  return m[1];
}

test('[CG-01] SW_VERSION equals APP_VERSION — a new app generation changes the worker bytes', () => {
  const app = appVersion();
  const sw = swVersion();
  eq(sw, app,
    `SW_VERSION (${sw}) must equal APP_VERSION (${app}). This is the whole defect: ` +
    'if app.js ships a new generation while SW_VERSION stands still, service-worker.js ' +
    'is byte-identical, the browser never installs a new worker, CACHE_NAME never changes, ' +
    'and an existing client keeps serving the old shell. Bumping SW_VERSION is what makes ' +
    'the release reachable.');
});

test('[CG-02] CACHE_NAME is derived from SW_VERSION, not written independently', () => {
  const sw = read('service-worker.js');
  ok(/const CACHE_NAME = `freightlogic-\$\{SW_VERSION\}`;/.test(sw),
    'CACHE_NAME must be a template literal over SW_VERSION so the cache generation cannot ' +
    'drift from the worker version. A hardcoded cache name is how you get a new worker that ' +
    'still reads the previous generation\'s cache.');
  ok(!/const CACHE_NAME = ['"]freightlogic-[0-9]/.test(sw),
    'CACHE_NAME must not hardcode a literal version');
});

test('[CG-03] every ?v= marker in service-worker.js is the current generation', () => {
  const v = appVersion();
  const sw = read('service-worker.js');
  const found = [...sw.matchAll(/\?v=([0-9]+\.[0-9]+\.[0-9]+)/g)].map(m => m[1]);
  ok(found.length > 0, 'expected versioned asset URLs in service-worker.js');
  const stale = [...new Set(found.filter(f => f !== v))];
  eq(stale.length, 0,
    `service-worker.js carries stale ?v= markers ${JSON.stringify(stale)}; expected all to be ${v}. ` +
    'A stale query string serves a stale asset out of the new cache.');
});

test('[CG-04] every ?v= marker in index.html is the current generation', () => {
  const v = appVersion();
  const found = [...read('index.html').matchAll(/\?v=([0-9]+\.[0-9]+\.[0-9]+)/g)].map(m => m[1]);
  ok(found.length > 0, 'expected versioned asset URLs in index.html');
  const stale = [...new Set(found.filter(f => f !== v))];
  eq(stale.length, 0,
    `index.html carries stale ?v= markers ${JSON.stringify(stale)}; expected all to be ${v}.`);
});

test('[CG-05] the exact URLs index.html requests are the exact URLs the SW precaches', () => {
  // This is the pairing that keeps the offline shell honest. The app-logic branch
  // of the fetch handler looks up `cache.match(req)` WITHOUT { ignoreSearch: true },
  // so a query-string mismatch is a hard cache miss, and the handler then falls
  // back to APP_SHELL — returning index.html, Content-Type text/html, in response
  // to a <script src>. The browser refuses to execute it and the script silently
  // vanishes. Exact agreement here is what prevents that.
  const index = read('index.html');
  const sw = read('service-worker.js');
  const requested = [...index.matchAll(/(?:src|href)="([A-Za-z0-9._/-]+\?v=[0-9.]+)"/g)].map(m => m[1]);
  ok(requested.length >= 4,
    `expected at least 4 versioned assets in index.html (app.js, voice-load.js, sw-bridge.js, manifest.json), found ${requested.length}`);
  for (const url of requested) {
    ok(sw.includes(url),
      `index.html requests "${url}" but service-worker.js never precaches that exact URL. ` +
      'The app-logic cache lookup does not pass { ignoreSearch: true }, so this is a cache ' +
      'miss offline and the handler serves index.html as text/html in its place.');
  }
});

test('[CG-06] the install-blocking critical shell is at the current generation and still complete', () => {
  const v = appVersion();
  const sw = read('service-worker.js');
  const m = sw.match(/const critical = \[([^\]]*)\]/);
  ok(m, 'could not locate the install-blocking `critical` array');
  const body = m[1];
  // X-08 / X-10: these two must stay install-blocking, not merely in CORE.
  ok(body.includes('midwest-stack-authority.js?v=' + v),
    `critical must include midwest-stack-authority.js?v=${v} (X-08) — the TRUE_RPM decision ` +
    'layer must be cached before a first offline install can complete');
  ok(body.includes('vendor/xlsx.full.min.js'),
    'critical must include vendor/xlsx.full.min.js (X-10) — SheetJS is bundled with no CDN fallback');
  ok(body.includes('app.js?v=' + v), `critical must include app.js?v=${v}`);
  const stale = [...new Set([...body.matchAll(/\?v=([0-9]+\.[0-9]+\.[0-9]+)/g)].map(x => x[1]).filter(f => f !== v))];
  eq(stale.length, 0, `critical array carries stale ?v= markers ${JSON.stringify(stale)}; expected ${v}`);
});

test('[CG-07] manifest name, overlay VERSION and the module headers all agree', () => {
  const v = appVersion();
  const manifestName = JSON.parse(read('manifest.json')).name;
  eq(manifestName, `FreightLogic v${v}`, `manifest.json name must read "FreightLogic v${v}"`);

  const overlay = read('midwest-stack-authority.js');
  const om = overlay.match(/const VERSION = '([0-9]+\.[0-9]+\.[0-9]+)';/);
  ok(om, 'could not read VERSION from midwest-stack-authority.js');
  eq(om[1], v, 'midwest-stack-authority.js VERSION must match the app generation');

  // Header comment on each shipped module — historically the quietest drift.
  for (const f of ['service-worker.js', 'sw-bridge.js', 'voice-load.js', 'midwest-stack-authority.js']) {
    const firstLine = read(f).split('\n', 1)[0];
    ok(firstLine.includes(v), `${f} header comment must name v${v}; got: ${firstLine.trim()}`);
  }
});

test('[CG-08] the parity script expects the current generation', () => {
  const v = appVersion();
  const script = read('scripts/verify-cloudflare-parity.mjs');
  ok(script.includes(`serviceWorkerVersion: "${v}"`),
    `verify-cloudflare-parity.mjs EXPECTED.serviceWorkerVersion must be "${v}" or the deploy gate passes on a stale target`);
  ok(script.includes(`manifestName: "FreightLogic v${v}"`),
    `verify-cloudflare-parity.mjs EXPECTED.manifestName must be "FreightLogic v${v}"`);
  ok(script.includes(`overlayScript: "midwest-stack-authority.js?v=${v}"`),
    `verify-cloudflare-parity.mjs EXPECTED.overlayScript must target ?v=${v}`);
});

test('[CG-09] DB version and Worker version are unchanged by a generation freeze', () => {
  // The handoff is explicit: keep DB v15 and Worker v13 unless source semantics
  // require otherwise. A cache-generation bump is a release-identity change only.
  const dbm = read('app.js').match(/^const DB_VERSION = (\d+);/m);
  ok(dbm, 'could not read DB_VERSION from app.js');
  eq(dbm[1], '15', 'DB_VERSION must stay 15 — a cache-generation freeze must not migrate the database');
  ok(read('scripts/verify-cloudflare-parity.mjs').includes('workerVersion: "13"'),
    'the expected Worker version must stay 13 — no Worker source semantics changed');
});

test('[CG-10] index.html and _headers CSP stay byte-identical across the bump', () => {
  // Amendment 5. Editing index.html for ?v= markers is the most likely moment to
  // disturb the neighbouring CSP meta tag, so assert it here too rather than
  // relying only on the parity script an operator has to remember to run.
  const im = read('index.html').match(/content="(default-src[^"]*)"/);
  ok(im, 'could not find the CSP meta tag content in index.html');
  const hm = read('_headers').match(/^\s+Content-Security-Policy:\s(.+)$/m);
  ok(hm, 'could not find the Content-Security-Policy line in _headers');
  eq(im[1], hm[1].trim(),
    'index.html CSP meta and _headers Content-Security-Policy must be byte-identical; ' +
    'Cloudflare Pages serves the _headers copy as the real response and the meta tag is ' +
    'enforced independently, so a drift silently blocks resources on the live site only.');
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
