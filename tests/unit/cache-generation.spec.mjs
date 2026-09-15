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
  for (const f of ['service-worker.js', 'sw-bridge.js', 'voice-load.js', 'midwest-stack-authority.js', 'modern-shell.js']) {
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
  // DB v15 is unchanged. The Worker version is PINNED here rather than derived,
  // deliberately: the point of this assertion is to catch a Worker bump that
  // rides along accidentally with an app-generation bump. So it must be updated
  // by hand, and only when the Worker really did change — which forces someone
  // to state why in this comment.
  //
  // Moved 13 -> 14 for the production-origin/CORS repair the live release probe
  // proved necessary. Moved 14 -> 15 for `POST /admin/users/:id/rotate`: before
  // it, the only way to re-key a driver was to create a new one, which mints a
  // new `userId` and orphans that driver's entire backup history, since backups
  // are keyed `user:<userId>:device:<id>:backup:<ts>`.
  // Moved 15 -> 16 for the live-observed authority-order defect: model-free
  // canonical absence and request validation must work without an OpenAI key.
  // Moved 16 -> 17 because backup/delta keys were minted at millisecond
  // precision, so two writes in one millisecond shared a key and the second
  // silently destroyed the first.
  //
  // This no longer pins a Worker NUMBER. It pins the INVARIANT: the Worker
  // source and the parity gate must name one generation. A literal here had to
  // be hand-edited on every Worker bump, which is the same remembered-marker
  // drift the rest of this spec exists to eliminate.
  const dbm = read('app.js').match(/^const DB_VERSION = (\d+);/m);
  ok(dbm, 'could not read DB_VERSION from app.js');
  eq(dbm[1], '15', 'DB_VERSION must stay 15 — a cache-generation freeze must not migrate the database');
  const workerSrc = read('cloud-backup-worker.js');
  const srcWorker = workerSrc.match(/Cloud Backup Worker v(\d+)/)?.[1];
  const healthWorker = workerSrc.match(/version:\s*'(\d+)'/)?.[1];
  const parityWorker = read('scripts/verify-cloudflare-parity.mjs').match(/workerVersion:\s*"(\d+)"/)?.[1];
  ok(srcWorker, 'could not read the Worker generation from the cloud-backup-worker.js header');
  eq(healthWorker, srcWorker, 'GET /health must report the same generation the Worker header declares');
  eq(parityWorker, srcWorker, 'the parity gate must expect the Worker generation actually in the source');
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

test('[CG-11] styles.css carries no release version, so it cannot drift', () => {
  // Checklist item 7 is RETIRED, and this is what keeps it retired.
  //
  // The design-system header used to carry a release number. The version-bump
  // checklist pointed at index.html — where that comment has not lived since the
  // CSS extraction — so it guarded a location that could not drift while the real
  // marker in styles.css silently missed 24.0.1, 24.0.2 and 24.0.3. The gpt lane
  // fixed it by DELETING the version rather than bumping it (PR #138), which is
  // the better fix: a presentation file with no version cannot go stale, and it
  // removes a cross-lane bump request from every future release.
  //
  // styles.css is gpt-owned, so the core lane cannot bump it. That is precisely
  // why this must be an assertion rather than a line in a checklist: if a version
  // string reappears here, it becomes un-bumpable drift again, and this fails on
  // the very next release instead of three releases later.
  const css = read('styles.css');
  // NB: no leading \b. A version is normally written "v24.0.4", and `v` and `2`
  // are both word characters, so \b never matches between them — an earlier draft
  // of this assertion could not fire at all. Caught by its own negative control.
  const hits = [...css.matchAll(/2[0-9]\.[0-9]+\.[0-9]+/g)].map(m => m[0]);
  eq(hits.length, 0,
    `styles.css must carry no release version; found ${JSON.stringify(hits)}. ` +
    'It is gpt-owned, so a version here cannot be bumped from the core lane and ' +
    'becomes permanent drift. Describe the design system by name, not by release.');
});

test('[CG-12] the modern-shell adapter is at the current generation on every axis', () => {
  // v24.0.8. modern-shell.js is release-bound but is requested by sw-bridge.js
  // via dynamic import, NOT by index.html — so CG-04 and CG-05, which read
  // index.html, could never see it. It was precached by the service worker and
  // referenced by the bridge with nothing asserting the two agreed, which is the
  // same shape of hole that CG-05 exists to close for the index-side assets.
  const v = appVersion();
  const bridge = read('sw-bridge.js');
  const sw = read('service-worker.js');

  const m = bridge.match(/import\((['"])(\.\/modern-shell\.js\?v=[0-9.]+)\1\)/);
  ok(m, 'sw-bridge.js must dynamically import ./modern-shell.js with a ?v= generation marker');
  const imported = m[2];
  ok(imported.endsWith(`?v=${v}`),
    `sw-bridge.js imports "${imported}"; expected ?v=${v}. A stale import string loads the ` +
    'previous generation of the tab bar while every index-side marker reports current.');

  const precached = imported.replace(/^\.\//, '');
  ok(sw.includes(precached),
    `service-worker.js must precache the exact URL sw-bridge.js imports ("${precached}")`);

  const critical = sw.match(/const critical = \[([^\]]*)\]/);
  ok(critical, 'could not locate the install-blocking `critical` array');
  ok(critical[1].includes(precached),
    `critical must include ${precached} — the five-surface tab bar is the app's primary ` +
    'navigation, so a first offline install that completes without it has no way to reach ' +
    'Loads, Trips or Money.');
});

test('[CG-13] every primary tab the shell renders is a route the canonical router owns', () => {
  // v24.0.8, and the whole reason this release exists. PR #168 shipped a Loads
  // tab whose section was created by modern-shell.js AFTER app.js had already
  // built its `views` map from existing markup. `views` had no `loads` entry, so
  // navigate() fell through to `home`: the driver tapped Loads and got the Today
  // screen with the Loads tab highlighted, and the Smart Load Inbox — relocated
  // out of Evaluate into that surface — became unreachable from anywhere.
  //
  // A hash the tab bar can produce but the router cannot resolve is exactly that
  // defect, so assert the two sides agree statically. The behavioural proof lives
  // in integration/modern-shell-routing.spec.mjs.
  const shell = read('modern-shell.js');
  const app = read('app.js');
  const index = read('index.html');

  const hrefs = [...shell.matchAll(/<a href="#([a-z]+)"/g)].map(m => m[1]);
  ok(hrefs.length === 5, `expected 5 primary tabs in modern-shell.js, found ${hrefs.length}: ${JSON.stringify(hrefs)}`);

  const vm = app.match(/const views = \{([\s\S]*?)\};/);
  ok(vm, 'could not locate the `views` map in app.js');
  const routes = [...vm[1].matchAll(/([a-z]+)\s*:\s*\$\('#(view-[a-z-]+)'\)/g)]
    .reduce((acc, m) => { acc[m[1]] = m[2]; return acc; }, {});

  for (const href of hrefs) {
    ok(routes[href],
      `modern-shell.js renders a tab linking to "#${href}" but app.js's views map has no ` +
      `"${href}" route. navigate() resolves an unknown hash to home, so that tab would ` +
      'silently show the Today screen while highlighting itself.');
    ok(index.includes(`id="${routes[href]}"`),
      `app.js maps route "${href}" to #${routes[href]}, but index.html contains no such ` +
      'section. A section injected at runtime is too late: `views` is built at parse time.');
  }

  // Each tab must also carry the CANONICAL route name in data-nav, because that
  // is what app.js's own setActiveNav() matches on. A driver-facing label in
  // data-nav (the pre-24.0.8 shape used data-nav="evaluate") leaves the tab
  // unhighlighted on every navigation the adapter did not itself perform.
  const navAttrs = [...shell.matchAll(/<a href="#([a-z]+)" data-nav="([a-z]+)"/g)];
  eq(navAttrs.length, hrefs.length, 'every primary tab must declare data-nav');
  for (const [, href, nav] of navAttrs) {
    eq(nav, href, `tab "#${href}" declares data-nav="${nav}"; app.js setActiveNav() matches on the ` +
      'canonical route name, so these must be the same string');
  }
});

test('[CG-14] midwest-stack-config.json appTarget is at the current generation', () => {
  // Version-bump checklist item 15, which item 16 has claimed since v24.0.3 was
  // "machine-checked rather than remembered" — along with items 3-6, 11, 12 and
  // 14. It was NOT: nothing in this spec or verify-cloudflare-parity.mjs read
  // this field. The parity script checks only that the service worker CACHES the
  // file, which a stale appTarget passes happily.
  //
  // So it drifted exactly as before. It read `FreightLogic v24.0.0` at v24.0.3
  // (two releases behind, found by the read-only recon, fixed and added to the
  // checklist as item 15), and it read `FreightLogic v24.0.10` at 24.0.11 — the
  // same defect, in the same field, one release after being written down as
  // covered. A checklist item that is documented as enforced but is not is worse
  // than one that is merely remembered, because it stops anyone from looking.
  const app = appVersion();
  const m = read('midwest-stack-config.json').match(/"appTarget"\s*:\s*"FreightLogic v([0-9]+\.[0-9]+\.[0-9]+)"/);
  ok(m, 'could not read appTarget from midwest-stack-config.json');
  eq(m[1], app,
    `midwest-stack-config.json appTarget is v${m ? m[1] : '?'} but APP_VERSION is ${app}. ` +
    'Checklist item 15 — bump it with every release.');
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
