#!/usr/bin/env node
/* FreightLogic Cloudflare parity verifier
 * No npm dependencies. Requires Node 18+ for global fetch.
 * Usage:
 *   node scripts/verify-cloudflare-parity.mjs https://freightlogic-v2.fimseitef.workers.dev https://freightlogic-backup.fimseitef.workers.dev
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
// Shared with tests/unit/deploy-asset-coverage.spec.mjs so the release gate and
// its regression cannot disagree about what the app declares or what the deploy
// excludes — two lists that disagreed is the defect being closed here.
import { declaredRuntimeAssets, assetsIgnoreMatcher, expectsNonHtml } from './lib/deploy-assets.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

// `--static-only` runs the local, no-network half alone. The live half needs to
// reach the deployed origins, which is an OPERATOR gate — it belongs in a
// deliberate deployment check, not inside an automated test suite, where an
// unreachable or slow origin turns a code gate into a network gate.
const STATIC_ONLY = process.argv.includes('--static-only');
const positional = process.argv.slice(2).filter(a => !a.startsWith('--'));
// The APP origin (not a Pages origin): `wrangler.jsonc` deploys this repo as a
// Cloudflare Worker named `freightlogic-v2` with an `assets` block, so the app
// is served from `<name>.<subdomain>.workers.dev`. Verified against the wrong
// hostname, every live check below is meaningless — which is why this default
// and this variable's name both changed with the Worker v14 origin repair.
const appOrigin = (positional[0] || 'https://freightlogic-v2.fimseitef.workers.dev').replace(/\/$/, '');
const workerOrigin = (positional[1] || 'https://freightlogic-backup.fimseitef.workers.dev').replace(/\/$/, '');

const EXPECTED = {
  serviceWorkerVersion: "24.0.32",
  manifestName: "FreightLogic v24.0.32",
  workerVersion: "23",
  overlayScript: "midwest-stack-authority.js?v=24.0.32"
};

// Every live fetch is bounded. This script is a RELEASE GATE, and a gate that
// can hang indefinitely on an unreachable origin is not a gate — it just stops
// the pipeline with no verdict. 15 seconds is far longer than any of these
// static assets or the Worker's /health should ever take.
const LIVE_FETCH_TIMEOUT_MS = 15000;
async function liveFetch(url) {
  reachability.attempted = true;
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout ? AbortSignal.timeout(LIVE_FETCH_TIMEOUT_MS) : undefined,
    });
    // Any HTTP response at all — including a 404 or a 500 — proves the origin
    // was reached. Only a transport failure is evidence of unreachability.
    noteResponse();
    return res;
  } catch (err) {
    noteTransportError();
    throw err;
  }
}

async function fetchText(url) {
  const res = await liveFetch(url);
  const text = await res.text();
  return { url, ok: res.ok, status: res.status, headers: res.headers, text };
}

async function fetchJson(url) {
  const res = await liveFetch(url);
  let json = null;
  try { json = await res.json(); } catch {}
  return { url, ok: res.ok, status: res.status, headers: res.headers, json };
}

function assert(checks, name, pass, detail) {
  checks.push({ name, pass: !!pass, detail: detail || '' });
}

/** Did we actually reach the deployed origins this run?
 *
 *  "Could not reach production" and "production is wrong" are different facts,
 *  and conflating them is how an unreachable network gets recorded as a parity
 *  failure — or, worse, how a parity claim gets made on no evidence at all. The
 *  verifier therefore reports three outcomes, not two:
 *
 *    PASS       exit 0  — live evidence observed, everything agreed
 *    FAILURE    exit 1  — real evidence of a mismatch, or a static check failed
 *    UNOBSERVED exit 2  — the origins were not reachable; NO parity claim either way
 *
 *  Exit 2 is still non-zero, so every existing caller (the deploy workflow, the
 *  deploy script, m7-certify) keeps failing closed exactly as before — this
 *  only lets a caller that cares tell the two apart. `--static-only` can never
 *  be UNOBSERVED: it deliberately never attempts the live half. */
const reachability = { attempted: false, anyResponse: false, transportErrors: 0 };
function noteTransportError(){ reachability.transportErrors++; }
function noteResponse(){ reachability.anyResponse = true; }

/** Amendment 5: index.html's <meta http-equiv="Content-Security-Policy"> and
 *  _headers' Content-Security-Policy line must stay byte-identical — a
 *  real, pre-existing drift between them (missing Google Fonts origins in
 *  _headers, meaning the LIVE site had effectively been blocking its own
 *  fonts, since Cloudflare Pages serves _headers as the real HTTP response
 *  independently of the meta tag) was found and fixed while adding this
 *  check (v23.9 Phase 6, X-10). Purely local/static — no network needed —
 *  so it runs even when the live-fetch checks below can't reach anything. */
function checkLocalCspParity(checks) {
  try {
    const indexHtml = readFileSync(path.join(REPO_ROOT, 'index.html'), 'utf8');
    const headersFile = readFileSync(path.join(REPO_ROOT, '_headers'), 'utf8');
    const metaMatch = indexHtml.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/);
    const headerMatch = headersFile.match(/^\s*Content-Security-Policy:\s*(.+)$/m);
    if (!metaMatch) { assert(checks, 'index.html has a CSP meta tag', false, 'no <meta http-equiv="Content-Security-Policy"> found'); return; }
    if (!headerMatch) { assert(checks, '_headers has a CSP line', false, 'no Content-Security-Policy: line found'); return; }
    const metaCsp = metaMatch[1].trim();
    const headerCsp = headerMatch[1].trim();
    assert(checks, 'index.html and _headers CSP are byte-identical', metaCsp === headerCsp,
      metaCsp === headerCsp ? '' : `index.html: ${metaCsp}\n  _headers:   ${headerCsp}`);
  } catch (err) {
    assert(checks, 'local CSP parity check ran', false, err && err.message ? err.message : String(err));
  }
}

/** An asset excluded by `.assetsignore` cannot be deployed at all, so naming the
 *  offending pattern turns an unexplained production 404 into a one-line
 *  diagnosis. Purely local, so it runs under `--static-only` too — this is the
 *  half of the 2026-09-13 defect that was visible without a network at all. */
function checkLocalAssetExclusions(checks) {
  try {
    const { assets, problems } = declaredRuntimeAssets();
    // A declaration source this module could not parse is reported, never
    // silently dropped: an empty inventory would otherwise read as "nothing is
    // broken", which is the shape of the defect being closed.
    for (const problem of problems) assert(checks, 'runtime asset declarations are parseable', false, problem);
    const isIgnored = assetsIgnoreMatcher();
    const blocked = [];
    for (const [p, { requesters }] of assets) {
      const { excluded, by } = isIgnored(p);
      if (excluded) blocked.push(`${p} (pattern "${by}"; requested by ${[...requesters].join(', ')})`);
    }
    assert(checks, `No runtime asset is excluded from deployment by .assetsignore (${assets.size} declared)`,
      blocked.length === 0, blocked.join('; '));
  } catch (err) {
    assert(checks, 'local deploy-exclusion check ran', false, err && err.message ? err.message : String(err));
  }
}

const EXIT = { PASS: 0, FAILURE: 1, UNOBSERVED: 2 };

/** The live half was attempted and NOTHING came back. Not "some checks failed" —
 *  no HTTP response of any kind was received, so there is no live evidence to
 *  reason about in either direction. */
function liveWasUnobserved(){
  return reachability.attempted && !reachability.anyResponse && reachability.transportErrors > 0;
}

function report(checks) {
  for (const c of checks) {
    console.log(`${c.pass ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? ' — ' + c.detail : ''}`);
  }
  const failed = checks.filter(c => !c.pass);
  const unobserved = liveWasUnobserved();

  // A static failure is real evidence of a defect regardless of the network, so
  // it outranks unreachability: reporting UNOBSERVED while index.html and
  // _headers genuinely disagree would hide a source defect behind a network
  // excuse.
  const staticFailed = failed.some(c => !/^(Pages index|Index references|Service worker|Midwest Stack|Overlay|SW bridge|Modern shell|Manifest|Worker|Admin endpoint|All \d+ declared|No runtime asset is served|live deployment checks)/.test(c.name));

  if (unobserved && !staticFailed) {
    console.log(`\nVERDICT: UNOBSERVED — the deployed origins were not reachable from this runner ` +
      `(${reachability.transportErrors} transport error(s), zero HTTP responses). No parity claim is ` +
      `made in either direction. Re-run from a network that can reach ${appOrigin} and ${workerOrigin}.`);
    process.exit(EXIT.UNOBSERVED);
  }
  if (failed.length) {
    console.error(`\n${failed.length} parity check(s) failed.`);
    console.error('VERDICT: FAILURE');
    process.exit(EXIT.FAILURE);
  }
  console.log('\nAll FreightLogic Cloudflare parity checks passed.');
  console.log('VERDICT: PASS');
}

/** The live half needs to reach the deployed Pages origin and Worker. When it
 *  can't (no network, DNS blocked, running from CI), a thrown fetch error used
 *  to escape main() and hit the top-level catch, which printed only
 *  "Parity verifier failed: fetch failed" and exited — discarding the local
 *  CSP-parity result that had already been collected, despite that check being
 *  purely static and documented as running "even when the live-fetch checks
 *  below can't reach anything." Now a network failure is recorded as one failed
 *  check and every collected result is still reported. */
async function runLiveChecks(checks) {
  const index = await fetchText(`${appOrigin}/`);
  assert(checks, 'Pages index loads', index.ok, `${index.status} ${index.url}`);
  assert(checks, 'Index references app.js v24.0.32', index.text.includes('app.js?v=24.0.32'));
  // Voice Load was removed completely by operator decision (Issue #230,
  // v24.0.21). The positive reference assertion is replaced by its absence:
  // a reintroduced tag or a stale deployed index must fail, not pass quietly.
  assert(checks, 'Index does not reference voice-load.js (removed, Issue #230)', !index.text.includes('voice-load.js'));
  assert(checks, 'Index references sw-bridge.js v24.0.32', index.text.includes('sw-bridge.js?v=24.0.32'));

  const sw = await fetchText(`${appOrigin}/service-worker.js?verify=${Date.now()}`);
  assert(checks, 'Service worker loads', sw.ok, `${sw.status}`);
  assert(checks, 'Service worker version 24.0.32', sw.text.includes("SW_VERSION = '24.0.32'"));
  assert(checks, 'Service worker caches Midwest overlay', sw.text.includes(EXPECTED.overlayScript));
  // X-08/X-10 (v23.9, Amendment 4): the install-blocking `critical` array — not
  // just the broader, non-blocking CORE list — must include both files, or a
  // first offline install can complete without them cached.
  {
    const criticalMatch = sw.text.match(/const critical = \[([^\]]*)\]/);
    const criticalContents = criticalMatch ? criticalMatch[1] : '';
    assert(checks, 'SW critical shell includes midwest-stack-authority.js', criticalContents.includes('midwest-stack-authority.js'), criticalMatch ? '' : 'could not find `const critical = [...]` in service-worker.js');
    assert(checks, 'SW critical shell includes vendor/xlsx.full.min.js', criticalContents.includes('vendor/xlsx.full.min.js'), criticalMatch ? '' : 'could not find `const critical = [...]` in service-worker.js');
  }
  // v23.8.3: rate-overrides-*.json was deleted — never read by any code path; the
  // July bands now live in midwest-stack-authority.js. Assert it stays gone.
  assert(checks, 'Service worker caches authority JSON', sw.text.includes('midwest-stack-config.json'));
  assert(checks, 'Service worker no longer precaches removed rate-overrides JSON', !sw.text.includes('rate-overrides'));

  const overlay = await fetchText(`${appOrigin}/midwest-stack-authority.js?v=24.0.32`);
  assert(checks, 'Midwest Stack overlay loads', overlay.ok, `${overlay.status}`);
  assert(checks, 'Overlay exposes FreightLogicMidwestStack', overlay.text.includes('window.FreightLogicMidwestStack'));

  // Added in v24.0.14 (provenance, not a generation marker -- successive blanket
  // release bumps had rewritten this number to each new generation in turn): the
  // structural navigation adapter is a release-bound asset and was
  // not covered here. It is requested by sw-bridge.js rather than index.html, so
  // the index-side `?v=` assertions above cannot see it — a stale import string
  // would ship an old tab bar with every other marker reporting green.
  const bridge = await fetchText(`${appOrigin}/sw-bridge.js?v=24.0.32`);
  assert(checks, 'SW bridge loads', bridge.ok, `${bridge.status}`);
  assert(checks, 'SW bridge imports modern-shell.js v24.0.32', bridge.text.includes("modern-shell.js?v=24.0.32"));

  const shell = await fetchText(`${appOrigin}/modern-shell.js?v=24.0.32`);
  assert(checks, 'Modern shell adapter loads', shell.ok, `${shell.status}`);
  assert(checks, 'Modern shell exposes FreightLogicModernShell', shell.text.includes('window.FreightLogicModernShell'));
  assert(checks, 'Service worker precaches modern-shell.js v24.0.32', sw.text.includes('modern-shell.js?v=24.0.32'));

  const manifest = await fetchJson(`${appOrigin}/manifest.json?v=24.0.32`);
  assert(checks, 'Manifest loads', manifest.ok, `${manifest.status}`);
  assert(checks, 'Manifest name v24.0.32', manifest.json && manifest.json.name === EXPECTED.manifestName, manifest.json && manifest.json.name);

  const health = await fetchJson(`${workerOrigin}/health`);
  assert(checks, 'Worker /health loads', health.ok, `${health.status}`);
  assert(checks, `Worker reports v${EXPECTED.workerVersion}`, health.json && health.json.ok === true && String(health.json.version) === EXPECTED.workerVersion, JSON.stringify(health.json));

  const adminReject = await fetchJson(`${workerOrigin}/admin/users`);
  assert(checks, 'Admin endpoint rejects without token', adminReject.status === 401, `${adminReject.status} (expected 401; got 429 means IP is rate-limited — run from a fresh IP or reset the rl: KV keys)`);

  await runAssetCoverageChecks(checks);
}

/** Fetch EVERY declared runtime asset, not a curated subset.
 *
 *  The named checks above are deliberately kept — they assert CONTENT (version
 *  strings, exposed globals, precache entries), which a mere 200 does not. This
 *  sweep asserts DELIVERY, which is the axis that failed: `admin-driver-ui.js`
 *  404'd in production with every content check green, because no check fetched
 *  it at all. An asset miss here is a parity FAILURE, never an optional skip. */
async function runAssetCoverageChecks(checks) {
  const { assets } = declaredRuntimeAssets();

  // Bounded concurrency so a two-dozen-asset sweep does not serialize into
  // minutes, while staying well clear of anything a rate limiter would notice.
  const entries = [...assets.entries()];
  const results = new Map();
  const CONCURRENCY = 6;
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, entries.length) }, async () => {
    while (cursor < entries.length) {
      const [p, meta] = entries[cursor++];
      try {
        const res = await liveFetch(`${appOrigin}/${meta.ref}`);
        // Body is drained so the socket is released; content is not inspected
        // here beyond its type — the named checks above own content assertions.
        await res.arrayBuffer().catch(() => {});
        results.set(p, { status: res.status, ok: res.ok, type: res.headers.get('content-type') || '', meta });
      } catch (err) {
        results.set(p, { status: 0, ok: false, type: '', error: err && err.message ? err.message : String(err), meta });
      }
    }
  }));

  const missing = [];
  const htmlInsteadOfAsset = [];
  for (const [p, r] of results) {
    const requesters = [...r.meta.requesters].join(', ');
    if (!r.ok) {
      missing.push(`${p} -> ${r.error ? r.error : 'HTTP ' + r.status} (requested by ${requesters})`);
      continue;
    }
    // A 200 carrying text/html for a .js request is the SPA-fallback failure
    // mode: the browser refuses to execute it, with no 404 and no console
    // error, so the script silently vanishes. That is a delivery failure that
    // looks exactly like success to a status-code-only check.
    if (expectsNonHtml(p) && /text\/html/i.test(r.type)) {
      htmlInsteadOfAsset.push(`${p} -> HTTP 200 but Content-Type: ${r.type} (requested by ${requesters})`);
    }
  }

  assert(checks, `All ${results.size} declared runtime assets load from the app origin`,
    missing.length === 0, missing.join('; '));
  assert(checks, 'No runtime asset is served as HTML (SPA-fallback masking a miss)',
    htmlInsteadOfAsset.length === 0, htmlInsteadOfAsset.join('; '));
}

/** Issue #228, item 1 — the live half of the asset boundary.
 *
 *  `checkLocalAssetExclusions()` above proves no RUNTIME asset is withheld. This
 *  proves the opposite direction against the real origin: that repository-only
 *  material is genuinely not public. Those two are not the same check and
 *  neither implies the other — `.assetsignore` being correct in the repository
 *  says nothing about what the deployed origin is actually serving, which is the
 *  whole lesson of the 2026-09-13 defect where a curated subset passed 24/24
 *  while an undeclared asset 404'd.
 *
 *  It exists because a STATIC assertion could not have caught the reported
 *  defect either: `AUDIT_REPORT.md` and `FIELD_TEST_CHECKLIST.md` were observed
 *  at HTTP 200 on the app origin by external verification, and nothing in this
 *  repository would have noticed. `wrangler.jsonc` publishes
 *  `assets.directory: "."`, so the repository root IS the document root and an
 *  exclusion that silently stops matching re-exposes these immediately.
 *
 *  Non-public means 404 or 403. A 200 is the defect. Anything else (a 500, a
 *  redirect that resolves to a body) is reported rather than assumed benign,
 *  because "not obviously served" is not the same fact as "withheld". */
const MUST_NOT_BE_PUBLIC = [
  'AGENTS.md',
  'AUDIT_REPORT.md',
  'CLAUDE.md',
  'FIELD_TEST_CHECKLIST.md',
  'RECON_24_0_2.md',
  'UI_BRIEF_V24.5.md',
  'FreightLogic_UI_Reference.html',
  'cloud-backup-worker.js',
  'wrangler.jsonc',
  '.assetsignore',
  '.agents/LANES.md',
  '.agents/STATUS.md',
  '.claude/CLAUDE.md',
  '.github/workflows/deploy-backup-worker.yml',
  'docs/BACKUP_CONTRACT.md',
  'schemas/broker-memory.schema.json',
  'scripts/verify-cloudflare-parity.mjs',
  'scripts/lib/deploy-assets.mjs',
  'tests/run-all.mjs',
  'tests/lib/harness.mjs',
];

async function runWithheldPathChecks(checks) {
  const served = [];
  const unexpected = [];
  const CONCURRENCY = 6;
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, MUST_NOT_BE_PUBLIC.length) }, async () => {
    while (cursor < MUST_NOT_BE_PUBLIC.length) {
      const rel = MUST_NOT_BE_PUBLIC[cursor++];
      try {
        const res = await liveFetch(`${appOrigin}/${rel}`);
        const body = await res.text().catch(() => '');
        if (res.status === 404 || res.status === 403) continue;
        if (res.ok) {
          // Name the evidence, not just the status: a short prefix of the body
          // is what distinguishes "the document is really being served" from an
          // origin that answers 200 with an SPA shell for every unknown path.
          served.push(`${rel} -> HTTP ${res.status} (${body.length} bytes) "${body.slice(0, 60).replace(/\s+/g, ' ')}"`);
        } else {
          unexpected.push(`${rel} -> HTTP ${res.status}`);
        }
      } catch (err) {
        unexpected.push(`${rel} -> ${err && err.message ? err.message : String(err)}`);
      }
    }
  }));

  assert(checks, `No repository-only path is served publicly (${MUST_NOT_BE_PUBLIC.length} checked, Issue #228)`,
    served.length === 0, served.join('; '));
  // Separate check on purpose: a transport error or a 500 is not proof of
  // withholding and must not be counted as one, but it is also not the reported
  // defect. Keeping them apart stops an outage reading as a security pass.
  assert(checks, 'Every withheld path answered with a definite status', unexpected.length === 0, unexpected.join('; '));
}

async function main() {
  const checks = [];

  checkLocalCspParity(checks);
  checkLocalAssetExclusions(checks);

  if (STATIC_ONLY){
    console.log('(--static-only: the live deployment half was not run — it is an operator gate)');
    report(checks);
    return;
  }

  try {
    await runLiveChecks(checks);
    await runWithheldPathChecks(checks);
  } catch (err) {
    assert(checks, 'live deployment checks reached the deployed origins', false,
      `${err && err.message ? err.message : String(err)} — run this from a network that can reach ${appOrigin} and ${workerOrigin}`);
  }

  report(checks);
}

main().catch(err => {
  console.error('Parity verifier failed:', err && err.message ? err.message : err);
  process.exit(1);
});
