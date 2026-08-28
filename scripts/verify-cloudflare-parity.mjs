#!/usr/bin/env node
/* FreightLogic Cloudflare parity verifier
 * No npm dependencies. Requires Node 18+ for global fetch.
 * Usage:
 *   node scripts/verify-cloudflare-parity.mjs https://freightlogic.pages.dev https://freightlogic-backup.fimseitef.workers.dev
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

const pagesOrigin = (process.argv[2] || 'https://freightlogic.pages.dev').replace(/\/$/, '');
const workerOrigin = (process.argv[3] || 'https://freightlogic-backup.fimseitef.workers.dev').replace(/\/$/, '');

const EXPECTED = {
  serviceWorkerVersion: "24.0.2",
  manifestName: "FreightLogic v24.0.2",
  workerVersion: "13",
  overlayScript: "midwest-stack-authority.js?v=24.0.2"
};

// Every live fetch is bounded. This script is a RELEASE GATE, and a gate that
// can hang indefinitely on an unreachable origin is not a gate — it just stops
// the pipeline with no verdict. 15 seconds is far longer than any of these
// static assets or the Worker's /health should ever take.
const LIVE_FETCH_TIMEOUT_MS = 15000;
function liveFetch(url) {
  return fetch(url, {
    redirect: 'follow',
    signal: AbortSignal.timeout ? AbortSignal.timeout(LIVE_FETCH_TIMEOUT_MS) : undefined,
  });
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

function report(checks) {
  for (const c of checks) {
    console.log(`${c.pass ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? ' — ' + c.detail : ''}`);
  }
  const failed = checks.filter(c => !c.pass);
  if (failed.length) {
    console.error(`\n${failed.length} parity check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll FreightLogic Cloudflare parity checks passed.');
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
  const index = await fetchText(`${pagesOrigin}/`);
  assert(checks, 'Pages index loads', index.ok, `${index.status} ${index.url}`);
  assert(checks, 'Index references app.js v24.0.2', index.text.includes('app.js?v=24.0.2'));
  assert(checks, 'Index references voice-load.js v24.0.2', index.text.includes('voice-load.js?v=24.0.2'));
  assert(checks, 'Index references sw-bridge.js v24.0.2', index.text.includes('sw-bridge.js?v=24.0.2'));

  const sw = await fetchText(`${pagesOrigin}/service-worker.js?verify=${Date.now()}`);
  assert(checks, 'Service worker loads', sw.ok, `${sw.status}`);
  assert(checks, 'Service worker version 24.0.2', sw.text.includes("SW_VERSION = '24.0.2'"));
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

  const overlay = await fetchText(`${pagesOrigin}/midwest-stack-authority.js?v=24.0.2`);
  assert(checks, 'Midwest Stack overlay loads', overlay.ok, `${overlay.status}`);
  assert(checks, 'Overlay exposes FreightLogicMidwestStack', overlay.text.includes('window.FreightLogicMidwestStack'));

  const manifest = await fetchJson(`${pagesOrigin}/manifest.json?v=24.0.2`);
  assert(checks, 'Manifest loads', manifest.ok, `${manifest.status}`);
  assert(checks, 'Manifest name v24.0.2', manifest.json && manifest.json.name === EXPECTED.manifestName, manifest.json && manifest.json.name);

  const health = await fetchJson(`${workerOrigin}/health`);
  assert(checks, 'Worker /health loads', health.ok, `${health.status}`);
  assert(checks, 'Worker reports v13', health.json && health.json.ok === true && String(health.json.version) === EXPECTED.workerVersion, JSON.stringify(health.json));

  const adminReject = await fetchJson(`${workerOrigin}/admin/users`);
  assert(checks, 'Admin endpoint rejects without token', adminReject.status === 401, `${adminReject.status} (expected 401; got 429 means IP is rate-limited — run from a fresh IP or reset the rl: KV keys)`);
}

async function main() {
  const checks = [];

  checkLocalCspParity(checks);

  try {
    await runLiveChecks(checks);
  } catch (err) {
    assert(checks, 'live deployment checks reached the deployed origins', false,
      `${err && err.message ? err.message : String(err)} — run this from a network that can reach ${pagesOrigin} and ${workerOrigin}`);
  }

  report(checks);
}

main().catch(err => {
  console.error('Parity verifier failed:', err && err.message ? err.message : err);
  process.exit(1);
});
