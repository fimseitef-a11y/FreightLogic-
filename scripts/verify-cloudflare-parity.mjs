#!/usr/bin/env node
/* FreightLogic Cloudflare parity verifier
 * No npm dependencies. Requires Node 18+ for global fetch.
 * Usage:
 *   node scripts/verify-cloudflare-parity.mjs https://freightlogic.pages.dev https://freightlogic-backup.fimseitef.workers.dev
 */

const pagesOrigin = (process.argv[2] || 'https://freightlogic.pages.dev').replace(/\/$/, '');
const workerOrigin = (process.argv[3] || 'https://freightlogic-backup.fimseitef.workers.dev').replace(/\/$/, '');

const EXPECTED = {
  serviceWorkerVersion: "23.5.1",
  manifestName: "FreightLogic v23.5.1",
  workerVersion: "10",
  overlayScript: "midwest-stack-authority.js?v=23.5.1"
};

async function fetchText(url) {
  const res = await fetch(url, { redirect: 'follow' });
  const text = await res.text();
  return { url, ok: res.ok, status: res.status, headers: res.headers, text };
}

async function fetchJson(url) {
  const res = await fetch(url, { redirect: 'follow' });
  let json = null;
  try { json = await res.json(); } catch {}
  return { url, ok: res.ok, status: res.status, headers: res.headers, json };
}

function assert(checks, name, pass, detail) {
  checks.push({ name, pass: !!pass, detail: detail || '' });
}

async function main() {
  const checks = [];

  const index = await fetchText(`${pagesOrigin}/`);
  assert(checks, 'Pages index loads', index.ok, `${index.status} ${index.url}`);
  assert(checks, 'Index references app.js v23.5.0', index.text.includes('app.js?v=23.5.0'));
  assert(checks, 'Index references voice-load.js v23.5.0', index.text.includes('voice-load.js?v=23.5.0'));
  assert(checks, 'Index references sw-bridge.js v23.5.0', index.text.includes('sw-bridge.js?v=23.5.0'));

  const sw = await fetchText(`${pagesOrigin}/service-worker.js?verify=${Date.now()}`);
  assert(checks, 'Service worker loads', sw.ok, `${sw.status}`);
  assert(checks, 'Service worker version 23.5.1', sw.text.includes("SW_VERSION = '23.5.1'"));
  assert(checks, 'Service worker caches Midwest overlay', sw.text.includes(EXPECTED.overlayScript));
  assert(checks, 'Service worker caches authority JSON', sw.text.includes('midwest-stack-config.json') && sw.text.includes('rate-overrides-2026-05.json'));

  const overlay = await fetchText(`${pagesOrigin}/midwest-stack-authority.js?v=23.5.1`);
  assert(checks, 'Midwest Stack overlay loads', overlay.ok, `${overlay.status}`);
  assert(checks, 'Overlay exposes FreightLogicMidwestStack', overlay.text.includes('window.FreightLogicMidwestStack'));

  const manifest = await fetchJson(`${pagesOrigin}/manifest.json?v=23.5.1`);
  assert(checks, 'Manifest loads', manifest.ok, `${manifest.status}`);
  assert(checks, 'Manifest name v23.5.1', manifest.json && manifest.json.name === EXPECTED.manifestName, manifest.json && manifest.json.name);

  const health = await fetchJson(`${workerOrigin}/health`);
  assert(checks, 'Worker /health loads', health.ok, `${health.status}`);
  assert(checks, 'Worker reports v10', health.json && health.json.ok === true && String(health.json.version) === EXPECTED.workerVersion, JSON.stringify(health.json));

  const adminReject = await fetchJson(`${workerOrigin}/admin/users`);
  assert(checks, 'Admin endpoint rejects without token', adminReject.status === 401 || adminReject.status === 429, `${adminReject.status}`);

  const failed = checks.filter(c => !c.pass);
  for (const c of checks) {
    console.log(`${c.pass ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? ' — ' + c.detail : ''}`);
  }
  if (failed.length) {
    console.error(`\n${failed.length} parity check(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll FreightLogic Cloudflare parity checks passed.');
}

main().catch(err => {
  console.error('Parity verifier failed:', err && err.message ? err.message : err);
  process.exit(1);
});
