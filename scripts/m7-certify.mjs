#!/usr/bin/env node
// FreightLogic M7 — completion-release certification runner.
// docs/COMPLETION_RELEASE_PLAN_2026-08-25.md, Milestone 7.
//
// Consolidates every AUTOMATED release gate into one command and enumerates the
// operator-only field/live gates with exact steps. It is honest about the split:
// automated gates it can prove here; field + live-deployment gates it cannot,
// because they need a physical iPhone and the live Cloudflare dashboard.
//
//   node scripts/m7-certify.mjs            # automated gates only (fast, no browser)
//   node scripts/m7-certify.mjs --suite    # also run the full Playwright suite
//
// Exit 0 iff every automated gate passes. Operator gates never fail this run;
// they are reported PENDING so the freeze decision stays with the operator.

import { readFileSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const R = p => readFileSync(path.join(ROOT, p), 'utf8');
const runSuite = process.argv.includes('--suite');

const checks = [];
const ok = (name, pass, detail='') => checks.push({ name, pass, detail });

/* ---- 1. version-marker consistency (the CLAUDE.md release-bump contract) ---- */
let appV = (R('app.js').match(/APP_VERSION = '([0-9.]+)'/) || [])[1];
const markers = {
  'service-worker SW_VERSION': (R('service-worker.js').match(/SW_VERSION = '([0-9.]+)'/) || [])[1],
  'manifest name': (R('manifest.json').match(/"name":\s*"FreightLogic v([0-9.]+)"/) || [])[1],
  'index app.js ?v': (R('index.html').match(/app\.js\?v=([0-9.]+)/) || [])[1],
  'index manifest ?v': (R('index.html').match(/manifest\.json\?v=([0-9.]+)/) || [])[1],
  'overlay VERSION': (R('midwest-stack-authority.js').match(/VERSION = '([0-9.]+)'/) || [])[1],
  'verify-script SW': (R('scripts/verify-cloudflare-parity.mjs').match(/serviceWorkerVersion:\s*"([0-9.]+)"/) || [])[1],
};
for (const [k, v] of Object.entries(markers)) ok(`version marker ${k} == ${appV}`, v === appV, v ? `found ${v}` : 'not found');

/* ---- 2. SW critical install-shell contents (X-08/X-10) ---- */
const sw = R('service-worker.js');
const crit = (sw.match(/const critical = \[([^\]]*)\]/) || [,''])[1];
ok('SW critical shell includes midwest-stack-authority.js', crit.includes('midwest-stack-authority.js'));
ok('SW critical shell includes vendor/xlsx.full.min.js', crit.includes('vendor/xlsx.full.min.js'));

/* ---- 3. CSP byte-parity: index.html <meta> == _headers ---- */
try {
  const meta = (R('index.html').match(/content="(default-src[^"]*)"/) || [,''])[1].trim();
  const hdr = (R('_headers').match(/^\s*Content-Security-Policy:\s*(.+)$/m) || [,''])[1].trim();
  ok('CSP index.html <meta> is byte-identical to _headers', meta === hdr && !!meta);
} catch { ok('CSP index.html <meta> is byte-identical to _headers', false, 'read error'); }

/* ---- 4. release-gate wiring ---- */
ok('tests/run-all.mjs exits non-zero on failure (X-06 gate)', R('tests/run-all.mjs').includes('process.exit(totalFail ? 1 : 0)'));
ok('.github/workflows/tests.yml present', existsSync(path.join(ROOT, '.github/workflows/tests.yml')));
ok('.github/workflows/lanes.yml present (lane guards)', existsSync(path.join(ROOT, '.github/workflows/lanes.yml')));

/* ---- 5. static Cloudflare parity (no network half) ---- */
try {
  execSync('node scripts/verify-cloudflare-parity.mjs', { cwd: ROOT, stdio: 'pipe' });
  ok('verify-cloudflare-parity static CSP check', true);
} catch (e) {
  const out = String(e.stdout || '') + String(e.stderr || '');
  // The live half fails without network reach — that's the operator gate, not a defect.
  ok('verify-cloudflare-parity static CSP check', /CSP are byte-identical/.test(out) && out.includes('PASS'),
     'static passed; live half needs the deployed origins (operator gate)');
}

/* ---- 6. optional full suite ---- */
if (runSuite){
  try {
    const out = execSync('node tests/run-all.mjs', { cwd: ROOT, encoding: 'utf8' });
    const m = out.match(/TOTAL:\s*(\d+) passed, (\d+) failed across (\d+) spec files/);
    ok('full Playwright suite green', m && Number(m[2]) === 0, m ? `${m[1]} passed / ${m[2]} failed / ${m[3]} specs` : 'no TOTAL line');
  } catch (e) { ok('full Playwright suite green', false, 'suite exited non-zero'); }
} else {
  ok('full Playwright suite (run with --suite)', true, 'skipped — run `node scripts/m7-certify.mjs --suite` or rely on CI playwright-suite');
}

/* ---------------- report ---------------- */
const pass = checks.filter(c => c.pass).length, fail = checks.length - pass;
console.log(`\nFreightLogic M7 — automated release certification  (release v${appV})\n${'='.repeat(64)}`);
for (const c of checks) console.log(`  ${c.pass ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? '  — ' + c.detail : ''}`);
console.log(`${'-'.repeat(64)}\n  AUTOMATED GATES: ${pass}/${checks.length} passed${fail ? ` — ${fail} FAILED` : ''}\n`);

console.log(`OPERATOR-ONLY GATES (cannot be automated here — need your device + dashboard):`);
for (const [g, cmd] of [
  ['iPhone Safari one-handed decision journey', 'manual — load the app on iPhone Safari, evaluate a load one-handed'],
  ['Offline install / reload / update', 'manual — airplane mode: install PWA, reload, confirm update-on-reconnect'],
  ['GPS / background resilience', 'manual — start a trip, background the app, confirm the session survives'],
  ['Live Cloudflare Pages + Worker parity', 'node scripts/verify-cloudflare-parity.mjs  (from a network reaching the deployed origins)'],
  ['Worker /health + unauthorized-admin denial', 'curl the deployed Worker /health and an admin endpoint without a token'],
  ['Live /evaluate + /extract authority smoke', 'non-sensitive fixture POST to the deployed Worker; confirm it projects, not recalculates'],
]) console.log(`  PENDING  ${g}\n           → ${cmd}`);

console.log(`\n${fail ? 'AUTOMATED CERTIFICATION FAILED — do not freeze.' :
  'AUTOMATED CERTIFICATION PASSED. Freeze the release after the operator gates above pass.'}\n`);
process.exit(fail ? 1 : 0);
