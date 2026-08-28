#!/usr/bin/env node
// FreightLogic M7 — completion-release PREFLIGHT / certification runner.
// docs/COMPLETION_RELEASE_PLAN_2026-08-25.md, Milestone 7.
//
// A7 (Issue #119 Batch A): this script used to print
//   "AUTOMATED CERTIFICATION PASSED. Freeze the release after the operator
//    gates pass."
// on a fast run that had SKIPPED the entire Playwright suite, while the
// canonical certification state was HOLD with uncovered source defects. A
// skipped gate was scored as a pass, and the word "certification" was applied to
// a check set that could not establish it. Both are fixed here:
//
//   * The DEFAULT run is a RELEASE PREFLIGHT, never a certification.
//   * A skipped suite is SKIP/PENDING. It is neither a pass nor a failure, and
//     it can never contribute certification evidence.
//   * The canonical release state is read from docs/ and is authoritative. While
//     it says HOLD, this prints NOT CERTIFIABLE and never tells the operator to
//     freeze — no combination of green automated gates overrides it.
//   * Automated preflight, the full suite, live Cloudflare checks and physical
//     iPhone checks stay four visibly separate classes.
//
//   node scripts/m7-certify.mjs            # release preflight (fast, no browser)
//   node scripts/m7-certify.mjs --suite    # preflight + the full Playwright suite
//
// Exit 0 iff no gate FAILED. A NOT CERTIFIABLE verdict with no failed gate still
// exits 0 — it is a true statement about a clean preflight on a held release —
// so read the verdict line, not just the exit code.

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { execSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const R = p => readFileSync(path.join(ROOT, p), 'utf8');
const runSuite = process.argv.includes('--suite');

// Tri-state gates. SKIP is a first-class result: it is the honest record of a
// check that was not performed, and it is never silently promoted to PASS.
const PASS = 'PASS', FAIL = 'FAIL', SKIP = 'SKIP';
const checks = [];
const gate = (name, state, detail='') => checks.push({ name, state, detail });
const ok = (name, pass, detail='') => gate(name, pass ? PASS : FAIL, detail);

/* ---- 0. canonical release state — authoritative over every gate below ---- */
function readCanonicalReleaseState(){
  const dir = path.join(ROOT, 'docs');
  let files = [];
  try {
    files = readdirSync(dir)
      .filter(f => /^COMPLETION_RELEASE_CERTIFICATION_(STATE|ADDENDUM)_\d{4}-\d{2}-\d{2}\.md$/.test(f))
      // Sort by the DATE embedded in the filename, not the filename itself —
      // STATE_ and ADDENDUM_ have different prefixes, so lexical order is not
      // chronological order across the two kinds.
      .sort((a, b) => (a.match(/\d{4}-\d{2}-\d{2}/)||[''])[0].localeCompare((b.match(/\d{4}-\d{2}-\d{2}/)||[''])[0]));
  } catch { /* no docs dir */ }
  if (!files.length) return { held: true, source: null, status: 'no certification-state document found' };
  // ANY document still declaring HOLD holds the release. A newer document does
  // not silently clear an older unresolved one; it has to say so itself.
  const held = [];
  let latest = null;
  for (const f of files){
    const status = (readFileSync(path.join(dir, f), 'utf8').match(/^Status:\s*(.+)$/m) || [,''])[1].trim();
    latest = { file: f, status };
    if (/HOLD|NOT\s+CERTIFIED|BLOCKED/i.test(status)) held.push({ file: f, status });
  }
  return held.length
    ? { held: true, source: held[held.length-1].file, status: held[held.length-1].status }
    : { held: false, source: latest.file, status: latest.status };
}
const releaseState = readCanonicalReleaseState();

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
  // Bounded: that script's live half reaches deployed origins. It has its own
  // per-fetch timeout, and this is the belt-and-braces bound so a stalled
  // network can never hang the preflight itself.
  execSync('node scripts/verify-cloudflare-parity.mjs', { cwd: ROOT, stdio: 'pipe', timeout: 120000 });
  ok('verify-cloudflare-parity static CSP check', true);
} catch (e) {
  const out = String(e.stdout || '') + String(e.stderr || '');
  // The live half fails without network reach — that's the operator gate, not a defect.
  ok('verify-cloudflare-parity static CSP check', /CSP are byte-identical/.test(out) && out.includes('PASS'),
     'static passed; live half needs the deployed origins (operator gate)');
}

/* ---- 6. the full suite: run it, or record that it was NOT run ---- */
let suiteEvidence = null; // only set when the suite actually executed
if (runSuite){
  try {
    const out = execSync('node tests/run-all.mjs', { cwd: ROOT, encoding: 'utf8' });
    const m = out.match(/TOTAL:\s*(\d+) passed, (\d+) failed across (\d+) spec files/);
    const green = !!m && Number(m[2]) === 0;
    suiteEvidence = { green, detail: m ? `${m[1]} passed / ${m[2]} failed / ${m[3]} specs` : 'no TOTAL line' };
    ok('full Playwright suite green', green, suiteEvidence.detail);
  } catch (e) {
    suiteEvidence = { green: false, detail: 'suite exited non-zero' };
    ok('full Playwright suite green', false, suiteEvidence.detail);
  }
} else {
  gate('full Playwright suite', SKIP, 'NOT RUN — this preflight cannot claim suite evidence. Run `node scripts/m7-certify.mjs --suite`.');
}

/* ---------------- report ---------------- */
const counts = { PASS: 0, FAIL: 0, SKIP: 0 };
for (const c of checks) counts[c.state]++;
const mode = runSuite ? 'PREFLIGHT + FULL SUITE' : 'RELEASE PREFLIGHT (fast — suite not run)';

console.log(`\nFreightLogic M7 — ${mode}  (release v${appV})\n${'='.repeat(72)}`);
console.log(`  Canonical release state: ${releaseState.status || 'unknown'}`);
console.log(`  Source: ${releaseState.source ? 'docs/' + releaseState.source : '(none found)'}\n`);
for (const c of checks) console.log(`  ${c.state.padEnd(4)}  ${c.name}${c.detail ? '  — ' + c.detail : ''}`);
console.log(`${'-'.repeat(72)}\n  AUTOMATED GATES: ${counts.PASS} passed, ${counts.FAIL} failed, ${counts.SKIP} not run\n`);

console.log(`LIVE DEPLOYMENT GATES (need network reach to the deployed origins):`);
for (const [g, cmd] of [
  ['Live Cloudflare Pages + Worker parity', 'node scripts/verify-cloudflare-parity.mjs  (from a network reaching the deployed origins)'],
  ['Worker /health + unauthorized-admin denial', 'curl the deployed Worker /health and an admin endpoint without a token'],
  ['Live /evaluate + /extract authority smoke', 'non-sensitive fixture POST to the deployed Worker; confirm it projects, not recalculates'],
]) console.log(`  PENDING  ${g}\n           → ${cmd}`);

console.log(`\nPHYSICAL DEVICE GATES (need the operator's iPhone — see FIELD_TEST_CHECKLIST.md):`);
for (const [g, cmd] of [
  ['iPhone Safari one-handed decision journey', 'manual — load the app on iPhone Safari, evaluate a load one-handed'],
  ['Offline install / reload / update', 'manual — airplane mode: install PWA, reload, confirm update-on-reconnect'],
  ['GPS / background / permission-loss resilience', 'manual — start a trip, background the app, revoke location, confirm the session survives'],
  ['Production M5B intake durability check', 'manual — More → Opportunity Intake, save evidence, reload, export, re-import'],
]) console.log(`  PENDING  ${g}\n           → ${cmd}`);

/* ---- the verdict. Certification requires ALL of: canonical state clear,
       zero failed gates, and a suite that actually ran green. ---- */
const blockers = [];
if (releaseState.held) blockers.push(`canonical release state is HOLD (docs/${releaseState.source})`);
if (counts.FAIL) blockers.push(`${counts.FAIL} automated gate(s) FAILED`);
if (!suiteEvidence) blockers.push('the full suite was not run in this invocation (--suite)');
else if (!suiteEvidence.green) blockers.push('the full suite is not green');

console.log(`\n${'='.repeat(72)}`);
if (blockers.length){
  console.log(`  NOT CERTIFIABLE — this run does not certify the completion release.`);
  for (const b of blockers) console.log(`    • ${b}`);
  console.log(`\n  Do not freeze. ${counts.FAIL ? 'Fix the failed gates at the cause.' :
    'The gates this run performed are clean; the blockers above are what remain.'}`);
} else {
  console.log(`  AUTOMATED GATES GREEN and the canonical release state is clear.`);
  console.log(`  Remaining: the LIVE and PHYSICAL gates above. Freeze only after those pass`);
  console.log(`  and the operator records the release + rollback SHAs.`);
}
console.log(`${'='.repeat(72)}\n`);

// Exit code reports GATE FAILURE only. A held release with a clean preflight is
// not a script failure — the verdict line above is the certification statement.
process.exit(counts.FAIL ? 1 : 0);
