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
// Blocker 5: a historical HOLD must stay immutable EVIDENCE without becoming a
// permanent, unclearable state. The previous rule — any file that ever said
// HOLD holds the release forever — made certification impossible without
// editing history, which is exactly what must never happen.
//
// The rule is explicit supersession, not date ordering. Date-only ordering is
// not an authority: several STATE/ADDENDUM files can carry the same date, and
// "newest filename wins" would let an unrelated addendum silently clear a
// blocking state. A document supersedes another only by naming it:
//
//     Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-08-27.md
//
// A superseded file remains on disk as evidence and stops being current state.
// The release is held while ANY non-superseded document declares a hold.
// Missing, unreadable or unparseable state fails closed.
// A `Supersedes:` value is compared against a BARE BASENAME, so the reference has
// to be reduced to one. Every real document in `docs/` writes it the way prose
// wants it — `` `docs/NAME.md` `` — and every one of those references was
// therefore inert: the supersession silently did not register and the superseded
// document stayed "current". It cost nothing while every document held, which is
// exactly why it survived: the resolver still returned held=true, by a different
// route. The day one of them was meant to clear, six stale HOLDs would have held
// the release and the reported source would have been a document nobody had read
// in two weeks. Normalizing the REFERENCE keeps the historical files untouched,
// which blocker 5 requires; editing six documents to match a parser is the
// rewriting-history move this rule exists to forbid.
function supersededBasename(raw){
  const t = String(raw).trim().replace(/^[`'"]+|[`'"]+$/g, '').trim();
  const slash = t.lastIndexOf('/');
  return slash === -1 ? t : t.slice(slash + 1);
}

function readCanonicalReleaseState(){
  const dir = path.join(ROOT, 'docs');
  let files = [];
  try {
    files = readdirSync(dir)
      .filter(f => /^COMPLETION_RELEASE_CERTIFICATION_(STATE|ADDENDUM)_\d{4}-\d{2}-\d{2}\.md$/.test(f))
      .sort();
  } catch { /* no docs dir */ }
  if (!files.length) return { held: true, source: null, status: 'no certification-state document found' };

  const docs = [];
  const superseded = new Set();
  for (const f of files){
    let text;
    try { text = readFileSync(path.join(dir, f), 'utf8'); }
    catch { return { held: true, source: f, status: `certification-state document ${f} could not be read` }; }
    const status = (text.match(/^Status:\s*(.+)$/m) || [,''])[1].trim();
    if (!status) return { held: true, source: f, status: `certification-state document ${f} declares no Status:` };
    const sup = (text.match(/^Supersedes:\s*(.+)$/m) || [,''])[1].trim();
    for (const name of sup.split(',').map(supersededBasename).filter(Boolean)) superseded.add(name);
    docs.push({ file: f, status });
  }

  const current = docs.filter(d => !superseded.has(d.file));
  if (!current.length){
    // Everything claims to be superseded by something: there is no current
    // state at all. Fail closed rather than guess which one governs.
    return { held: true, source: null, status: 'every certification-state document is superseded — no current state' };
  }
  const holding = current.filter(d => /HOLD|NOT\s+CERTIFIED|BLOCKED/i.test(d.status));
  if (holding.length){
    return { held: true, source: holding[holding.length - 1].file, status: holding[holding.length - 1].status,
             currentCount: current.length, supersededCount: superseded.size };
  }
  return { held: false, source: current[current.length - 1].file, status: current[current.length - 1].status,
           currentCount: current.length, supersededCount: superseded.size };
}
const releaseState = readCanonicalReleaseState();

/* ---- 1. version-marker consistency (the CLAUDE.md release-bump contract) ---- */
let appV = (R('app.js').match(/APP_VERSION = '([0-9.]+)'/) || [])[1];
// Derived, never pinned: a hardcoded generation in this runner's prose is the exact drift
// class this repository has recorded against itself at 24.0.3, 24.0.10, 24.0.11 and 24.0.12.
const workerV = (R('cloud-backup-worker.js').match(/version:\s*'(\d+)'/) || [])[1];
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

/* ---- 5. static Cloudflare parity (genuinely no network half) ---- */
// This gate's name has always said "static". It was nonetheless invoking the
// verifier's LIVE half and then inspecting the failure text, which made an
// automated code gate depend on reaching the deployed origins — slow or
// unreachable, and a preflight that should take a second takes minutes or
// stalls. `--static-only` runs the local CSP-parity check alone; the live half
// stays where it belongs, in the LIVE DEPLOYMENT GATES section below.
try {
  execSync('node scripts/verify-cloudflare-parity.mjs --static-only', { cwd: ROOT, stdio: 'pipe', timeout: 60000 });
  ok('verify-cloudflare-parity static CSP check', true, 'live half is an operator gate, listed separately below');
} catch (e) {
  const out = String(e.stdout || '') + String(e.stderr || '');
  ok('verify-cloudflare-parity static CSP check', false, out.split('\n').filter(Boolean).slice(-2).join(' | '));
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

// These are PENDING *in this invocation* — a local run observes nothing live, and
// saying otherwise would be the inference this runner exists to refuse. They are
// no longer blocked, though: each is a GitHub workflow now, because GitHub-hosted
// runners can reach the deployed origins and this repository's agent proxies
// cannot. Where each has actually been observed is recorded in the canonical
// certification document, which is the only place a live PASS may be claimed.
console.log(`LIVE DEPLOYMENT GATES (not observable from this process — dispatch on GitHub, then record in the certification document):`);
for (const [g, cmd] of [
  ['Live Cloudflare Pages + Worker parity', 'Actions → Verify Live Parity → Run workflow on main (leave origins blank). Or locally, with network reach: node scripts/verify-cloudflare-parity.mjs'],
  ['Worker /health + unauthorized-admin denial', 'covered by Verify Live Parity above (it checks /health, the Worker version, and a tokenless /admin/users)'],
  ['Production service worker: install / reload / injection / precache / offline', 'Actions → Verify Production Service Worker → Run workflow on main. Or locally: node scripts/verify-production-sw.mjs  (needs Playwright + network reach)'],
  ['Live invite/claim contract (B7)', 'GitHub workflow — Verify Authenticated Worker (runs scripts/verify-live-invite-claim.mjs after every dispatched Worker deploy). OBSERVED PASS run 35049144080 @72ab81e against Worker v19; re-observe after any Worker redeploy. Do NOT run it twice inside one hour — /claim is 10/hr per IP and the second result reads UNOBSERVED, which is not a pass and not a failure'],
  ['Live /evaluate + /extract + backup/rotation authority smoke', 'Actions → Verify Authenticated Worker → Run workflow on main (seeds an expiring synthetic identity, cleans up). Or locally: FL_BACKUP_TOKEN=flk_... node scripts/verify-live-authority.mjs --paid   (omit --paid to skip OpenAI quota; exit 2 = UNOBSERVED, not a failure)'],
]) console.log(`  PENDING  ${g}\n           → ${cmd}`);

console.log(`\nPHYSICAL DEVICE GATES (need the operator's iPhone — see FIELD_TEST_CHECKLIST.md):`);
for (const [g, cmd] of [
  ['iPhone Safari one-handed decision journey', 'manual — load the app on iPhone Safari, evaluate a load one-handed'],
  ['Offline install / reload / update', 'manual — airplane mode: install PWA, reload, confirm update-on-reconnect'],
  ['GPS / background / permission-loss resilience', 'manual — start a trip, background the app, revoke location, confirm the session survives'],
  ['Production M5B intake durability check', 'manual — More → Opportunity Intake, save evidence, reload, export, re-import'],
  ['iOS 27 / Safari 27 regression pass (A11)', 'manual — on iOS 27+: F31 SVG chart, tab-bar icons, select zoom-on-focus, persisted storage granted, cloud-backup paused banner (FIELD_TEST_CHECKLIST.md A11)'],
  ['Zero-token driver onboarding (A12)', `manual — prerequisite SATISFIED: the invite/claim contract is deployed and live-observed (B7 PASS, run 35049144080). Run A12 against app ${appV} / Worker v${workerV} and record BOTH generations with the result. Owner sets admin access once under the PIN; invite by iMessage and by Mail; claim in Safari; then ADD TO HOME SCREEN and record whether the token is present or the install is a separate storage partition. If separate, walk the re-claim and confirm the owner still sees ONE driver with their backup count intact (FIELD_TEST_CHECKLIST.md A12)`],
  // A13 exists in FIELD_TEST_CHECKLIST.md as of v24.0.21 and was missing from
  // this list until now. That is not cosmetic: this runner is what a reader
  // consults to learn what the physical gate IS, and a runner that has never
  // heard of A13 cannot report it missing — the checklist says so in its own
  // words.
  //
  // The prerequisite is stated as a CAPABILITY rather than a version number,
  // and that is the honest form as well as the one M7-10 permits. What actually
  // blocks the row is the deployed Worker not exposing POST /extract-image; the
  // generation is only a proxy for that, and writing the proxy as a literal is
  // the pinned-generation drift this file already refuses in M7-09/M7-10 — it
  // fired on this very line when it was first written that way.
  ['Screenshot intake on a real iPhone (A13)', `manual — requires a DEPLOYED Worker exposing POST /extract-image; source carries v${workerV}, so confirm /health reports that generation or later before starting. Below it every attempt fails and the row is BLOCKED, not FAIL. Photos/Files picker is the guaranteed path; record the camera/screenshot control and clipboard-image outcomes separately rather than assuming either delivers a file in an INSTALLED PWA. A posting with no stated deadhead must stay blank/UNKNOWN and prompt for the figure; an explicit 0 must survive as a known zero; a manual correction must override the model; and the result must be the ordinary canonical evaluator, not an AI-authored grade/RPM/bid (FIELD_TEST_CHECKLIST.md A13)`],
  // A14 (v24.0.34): stated as a capability, like A13, not as a pinned generation.
  ['Shortcuts relay + Web Push on a real iPhone (A14)', `manual — requires a DEPLOYED Worker exposing /push/* and /relay; source carries v${workerV}, so confirm /health reports that generation or later, else the row is BLOCKED, not FAIL. From the INSTALLED Home Screen app: permission prompt only at the Turn on tap; a test push arrives and its tap opens the installed app, not Safari; a relayed expense opens prefilled and saves nothing until Save; a direct Open URLs trip link lands in Safari behind the warning and saves nothing into the installed app; a relayed evaluate with no deadhead stays UNKNOWN; an out-of-range value is dropped and named, not clamped; replacing the Shortcut key makes the old one 401 (FIELD_TEST_CHECKLIST.md A14)`],
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
