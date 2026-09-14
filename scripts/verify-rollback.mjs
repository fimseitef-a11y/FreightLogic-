#!/usr/bin/env node
/**
 * FreightLogic — rollback / fix-forward evidence generator (completion gate B5).
 *
 * Read-only by design: no checkout, revert, push, deploy, secret read or network
 * request. The gate identifies the current runtime candidate, identifies the
 * immediately previous app generation, proves whether rolling back to it would
 * regress a named safety gate, confirms the repository Worker source and the
 * live-parity verifier agree on one Worker generation, and confirms an
 * executable fix-forward deployment path exists.
 *
 * A PASS does NOT claim that an older build is safe. Nothing here can ever
 * produce a "safe rollback target" — the approved recovery policy is FIX
 * FORWARD, and an older build is disqualified either by a proven safety-gate
 * regression or, absent that proof, by not being approved at all.
 *
 * NOTHING IN THIS FILE IS PINNED TO A RELEASE. Earlier revisions hardcoded the
 * candidate SHA, the app generation and the Worker generation, so the gate went
 * stale on every release and reported PASS while describing a superseded
 * candidate — a green check for the wrong release, which is the exact failure
 * class this repository keeps rediscovering. Every fact below is derived from
 * the tree and from git history at run time, so this gate cannot drift out of
 * date and needs no per-release edit.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Safety gates that must never silently disappear by going backwards. Each is a
// source identifier introduced by a release whose whole point was refusing to
// price or grade something the app could not honestly price or grade. A previous
// generation missing any of them is a PROVEN unsafe rollback target.
const SAFETY_INVARIANTS = [
  ['checkPickupFeasibility', 'pickup-time feasibility gate (v24.0.9) — prevents pricing a pickup that cannot be reached'],
  ['checkVanFit', 'dimensional/payload pre-check (v23.9 7D) — prevents grading freight the van cannot carry'],
  ['isDeadZoneEligible', 'canonical Dead Zone activation gate (X-04) — prevents survival-floor pricing without the gate'],
  ['knownNum', 'UNKNOWN-is-not-zero money discipline (v24.0.1) — prevents a verdict derived from absent facts'],
];

function git(args, { allowFail = false } = {}) {
  try {
    return execFileSync('git', args, {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    }).trim();
  } catch (err) {
    if (allowFail) return null;
    throw err;
  }
}

function read(rel) {
  return readFileSync(path.join(REPO_ROOT, rel), 'utf8');
}

function show(sha, rel) {
  return git(['show', `${sha}:${rel}`], { allowFail: true }) || '';
}

function appVersion(src) {
  return src.match(/^const APP_VERSION = '([\d.]+)';/m)?.[1] || null;
}

function swVersion(src) {
  return src.match(/^const SW_VERSION = '([\d.]+)';/m)?.[1] || null;
}

function workerVersion(src) {
  return src.match(/Cloud Backup Worker v(\d+)/)?.[1]
    || src.match(/version:\s*'(\d+)'/)?.[1]
    || null;
}

let failures = 0;
const pass = (msg) => console.log(`  PASS  ${msg}`);
const fail = (msg) => { failures++; console.log(`  FAIL  ${msg}`); };
const note = (msg) => console.log(`  NOTE  ${msg}`);

/* ------------------------------------------------- derive the candidate */

const workingApp = read('app.js');
const workingSw = read('service-worker.js');
const worker = read('cloud-backup-worker.js');

const APP_VERSION = appVersion(workingApp);
const WORKER_VERSION = workerVersion(worker);
const HEAD = git(['rev-parse', 'HEAD']);

console.log('== FreightLogic rollback / fix-forward evidence (B5) ==');
if (!APP_VERSION) {
  fail('app.js does not declare a readable APP_VERSION — the candidate cannot be identified');
}
if (!WORKER_VERSION) {
  fail('cloud-backup-worker.js does not declare a readable Worker generation');
}
console.log(`release candidate: ${HEAD}`);
console.log(`app generation:    v${APP_VERSION ?? '?'}`);
console.log(`Worker generation: v${WORKER_VERSION ?? '?'}\n`);

pass(`HEAD resolves: ${HEAD.slice(0, 12)}`);

swVersion(workingSw) === APP_VERSION
  ? pass(`candidate service worker identifies v${APP_VERSION} (SW_VERSION == APP_VERSION)`)
  : fail(`candidate service-worker.js is v${swVersion(workingSw) ?? 'unreadable'}, expected v${APP_VERSION}`);

for (const [ident, why] of SAFETY_INVARIANTS) {
  workingApp.includes(ident)
    ? pass(`candidate contains ${ident} — ${why.split(' — ')[0]}`)
    : fail(`candidate is MISSING the ${ident} safety gate (${why})`);
}

/* --------------------------------------- derive the previous generation */

console.log('\n-- previous app generation --');

// The commit that introduced this generation's APP_VERSION; its first parent is
// the tip of the generation before it. Falls back to walking app.js history if
// the marker was introduced inside a merge commit.
function findPreviousGenerationTip() {
  const introducing = git(
    ['log', '--format=%H', '-S', `const APP_VERSION = '${APP_VERSION}';`, '--', 'app.js'],
    { allowFail: true },
  );
  const introduced = introducing ? introducing.split('\n').filter(Boolean).pop() : null;
  if (introduced) {
    const parent = git(['rev-parse', '--verify', `${introduced}^`], { allowFail: true });
    if (parent && appVersion(show(parent, 'app.js')) && appVersion(show(parent, 'app.js')) !== APP_VERSION) {
      return parent;
    }
  }
  const history = (git(['log', '--format=%H', '-n', '400', '--', 'app.js'], { allowFail: true }) || '')
    .split('\n').filter(Boolean);
  for (const sha of history) {
    const v = appVersion(show(sha, 'app.js'));
    if (v && v !== APP_VERSION) return sha;
  }
  return null;
}

const previousTip = findPreviousGenerationTip();
let previousVersion = null;

if (!previousTip) {
  fail('no previous app generation is reachable in this clone — rollback evidence cannot be produced');
} else {
  const oldApp = show(previousTip, 'app.js');
  const oldSw = show(previousTip, 'service-worker.js');
  previousVersion = appVersion(oldApp);

  pass(`previous generation derived from history: ${previousTip.slice(0, 12)} (v${previousVersion ?? '?'})`);

  git(['merge-base', '--is-ancestor', previousTip, HEAD], { allowFail: true }) !== null
    ? pass(`v${previousVersion} candidate is a true ancestor of v${APP_VERSION}`)
    : fail(`derived v${previousVersion} candidate is not an ancestor of HEAD`);

  swVersion(oldSw) === previousVersion
    ? pass(`previous service worker identifies v${previousVersion}`)
    : fail(`previous service-worker is v${swVersion(oldSw) ?? 'unreadable'}, expected v${previousVersion}`);

  const regressions = SAFETY_INVARIANTS.filter(([ident]) => !oldApp.includes(ident));
  if (regressions.length) {
    for (const [ident, why] of regressions) {
      pass(`v${previousVersion} demonstrably lacks ${ident} — ${why}`);
    }
    pass(`v${previousVersion} is a PROVEN UNSAFE rollback target (${regressions.length} safety gate(s) absent)`);
  } else {
    note(`v${previousVersion} retains every named safety gate; no safety-gate regression is PROVEN for it.`);
    note('That is not an approval. No older build is an approved rollback target, and absence of proof is not proof of safety.');
  }
}

/* ------------------------------------------------ Worker / recovery path */

console.log('\n-- Worker / recovery path --');
pass(`repository Worker source is v${WORKER_VERSION}`);

const parity = read('scripts/verify-cloudflare-parity.mjs');
parity.includes(`workerVersion: "${WORKER_VERSION}"`)
  ? pass(`live-parity verifier expects the same Worker generation (v${WORKER_VERSION})`)
  : fail(`live-parity verifier is not aligned to the repository Worker source (v${WORKER_VERSION})`);

const deployWorkflow = read('.github/workflows/deploy-backup-worker.yml');
const fixForwardReady = [
  /workflow_dispatch:/,
  /wrangler@4 deploy -c scripts\/wrangler\.backup-worker\.jsonc/,
  /Verify \/health reports the expected Worker version/,
  /Verify the auth boundaries still deny/,
].every((re) => re.test(deployWorkflow));
fixForwardReady
  ? pass('manual Worker fix-forward workflow is present with deploy + post-deploy verification')
  : fail('Worker fix-forward workflow is incomplete or unreadable');

/* ------------------------------------------------ approved recovery policy */

console.log('\n-- approved recovery policy --');
note('APP: no older app SHA is approved as a safe rollback target.');
if (previousVersion) {
  note(`v${previousVersion} is the only adjacent candidate and it is not approved.`);
}
note('WORKER: no older Worker deployment is approved as a safe rollback target.');
note('Default for both components: FIX FORWARD from committed, tested source; then rerun parity/authority/backup gates.');

console.log('\n== B5 verdict ==');
if (failures) {
  console.log(`FAIL — ${failures} check(s) failed. Rollback/fix-forward evidence is NOT established.`);
  process.exit(1);
}
console.log('PASS — current candidate identity and the fix-forward procedure are verified.');
console.log(`Final runtime candidate: ${HEAD}`);
console.log('Safe rollback target: NONE PROVEN.');
console.log('Approved recovery action: FIX FORWARD.');
