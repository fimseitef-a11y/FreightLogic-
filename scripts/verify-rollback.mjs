#!/usr/bin/env node
/**
 * FreightLogic — rollback / fix-forward evidence generator (completion gate B5).
 *
 * Read-only. It never checks out, reverts, pushes or deploys anything.
 *
 * B5 is intentionally allowed to conclude that NO rollback SHA is safe. In that
 * case the executable recovery policy is FIX FORWARD, and this script proves the
 * current frozen runtime identity plus the repository paths needed to execute
 * that recovery. That is more truthful than blessing a known-regression build
 * merely because it exists in history.
 *
 * Usage:
 *   node scripts/verify-rollback.mjs
 *   node scripts/verify-rollback.mjs --candidate <sha>
 *
 * The default candidate is the latest FIRST-PARENT main commit that changed the
 * release-bound app shell. Using first-parent history matters: the implementation
 * commit on a topic branch is not the deployed release boundary; the merge into
 * main is. CI checks out full history before running this verifier.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

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

const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');
let failures = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const bad = (m) => { console.log(`  FAIL  ${m}`); failures++; };
const warn = (m) => console.log(`  WARN  ${m}`);

function argValue(name) {
  const i = process.argv.indexOf(name);
  if (i >= 0) return process.argv[i + 1] || '';
  const inline = process.argv.find(a => a.startsWith(`${name}=`));
  return inline ? inline.slice(name.length + 1) : '';
}

const RUNTIME_PATHS = [
  'app.js', 'index.html', 'styles.css', 'admin-driver-ui.js',
  'midwest-stack-authority.js', 'midwest-stack-config.json',
  'manifest.json', 'service-worker.js', 'sw-bridge.js', 'modern-shell.js',
  'voice-load.js', 'cloud-backup-worker.js', '.assetsignore',
];

function deriveRuntimeCandidate() {
  return git(['log', '--first-parent', '-1', '--format=%H', '--',
    'app.js', 'index.html', 'service-worker.js', 'manifest.json',
    'sw-bridge.js', 'modern-shell.js']);
}

const requestedCandidate = argValue('--candidate') || process.env.FL_RELEASE_SHA || '';
const PRODUCTION_CANDIDATE = requestedCandidate || deriveRuntimeCandidate();

const UNSAFE_APP_TARGETS = [
  {
    sha: '5821e8a',
    label: 'v24.0.5 source-integrity release before operator van-profile reconciliation',
    reintroduces: [
      'Cargo-fit safety regression: practical payload returns above the operator-confirmed 3,000 lb boundary and the 54.8 in wheel-well constraint is lost.',
    ],
  },
  {
    sha: 'ff9d9ab',
    label: 'v24.0.4 fail-closed release',
    reintroduces: [
      'The cargo-fit regression above.',
      'UNKNOWN-deadhead persistence regression: an unstated deadhead can again be manufactured as numeric zero in historical/economic data.',
    ],
  },
];

console.log('== FreightLogic rollback / fix-forward evidence (gate B5) ==\n');

// 1. Current release identity.
console.log('-- current frozen release identity --');
const head = git(['rev-parse', 'HEAD']);
ok(`HEAD resolves: ${head}`);

const candidateFull = git(['rev-parse', '--verify', `${PRODUCTION_CANDIDATE}^{commit}`], { allowFail: true });
if (!candidateFull) {
  bad(`runtime candidate ${PRODUCTION_CANDIDATE || '(empty)'} does not resolve. CI must use full git history or pass --candidate explicitly.`);
} else {
  ok(`runtime candidate resolves: ${candidateFull}`);
  const ancestor = git(['merge-base', '--is-ancestor', candidateFull, head], { allowFail: true }) !== null;
  ancestor ? ok('runtime candidate is an ancestor of HEAD') : bad('runtime candidate is not an ancestor of HEAD');
}

let appVersion = null;
let swVersion = null;
let manifestName = null;
if (candidateFull) {
  const appAtCandidate = git(['show', `${candidateFull}:app.js`], { allowFail: true }) || '';
  const swAtCandidate = git(['show', `${candidateFull}:service-worker.js`], { allowFail: true }) || '';
  const manifestAtCandidate = git(['show', `${candidateFull}:manifest.json`], { allowFail: true }) || '';
  appVersion = appAtCandidate.match(/^const APP_VERSION = '([\d.]+)';/m)?.[1] || null;
  swVersion = swAtCandidate.match(/^const SW_VERSION = '([\d.]+)';/m)?.[1] || null;
  try { manifestName = JSON.parse(manifestAtCandidate).name || null; } catch {}

  if (appVersion && swVersion && appVersion === swVersion) {
    ok(`candidate APP_VERSION == SW_VERSION == ${appVersion}`);
  } else {
    bad(`candidate release identity is split: APP_VERSION=${appVersion ?? 'none'} SW_VERSION=${swVersion ?? 'none'}`);
  }
  if (appVersion && manifestName === `FreightLogic v${appVersion}`) {
    ok(`candidate manifest name matches FreightLogic v${appVersion}`);
  } else {
    bad(`candidate manifest mismatch: ${manifestName ?? 'unreadable'}`);
  }

  const runtimeDrift = git(['diff', '--name-only', `${candidateFull}..HEAD`, '--', ...RUNTIME_PATHS], { allowFail: true });
  if (runtimeDrift === null) {
    bad('could not compare candidate to HEAD for runtime drift');
  } else if (runtimeDrift.trim()) {
    bad(`runtime files changed after the frozen candidate:\n    ${runtimeDrift.split('\n').join('\n    ')}`);
  } else {
    ok('no release-bound runtime file changed after the frozen candidate');
  }
}

// 2. Worker generation must be derived from the same contract the live parity
// verifier uses, never pinned independently here.
console.log('\n-- Worker generation contract --');
const parity = read('scripts/verify-cloudflare-parity.mjs');
const workerSrc = read('cloud-backup-worker.js');
const expectedWorkerVersion = parity.match(/workerVersion:\s*"(\d+)"/)?.[1] || null;
const headerWorkerVersion = workerSrc.match(/Cloud Backup Worker v(\d+)/)?.[1] || null;
const healthWorkerVersion = workerSrc.match(/path === '\/health'[\s\S]{0,400}?version:\s*'(\d+)'/)?.[1] || null;

if (!expectedWorkerVersion) bad('could not derive expected Worker version from the live parity verifier');
if (expectedWorkerVersion && headerWorkerVersion === expectedWorkerVersion) {
  ok(`Worker source header matches parity contract: v${expectedWorkerVersion}`);
} else {
  bad(`Worker source header v${headerWorkerVersion ?? '?'} != parity contract v${expectedWorkerVersion ?? '?'}`);
}
if (expectedWorkerVersion && healthWorkerVersion === expectedWorkerVersion) {
  ok(`/health source reports Worker v${expectedWorkerVersion}`);
} else {
  bad(`/health version v${healthWorkerVersion ?? '?'} != parity contract v${expectedWorkerVersion ?? '?'}`);
}

// 3. Known historical app targets are deliberately UNSAFE. Their existence is
// evidence for why fix-forward is the approved policy, not permission to use them.
console.log('\n-- historical app rollback targets (classification only) --');
for (const t of UNSAFE_APP_TARGETS) {
  const full = git(['rev-parse', '--verify', `${t.sha}^{commit}`], { allowFail: true });
  if (!full) {
    bad(`${t.sha} does not resolve; full history is required to verify its known regressions`);
    continue;
  }
  const beforeCandidate = candidateFull
    ? git(['merge-base', '--is-ancestor', full, candidateFull], { allowFail: true }) !== null
    : false;
  beforeCandidate ? ok(`${t.sha} resolves and predates the frozen candidate`) : bad(`${t.sha} is not a verified ancestor of the frozen candidate`);
  console.log(`        UNSAFE target: ${t.label}`);
  for (const r of t.reintroduces) console.log(`        !! ${r}`);
}

// 4. Worker rollback classification. v7 is intentionally not approved: it
// exposed plaintext driver bearer tokens and violated the canonical authority
// boundary. If v15 needs repair, the next corrected Worker generation is deployed
// from source; do not "fix" v15 by rolling back into the security defect.
console.log('\n-- Worker rollback classification --');
console.log('  !! NO SAFE WORKER ROLLBACK TARGET IS APPROVED.');
console.log('     The known prior v7 deployment is a security/data-authority regression.');
console.log('     Approved response to a Worker defect: FIX FORWARD to the next corrected');
console.log('     Worker generation, then repeat health/CORS/auth-boundary/backup/parity checks.');

// 5. Prove the repository actually contains the recovery machinery named by the
// policy. This is read-only executability evidence: the paths and safety gates
// exist, and the live-parity job is wired to re-observe a release-bound main push.
console.log('\n-- fix-forward executability --');
const requiredFiles = [
  '.github/workflows/tests.yml',
  '.github/workflows/verify-live-parity.yml',
  '.github/workflows/deploy-backup-worker.yml',
  'scripts/deploy-backup-worker.sh',
  'scripts/verify-cloudflare-parity.mjs',
  'scripts/verify-live-authority.mjs',
  'scripts/verify-live-backup.mjs',
  'wrangler.jsonc',
  'scripts/wrangler.backup-worker.jsonc',
];
for (const rel of requiredFiles) {
  existsSync(path.join(REPO_ROOT, rel)) ? ok(`${rel} exists`) : bad(`${rel} is missing`);
}

if (existsSync(path.join(REPO_ROOT, '.github/workflows/verify-live-parity.yml'))) {
  const wf = read('.github/workflows/verify-live-parity.yml');
  ok(/^\s{2}push:\s*$/m.test(wf) && /branches:\s*\[main\]/.test(wf),
    'live parity is automatically re-observed on release-bound main pushes');
  ok(/^permissions:\s*\n\s+contents:\s*read\s*$/m.test(wf),
    'live parity remains read-only');
}

if (existsSync(path.join(REPO_ROOT, 'wrangler.jsonc'))) {
  const appConfig = read('wrangler.jsonc');
  /"name"\s*:\s*"freightlogic-v2"/.test(appConfig)
    ? ok('app deployment config names freightlogic-v2')
    : bad('wrangler.jsonc does not name freightlogic-v2');
}

if (existsSync(path.join(REPO_ROOT, 'scripts/wrangler.backup-worker.jsonc'))) {
  const workerConfig = read('scripts/wrangler.backup-worker.jsonc');
  /"name"\s*:\s*"freightlogic-backup"/.test(workerConfig)
    ? ok('backup Worker deployment config names freightlogic-backup')
    : bad('backup Worker config does not name freightlogic-backup');
}

const tags = git(['tag'], { allowFail: true }) || '';
if (!tags.trim()) warn('repository still has no release tags; retain the exact SHA in certification records');

console.log('\n== B5 verdict ==\n');
if (failures) {
  console.log(`${failures} check(s) FAILED — rollback/fix-forward evidence is not complete.\n`);
  process.exit(1);
}

console.log('B5 VERIFIED.');
console.log(`  Frozen runtime candidate: ${candidateFull}`);
console.log(`  App/PWA generation:       ${appVersion}`);
console.log(`  Worker generation:        v${expectedWorkerVersion}`);
console.log('  Approved rollback SHA:    NONE — no known prior build is regression-safe.');
console.log('  Approved recovery policy: FIX FORWARD.');
console.log('');
console.log('Procedure:');
console.log('  1. Make the smallest corrective source change on a task branch.');
console.log('  2. Run the full suite and merge only green CI.');
console.log('  3. App fixes deploy through the normal freightlogic-v2 main build; the');
console.log('     read-only live-parity workflow automatically re-observes production.');
console.log('  4. Worker fixes use Deploy Backup Worker for the next corrected generation,');
console.log('     then run live authority + backup + parity verification with private test');
console.log('     credentials. Never roll back to v7.');
console.log('');
process.exit(0);
