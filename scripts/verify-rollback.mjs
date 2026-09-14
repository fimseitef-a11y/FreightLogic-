#!/usr/bin/env node
/**
 * FreightLogic — rollback / fix-forward evidence generator (completion gate B5).
 *
 * Read-only by design: no checkout, revert, push, deploy, secret read or network
 * request. The gate verifies the frozen v24.0.9 runtime candidate, proves the
 * immediately previous app generation is NOT a safe rollback because it lacks
 * the pickup-feasibility safety gate, verifies Worker v15 is the current source,
 * and verifies an executable fix-forward deployment path exists.
 *
 * A PASS therefore does NOT claim that an older build is safe. It proves the
 * opposite and records the approved recovery policy: FIX FORWARD.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const RELEASE_CANDIDATE = '5446b097fe8791f3d7c79b5a5833a0930ee83cf2';
const PREVIOUS_APP_CANDIDATE = 'a7b72592eb28fe073a65d28d9bcd61109e3ef026';
const EXPECTED_APP_VERSION = '24.0.9';
const PREVIOUS_APP_VERSION = '24.0.8';
const EXPECTED_WORKER_VERSION = '15';

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

console.log('== FreightLogic rollback / fix-forward evidence (B5) ==');
console.log(`release candidate: ${RELEASE_CANDIDATE}`);
console.log(`app generation:    v${EXPECTED_APP_VERSION}`);
console.log(`Worker generation: v${EXPECTED_WORKER_VERSION}\n`);

const head = git(['rev-parse', 'HEAD']);
pass(`HEAD resolves: ${head.slice(0, 12)}`);

const candidate = git(['rev-parse', '--verify', `${RELEASE_CANDIDATE}^{commit}`], { allowFail: true });
if (!candidate) {
  fail(`release candidate ${RELEASE_CANDIDATE} is not present in this clone`);
} else {
  pass('frozen v24.0.9 release candidate exists');
  const ancestor = git(['merge-base', '--is-ancestor', RELEASE_CANDIDATE, head], { allowFail: true }) !== null;
  ancestor ? pass('release candidate is an ancestor of HEAD') : fail('release candidate is not an ancestor of HEAD');

  const app = show(RELEASE_CANDIDATE, 'app.js');
  const sw = show(RELEASE_CANDIDATE, 'service-worker.js');
  appVersion(app) === EXPECTED_APP_VERSION
    ? pass(`release app.js identifies v${EXPECTED_APP_VERSION}`)
    : fail(`release app.js version is ${appVersion(app) ?? 'unreadable'}, expected ${EXPECTED_APP_VERSION}`);
  swVersion(sw) === EXPECTED_APP_VERSION
    ? pass(`release service worker identifies v${EXPECTED_APP_VERSION}`)
    : fail(`release service-worker.js version is ${swVersion(sw) ?? 'unreadable'}, expected ${EXPECTED_APP_VERSION}`);
  app.includes('checkPickupFeasibility')
    ? pass('release candidate contains the pickup-feasibility safety gate')
    : fail('release candidate is missing checkPickupFeasibility');
}

console.log('\n-- previous app generation --');
const previous = git(['rev-parse', '--verify', `${PREVIOUS_APP_CANDIDATE}^{commit}`], { allowFail: true });
if (!previous) {
  fail(`previous app candidate ${PREVIOUS_APP_CANDIDATE} is not present in this clone`);
} else {
  const ancestor = git(['merge-base', '--is-ancestor', PREVIOUS_APP_CANDIDATE, RELEASE_CANDIDATE], { allowFail: true }) !== null;
  ancestor ? pass('v24.0.8 candidate is a true ancestor of v24.0.9') : fail('named v24.0.8 candidate is not an ancestor of v24.0.9');

  const oldApp = show(PREVIOUS_APP_CANDIDATE, 'app.js');
  const oldSw = show(PREVIOUS_APP_CANDIDATE, 'service-worker.js');
  appVersion(oldApp) === PREVIOUS_APP_VERSION
    ? pass(`previous app identifies v${PREVIOUS_APP_VERSION}`)
    : fail(`previous app version is ${appVersion(oldApp) ?? 'unreadable'}, expected ${PREVIOUS_APP_VERSION}`);
  swVersion(oldSw) === PREVIOUS_APP_VERSION
    ? pass(`previous service worker identifies v${PREVIOUS_APP_VERSION}`)
    : fail(`previous service-worker version is ${swVersion(oldSw) ?? 'unreadable'}, expected ${PREVIOUS_APP_VERSION}`);

  if (!oldApp.includes('checkPickupFeasibility')) {
    pass('v24.0.8 demonstrably lacks the pickup-feasibility gate — rollback is UNSAFE');
  } else {
    fail('v24.0.8 unexpectedly contains checkPickupFeasibility; reassess rollback safety');
  }
}

console.log('\n-- Worker / recovery path --');
const worker = read('cloud-backup-worker.js');
workerVersion(worker) === EXPECTED_WORKER_VERSION
  ? pass(`repository Worker source is v${EXPECTED_WORKER_VERSION}`)
  : fail(`repository Worker source is v${workerVersion(worker) ?? '?'}, expected v${EXPECTED_WORKER_VERSION}`);

const parity = read('scripts/verify-cloudflare-parity.mjs');
parity.includes(`workerVersion: "${EXPECTED_WORKER_VERSION}"`)
  ? pass(`live-parity verifier expects Worker v${EXPECTED_WORKER_VERSION}`)
  : fail(`live-parity verifier is not aligned to Worker v${EXPECTED_WORKER_VERSION}`);

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

console.log('\n-- approved recovery policy --');
note('APP: no older app SHA is approved as a safe rollback target.');
note('v24.0.8 is specifically disqualified because it reintroduces pricing of unreachable pickups.');
note('WORKER: no older Worker deployment is approved as a safe rollback target.');
note('Default for both components: FIX FORWARD from committed, tested source; then rerun parity/authority/backup gates.');

console.log('\n== B5 verdict ==');
if (failures) {
  console.log(`FAILURE — ${failures} verification check(s) failed. Do not certify B5.`);
  process.exit(1);
}

console.log('PASS — current candidate identity and the fix-forward procedure are verified.');
console.log(`Final runtime candidate: ${RELEASE_CANDIDATE}`);
console.log('Safe rollback target: NONE PROVEN.');
console.log('Approved recovery action: FIX FORWARD.');
process.exit(0);
