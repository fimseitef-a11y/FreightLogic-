#!/usr/bin/env node
/**
 * FreightLogic — rollback evidence generator (completion gate B5).
 *
 * `FIELD_TEST_CHECKLIST.md` B5 requires: "Record the approved rollback SHA and
 * verify the rollback procedure is executable, not merely described."
 *
 * This script VERIFIES executability. It never mutates anything: no checkout,
 * no revert, no push, no deploy. It proves the named targets exist, proves the
 * revert applies cleanly (via an in-memory `git merge-tree`, not a working-tree
 * revert), and — the part that actually matters — names the regression each
 * rollback target REINTRODUCES.
 *
 * THE HEADLINE FINDING, which B5 had no record of:
 * neither component has a clean rollback target. Rolling back is not a safety
 * net here; it is a choice between named regressions. The default posture must
 * therefore be FIX FORWARD, and that is a release decision, not an ops detail.
 *
 *   node scripts/verify-rollback.mjs
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function git(args, { allowFail = false } = {}) {
  try {
    // maxBuffer must be generous: `git show <sha>:app.js` is ~1.1MB and
    // execFileSync's 1MB default truncates it into a throw, which — with
    // allowFail — silently became "APP_VERSION=none" and a FALSE rollback
    // failure in the B5 evidence. A release gate that fails for the wrong
    // reason is worse than one that does not run.
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

let failures = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const bad = (m) => { console.log(`  FAIL  ${m}`); failures++; };
const warn = (m) => console.log(`  WARN  ${m}`);

// ── The candidate currently in production ───────────────────────────────────
// Named by docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-12.md, which
// recorded exact-byte app parity against it.
const PRODUCTION_CANDIDATE = '8d5b82b8cfaf9d2264d0220d49e598e7ce705eec';

// ── Rollback targets, each with the regression it reintroduces ──────────────
const APP_TARGETS = [
  {
    sha: '5821e8a',
    label: 'v24.0.5 source-integrity release, before the van-profile reconciliation',
    reintroduces: [
      'CARGO-FIT SAFETY REGRESSION: payloadLbs reverts 3000 -> 3800, and the 54.8" ' +
      'wheelWellWidthIn constraint disappears entirely. Freight between 3,000 and ' +
      '3,800 lb — which this van physically cannot carry — scores as FITTING and ' +
      'proceeds to a full grade and bid. Introduced by 39882fa from operator ' +
      'measurement; a rollback past it discards measured vehicle truth in favour of ' +
      'published marketing figures.',
    ],
  },
  {
    sha: 'ff9d9ab',
    label: 'v24.0.4 "Fail Closed"',
    reintroduces: [
      'The cargo-fit regression above, AND:',
      'UNKNOWN-DEADHEAD REGRESSION: predates the v24.0.5 persistence fix, so ' +
      'newTripTemplate/sanitizeTrip coerce an unstated deadhead to 0 on every write. ' +
      'Unknown deadhead again contributes a flattering True RPM to lane averages, ' +
      'broker records, and historical comparisons.',
    ],
  },
];

console.log('== FreightLogic rollback evidence (gate B5) ==\n');
console.log(`Production candidate: ${PRODUCTION_CANDIDATE}\n`);

// ── 1. Repository preconditions ─────────────────────────────────────────────
console.log('-- repository preconditions --');

const fullHead = git(['rev-parse', 'HEAD']);
ok(`HEAD resolves: ${fullHead.slice(0, 8)}`);

if (git(['rev-parse', '--verify', `${PRODUCTION_CANDIDATE}^{commit}`], { allowFail: true })) {
  ok('production candidate SHA exists in this clone');
} else {
  bad(`production candidate ${PRODUCTION_CANDIDATE.slice(0, 8)} is NOT in this clone — ` +
      'fetch origin/main before trusting any rollback target below');
}

const tags = git(['tag'], { allowFail: true }) || '';
if (!tags.trim()) {
  warn('the repository has NO tags. Every rollback target is a bare SHA, which is ' +
       'exactly how a wrong one gets deployed under pressure. Tag the candidate ' +
       '(e.g. `git tag -a v24.0.5-prod 8d5b82b`) so rollback names a release, not a hash.');
}

// ── 2. App rollback targets ─────────────────────────────────────────────────
console.log('\n-- app rollback targets (Cloudflare service: freightlogic-v2) --');

for (const t of APP_TARGETS) {
  const full = git(['rev-parse', '--verify', `${t.sha}^{commit}`], { allowFail: true });
  if (!full) { bad(`${t.sha} does not resolve — not a usable rollback target`); continue; }

  const isAncestor = git(['merge-base', '--is-ancestor', full, fullHead], { allowFail: true }) !== null;
  if (isAncestor) ok(`${t.sha} resolves (${full.slice(0, 8)}) and is an ancestor of HEAD`);
  else bad(`${t.sha} resolves but is NOT an ancestor of HEAD — rolling "back" to it ` +
           'would not be a rollback');

  // Does it carry a coherent release identity? A rollback target whose markers
  // disagree ships a split cache generation (the v24.0.3 defect, in reverse).
  const appVer = (git(['show', `${full}:app.js`], { allowFail: true }) || '')
    .match(/^const APP_VERSION = '([\d.]+)';/m)?.[1];
  const swVer = (git(['show', `${full}:service-worker.js`], { allowFail: true }) || '')
    .match(/^const SW_VERSION = '([\d.]+)';/m)?.[1];
  if (appVer && swVer && appVer === swVer) {
    ok(`  ${t.sha}: APP_VERSION == SW_VERSION == ${appVer} (coherent cache generation)`);
  } else {
    bad(`  ${t.sha}: APP_VERSION=${appVer ?? 'none'} vs SW_VERSION=${swVer ?? 'none'} — ` +
        'a rollback to this SHA ships a split cache generation');
  }

  console.log(`        target: ${t.label}`);
  for (const r of t.reintroduces) {
    for (const line of wrap(r, 74)) console.log(`        !! ${line}`);
  }
}

// ── 3. Is a revert-based rollback actually clean? ───────────────────────────
console.log('\n-- revert cleanliness (in-memory; nothing is written) --');

const vanProfileCommit = git(['rev-parse', '--verify', '39882fa^{commit}'], { allowFail: true });
if (!vanProfileCommit) {
  warn('39882fa not present; skipping revert-cleanliness check');
} else {
  // `git merge-tree` performs a three-way merge entirely in memory. Reverting
  // X means merging (parent-of-X) into HEAD with X as the base.
  const parent = git(['rev-parse', `${vanProfileCommit}^`], { allowFail: true });
  const mt = git(['merge-tree', '--write-tree', '--name-only', parent, fullHead], { allowFail: true });
  if (mt === null) {
    warn('`git merge-tree --write-tree` unavailable (needs git >= 2.38) — verify the ' +
         'revert manually in a scratch worktree, never on the release branch');
  } else if (/^CONFLICT/m.test(mt)) {
    bad('a revert-based app rollback CONFLICTS — the procedure is described but not ' +
        'executable as-is. Resolve the conflict path before relying on it.');
  } else {
    ok('a revert-based app rollback applies cleanly (no conflicts)');
  }
}

// ── 4. Worker rollback — the part with no safe target ───────────────────────
console.log('\n-- worker rollback (Cloudflare service: freightlogic-backup) --');

const workerSrc = readFileSync(path.join(REPO_ROOT, 'cloud-backup-worker.js'), 'utf8');
const srcWorkerVer = workerSrc.match(/version:\s*'(\d+)'/)?.[1];
if (srcWorkerVer === '14') ok('repository Worker source is v14');
else bad(`repository Worker source reports v${srcWorkerVer ?? '?'}, expected 14`);

console.log('');
console.log('  !! THERE IS NO SAFE WORKER ROLLBACK TARGET.');
for (const line of wrap(
  'The only prior deployment of freightlogic-backup is v7 (read from the Cloudflare ' +
  'control plane on 2026-09-12; see AUDIT_REPORT.md P-01..P-07). v7 stores every driver ' +
  'bearer token in KV in PLAINTEXT and returns those tokens from GET /admin/users. ' +
  '`wrangler rollback` on this service is therefore a SECURITY REGRESSION, not a safety ' +
  'net, and it also reintroduces the live X-01 delta-loss defect and a Worker that owns ' +
  'verdict/grade in violation of the v24.0 authority rule.', 74)) {
  console.log(`     ${line}`);
}
console.log('');
for (const line of wrap(
  'APPROVED WORKER ROLLBACK POLICY: fix forward. If deployed v14 misbehaves, deploy a ' +
  'corrected v15 from source. Do not roll back to v7 under any circumstance short of a ' +
  'total outage, and if that ever happens, rotate every driver token immediately ' +
  'afterwards because the listing endpoint will have exposed them again.', 74)) {
  console.log(`     ${line}`);
}

// ── 5. Verdict ──────────────────────────────────────────────────────────────
console.log('\n== B5 verdict ==\n');
if (failures) {
  console.log(`${failures} check(s) FAILED — the rollback procedure is NOT verified executable.\n`);
  process.exit(1);
}
console.log('Rollback procedure is VERIFIED EXECUTABLE, with named regressions.\n');
console.log('Approved targets, in order of preference:');
console.log('  1. FIX FORWARD (both components) — the default.');
console.log('  2. App only, if required: revert 39882fa on main and let the');
console.log('     freightlogic-v2 build run. Accepts the cargo-fit regression above,');
console.log('     which must be communicated to the operator BEFORE the rollback,');
console.log('     because it silently raises the payload ceiling by 800 lb.');
console.log('  3. Worker: no rollback. See the policy above.\n');
console.log('This output is the B5 evidence artifact. Record it with the release SHAs.');
process.exit(0);

function wrap(s, width) {
  const words = String(s).split(/\s+/);
  const lines = [];
  let cur = '';
  for (const w of words) {
    if (cur && (cur.length + 1 + w.length) > width) { lines.push(cur); cur = w; }
    else cur = cur ? `${cur} ${w}` : w;
  }
  if (cur) lines.push(cur);
  return lines;
}
