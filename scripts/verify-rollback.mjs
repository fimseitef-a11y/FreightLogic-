#!/usr/bin/env node
/**
 * FreightLogic — rollback evidence generator (completion gate B5).
 *
 * `FIELD_TEST_CHECKLIST.md` B5 requires: "Record the approved rollback SHA and
 * verify the rollback procedure is executable, not merely described."
 *
 * This script VERIFIES executability. It never mutates anything: no checkout,
 * no revert, no push, no deploy. It proves the named targets exist, proves a
 * revert applies cleanly (via an in-memory `git merge-tree`, not a working-tree
 * revert), and — the part that actually matters — names the regression each
 * rollback target REINTRODUCES, then PROVES that naming against the target's
 * own bytes.
 *
 * THE HEADLINE FINDING, which B5 had no record of:
 * neither component has a clean rollback target. Rolling back is not a safety
 * net here; it is a choice between named regressions. The default posture must
 * therefore be FIX FORWARD, and that is a release decision, not an ops detail.
 *
 * NOTHING IN THIS FILE IS A PINNED RELEASE LITERAL, and that is deliberate.
 * The 2026-09-14 review found this generator carrying an obsolete candidate SHA
 * and a stale `=== '14'` Worker expectation while the release had moved to
 * v24.0.9 / Worker v15 — so running it failed for the wrong reason, which is
 * the one thing a release gate may never do. Both are now DERIVED:
 *
 *   - the release candidate, from the living release-authority documents;
 *   - the Worker generation, from `scripts/verify-cloudflare-parity.mjs`'s
 *     EXPECTED block, the single declared source of truth that
 *     `scripts/deploy-backup-worker.sh` already derives from.
 *
 * and the prose regressions are checked against each target's real bytes, so a
 * claim that quietly stops being true fails here instead of shipping as
 * evidence.
 *
 *   node scripts/verify-rollback.mjs
 *   node scripts/verify-rollback.mjs --candidate=<sha>   # explicit override
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { declaredRuntimeAssets } from './lib/deploy-assets.mjs';
import { deriveCandidate, declaredWorkerVersion, sourceWorkerVersion } from './lib/release-candidate.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function git(args, { allowFail = false } = {}) {
  const r = gitTry(args);
  if (r.status === 0) return r.out;
  if (allowFail) return null;
  throw new Error(`git ${args.join(' ')} failed (${r.status}): ${r.out}`);
}

// The status-preserving form. `git()` above collapses every non-zero exit into
// null, which is fine for "does this ref resolve?" and WRONG for `merge-tree`,
// where exit 1 means "conflicts found" — a real answer, not a failure to run.
// Conflating the two is how the old revert check reported a genuine conflict as
// "your git is too old".
function gitTry(args) {
  try {
    // maxBuffer must be generous: `git show <sha>:app.js` is ~1.1MB and
    // execFileSync's 1MB default truncates it into a throw, which — with
    // allowFail — silently became "APP_VERSION=none" and a FALSE rollback
    // failure in the B5 evidence. A release gate that fails for the wrong
    // reason is worse than one that does not run.
    const out = execFileSync('git', args, {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 0, out: out.trim() };
  } catch (err) {
    const out = [err.stdout, err.stderr].filter(Boolean).join('\n').trim();
    return { status: typeof err.status === 'number' ? err.status : null, out };
  }
}

let failures = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const bad = (m) => { console.log(`  FAIL  ${m}`); failures++; };
const warn = (m) => console.log(`  WARN  ${m}`);
const note = (indent, s, width = 74) => {
  for (const line of wrap(s, width)) console.log(`${indent}${line}`);
};

// Cache `git show <sha>:<path>` — the regression probes below read app.js at
// four SHAs, and that is 1.1MB a time.
const showCache = new Map();
function showAt(sha, rel) {
  const key = `${sha}:${rel}`;
  if (!showCache.has(key)) showCache.set(key, git(['show', `${sha}:${rel}`], { allowFail: true }) ?? '');
  return showCache.get(key);
}

// ── The candidate currently in production, DERIVED ──────────────────────────
// The derivation itself lives in scripts/lib/release-candidate.mjs, which this
// gate and tests/unit/rollback-verifier.spec.mjs both import. A second copy in
// the test could drift from the copy in the gate, and each would then report
// green about the other's blind spot — the 2026-09-13 deploy-coverage defect,
// one level up.
const argv = process.argv.slice(2);
const override = argv.map((a) => /^--candidate=([0-9a-f]{7,40})$/i.exec(a)).find(Boolean)?.[1];

console.log('== FreightLogic rollback evidence (gate B5) ==\n');
console.log('-- release candidate (derived, not pinned) --');

const { readings, agreed } = deriveCandidate();
for (const r of readings) {
  if (r.missing) { warn(`${r.rel} is missing — cannot corroborate the candidate from it`); continue; }
  if (r.shas.length === 0) { warn(`${r.rel} names no runtime candidate SHA`); continue; }
  if (r.shas.length > 1) {
    bad(`${r.rel} names ${r.shas.length} different runtime candidates ` +
        `(${r.shas.map((s) => s.slice(0, 8)).join(', ')}) — the release record contradicts itself`);
    continue;
  }
  ok(`${r.rel} names ${r.shas[0].slice(0, 8)}`);
}

let PRODUCTION_CANDIDATE = null;
if (override) {
  PRODUCTION_CANDIDATE = git(['rev-parse', '--verify', `${override}^{commit}`], { allowFail: true });
  if (!PRODUCTION_CANDIDATE) bad(`--candidate=${override} does not resolve in this clone`);
  else {
    ok(`explicit --candidate override: ${PRODUCTION_CANDIDATE.slice(0, 8)}`);
    if (agreed.length === 1 && agreed[0] !== PRODUCTION_CANDIDATE) {
      warn(`the override differs from what the release authorities name ` +
           `(${agreed[0].slice(0, 8)}). The evidence below describes the OVERRIDE, ` +
           'not the certified candidate — say so wherever you file it.');
    }
  }
} else if (agreed.length === 1) {
  PRODUCTION_CANDIDATE = agreed[0];
  ok(`all present authorities agree: ${PRODUCTION_CANDIDATE.slice(0, 8)}`);
} else if (agreed.length === 0) {
  bad('NO release authority names a runtime candidate — refusing to guess. ' +
      'Pass --candidate=<sha> only if you can state where that SHA is recorded.');
} else {
  bad(`release authorities DISAGREE about the runtime candidate ` +
      `(${agreed.map((s) => s.slice(0, 8)).join(' vs ')}). Reconcile the release ` +
      'record before generating B5 evidence from it.');
}

console.log('');
console.log(`Production candidate: ${PRODUCTION_CANDIDATE ?? '(unresolved)'}\n`);

// ── 1. Repository preconditions ─────────────────────────────────────────────
console.log('-- repository preconditions --');

const fullHead = git(['rev-parse', 'HEAD']);
ok(`HEAD resolves: ${fullHead.slice(0, 8)}`);

if (PRODUCTION_CANDIDATE) {
  if (git(['rev-parse', '--verify', `${PRODUCTION_CANDIDATE}^{commit}`], { allowFail: true })) {
    ok('production candidate SHA exists in this clone');

    if (PRODUCTION_CANDIDATE === fullHead) {
      ok('HEAD IS the production candidate');
    } else if (git(['merge-base', '--is-ancestor', PRODUCTION_CANDIDATE, fullHead], { allowFail: true }) !== null) {
      const ahead = git(['rev-list', '--count', `${PRODUCTION_CANDIDATE}..${fullHead}`], { allowFail: true });
      ok(`HEAD is ${ahead} commit(s) ahead of the candidate`);

      // The release record's claim is that everything after the candidate was
      // docs/tooling only. That is checkable rather than believable: compare the
      // declared runtime inventory blob-by-blob. If a shipped file moved, the
      // evidence below is about a build nobody certified.
      const { assets, problems } = declaredRuntimeAssets();
      if (problems.length) {
        bad(`runtime asset inventory could not be derived: ${problems.join('; ')}`);
      } else {
        const drifted = [];
        for (const rel of assets.keys()) {
          const a = git(['rev-parse', `${PRODUCTION_CANDIDATE}:${rel}`], { allowFail: true });
          const b = git(['rev-parse', `${fullHead}:${rel}`], { allowFail: true });
          if (a !== b) drifted.push(rel);
        }
        const genOf = (sha) => showAt(sha, 'app.js').match(/^const APP_VERSION = '([\d.]+)';/m)?.[1] ?? null;
        const candGen = genOf(PRODUCTION_CANDIDATE);
        const headGen = genOf(fullHead);

        if (drifted.length === 0) {
          ok(`all ${assets.size} declared runtime assets are byte-identical ` +
             'between the candidate and HEAD (post-candidate commits are docs/tooling only)');
        } else if (candGen && headGen && candGen === headGen) {
          // The dangerous case, and the reason this check exists. Runtime bytes
          // moved while APP_VERSION — and therefore SW_VERSION and CACHE_NAME —
          // stood still, so an installed PWA has no new identity to fetch on any
          // axis and keeps serving the old shell. That is the v24.0.3 defect
          // exactly, and it is a release blocker, not a note.
          bad(`${drifted.length} shipped runtime asset(s) DIFFER between the certified ` +
              `candidate and HEAD while BOTH still report v${headGen}: ${drifted.join(', ')}`);
          note('        ', 'A runtime change landed without a new generation. CACHE_NAME is ' +
               '`freightlogic-${SW_VERSION}`, so this change cannot reach an installed PWA ' +
               'at all — bump the generation per the version-bump checklist in CLAUDE.md ' +
               'before filing any of the output below as B5 evidence.');
        } else {
          // HEAD is a genuinely newer generation than the one the release record
          // names. That is ordinary progress on an uncertified line, not a
          // defect: the documents are simply behind. Say so rather than failing,
          // and be explicit about which build the evidence below describes.
          warn(`${drifted.length} shipped runtime asset(s) differ between the certified ` +
               `candidate (v${candGen ?? '?'}) and HEAD (v${headGen ?? '?'}): ${drifted.join(', ')}`);
          note('        ', 'HEAD is a NEWER generation than the release record names, so the ' +
               'record is stale rather than contradicted. The rollback targets below are ' +
               "HEAD's; the candidate named above has not been re-certified against this " +
               'generation, and must be before this output is filed as final B5 evidence.');
        }
      }
    } else {
      bad('the production candidate is NOT an ancestor of HEAD — this clone is not on ' +
          'the release line');
    }
  } else {
    bad(`production candidate ${PRODUCTION_CANDIDATE.slice(0, 8)} is NOT in this clone — ` +
        'fetch origin/main before trusting any rollback target below');
  }
}

const tags = git(['tag'], { allowFail: true }) || '';
if (!tags.trim()) {
  warn('the repository has NO tags. Every rollback target is a bare SHA, which is ' +
       'exactly how a wrong one gets deployed under pressure. Tag the candidate ' +
       `(e.g. \`git tag -a v24.0.9-prod ${(PRODUCTION_CANDIDATE ?? '<sha>').slice(0, 7)}\`) ` +
       'so rollback names a release, not a hash.');
}

// ── 2. App rollback targets ─────────────────────────────────────────────────
// Ordered nearest-first. Each target inherits every regression below it, so the
// cost of rolling back is cumulative and stated as such.
//
// Every `reintroduces` claim carries a `probe` that re-derives it from the
// target's own bytes. Prose in a release artifact goes stale silently; a probe
// that stops matching fails this gate instead.
const APP_TARGETS = [
  {
    sha: 'a7b7259',
    label: 'v24.0.8, after the admin-UI deploy repair and the deploy-asset coverage gate',
    reintroduces: [
      {
        text:
          'PICKUP-FEASIBILITY LOSS: predates v24.0.9, so checkPickupFeasibility() does not ' +
          'exist. An operator who has set settings[planningAvgMph] silently loses the only ' +
          'check that blocks a pickup they cannot physically reach in the window that is ' +
          'left — the 225-mile-deadhead-against-a-19:00-cutoff case. Nothing announces the ' +
          'loss: the evaluator simply grades and prices such a load again, as it always did.',
        probe: (at) => !at('app.js').includes('checkPickupFeasibility'),
        probeDesc: 'app.js at this SHA really has no checkPickupFeasibility()',
      },
    ],
  },
  {
    sha: 'c02ed36',
    label: 'v24.0.8 landing, BEFORE the admin-UI deploy repair',
    reintroduces: [
      { text: 'Everything above, AND:' },
      {
        text:
          'DEPLOY-COVERAGE REGRESSION: .assetsignore excludes admin-driver-ui.js, so the ' +
          'Cloudflare Workers assets uploader never publishes it — while service-worker.js ' +
          'still precaches it in CORE and injects a <script> tag for it into every HTML ' +
          'response. The file returns HTTP 404 from the live origin. This is the exact ' +
          '2026-09-13 defect that passed 24/24 parity checks, and this target also predates ' +
          'the coverage gate that detects it, so a parity run against it reports green.',
        probe: (at) => /(^|\n)\s*admin-driver-ui\.js\s*(\n|$)/.test(at('.assetsignore')),
        probeDesc: '.assetsignore at this SHA really excludes admin-driver-ui.js',
      },
    ],
  },
  {
    sha: '5821e8a',
    label: 'v24.0.5 source-integrity release, before the van-profile reconciliation',
    reintroduces: [
      { text: 'Everything above, AND:' },
      {
        text:
          'CARGO-FIT SAFETY REGRESSION: payloadLbs reverts 3000 -> 3800, and the 54.8" ' +
          'wheelWellWidthIn constraint disappears entirely. Freight between 3,000 and ' +
          '3,800 lb — which this van physically cannot carry — scores as FITTING and ' +
          'proceeds to a full grade and bid. Introduced by 39882fa from operator ' +
          'measurement; a rollback past it discards measured vehicle truth in favour of ' +
          'published marketing figures.',
        probe: (at) => /payloadLbs:\s*3800/.test(at('app.js')) && !at('app.js').includes('wheelWellWidthIn'),
        probeDesc: 'app.js at this SHA really carries payloadLbs 3800 and no wheel-well constraint',
      },
      {
        text:
          'SILENT BACKUP LOSS: predates v24.0.6, so cloudBackupPaused(), ' +
          'renderCloudPausedBanner() and openCloudReconnect() do not exist. ' +
          'cloudIsEnabled() still requires the sessionStorage passphrase, so cloud backup ' +
          'switches itself off after every browser close with nothing on Home reporting ' +
          'it — the failure is discovered at restore time, which is the worst available ' +
          'moment for a bookkeeping app whose whole cloud story is disaster recovery.',
        probe: (at) => !at('app.js').includes('cloudBackupPaused'),
        probeDesc: 'app.js at this SHA really has no cloudBackupPaused()',
      },
      {
        text:
          'UI GENERATION CHANGE (not a defect, but state it before rolling back): this SHA ' +
          'predates the structural shell, so the driver returns to the pre-24.0.8 ' +
          'navigation. The Today/Loads/Evaluate/Trips/Money tab bar and the Loads surface ' +
          'do not exist here. The older navigation worked — this is a visible change of ' +
          'app, not a broken one, and the operator must be told before it lands on them.',
        probe: (at) => at('modern-shell.js') === '',
        probeDesc: 'modern-shell.js really does not exist at this SHA',
      },
    ],
  },
  {
    sha: 'ff9d9ab',
    label: 'v24.0.4 "Fail Closed"',
    reintroduces: [
      { text: 'Everything above, AND:' },
      {
        text:
          'UNKNOWN-DEADHEAD PERSISTENCE REGRESSION: predates the v24.0.5 persistence fix, ' +
          'so newTripTemplate/sanitizeTrip coerce an unstated deadhead to 0 on every write ' +
          'and tripHasKnownDeadhead() does not exist to quarantine it. Unknown deadhead ' +
          'again contributes a flattering True RPM to lane averages, broker records, and ' +
          'historical comparisons — silently, and permanently, because the coercion ' +
          'happens at write time.',
        probe: (at) => !at('app.js').includes('tripHasKnownDeadhead'),
        probeDesc: 'app.js at this SHA really has no tripHasKnownDeadhead()',
      },
    ],
  },
];

console.log('\n-- app rollback targets (Cloudflare service: freightlogic-v2) --');
console.log('   nearest first; each target inherits every regression listed above it.\n');

for (const t of APP_TARGETS) {
  const full = git(['rev-parse', '--verify', `${t.sha}^{commit}`], { allowFail: true });
  if (!full) { bad(`${t.sha} does not resolve — not a usable rollback target`); continue; }

  const isAncestor = git(['merge-base', '--is-ancestor', full, fullHead], { allowFail: true }) !== null;
  if (isAncestor) ok(`${t.sha} resolves (${full.slice(0, 8)}) and is an ancestor of HEAD`);
  else bad(`${t.sha} resolves but is NOT an ancestor of HEAD — rolling "back" to it ` +
           'would not be a rollback');

  if (PRODUCTION_CANDIDATE &&
      git(['merge-base', '--is-ancestor', PRODUCTION_CANDIDATE, full], { allowFail: true }) !== null) {
    bad(`  ${t.sha} is not BEHIND the production candidate — it cannot be rolled back to`);
  }

  // Does it carry a coherent release identity? A rollback target whose markers
  // disagree ships a split cache generation (the v24.0.3 defect, in reverse).
  const appVer = showAt(full, 'app.js').match(/^const APP_VERSION = '([\d.]+)';/m)?.[1];
  const swVer = showAt(full, 'service-worker.js').match(/^const SW_VERSION = '([\d.]+)';/m)?.[1];
  if (appVer && swVer && appVer === swVer) {
    ok(`  ${t.sha}: APP_VERSION == SW_VERSION == ${appVer} (coherent cache generation)`);
  } else {
    bad(`  ${t.sha}: APP_VERSION=${appVer ?? 'none'} vs SW_VERSION=${swVer ?? 'none'} — ` +
        'a rollback to this SHA ships a split cache generation');
  }

  console.log(`        target: ${t.label}`);
  const at = (rel) => showAt(full, rel);
  for (const r of t.reintroduces) {
    for (const line of wrap(r.text, 74)) console.log(`        !! ${line}`);
    if (!r.probe) continue;
    let held = false;
    try { held = r.probe(at) === true; } catch { held = false; }
    if (held) console.log(`           (verified: ${r.probeDesc})`);
    else bad(`  ${t.sha}: the regression above is NOT confirmed by this SHA's bytes ` +
             `(${r.probeDesc}) — the B5 artifact would be describing a regression that ` +
             'is not there, or missing one that is');
  }
  console.log('');
}

// ── 3. Is a revert-based rollback actually clean? ───────────────────────────
console.log('-- revert cleanliness (in-memory; nothing is written) --');

const vanProfileCommit = git(['rev-parse', '--verify', '39882fa^{commit}'], { allowFail: true });
if (!vanProfileCommit) {
  warn('39882fa not present; skipping revert-cleanliness check');
} else {
  const parent = git(['rev-parse', `${vanProfileCommit}^`], { allowFail: true });
  // Reverting X into HEAD is the three-way merge (base = X, ours = HEAD,
  // theirs = X's parent). `--merge-base` is what makes it that merge.
  //
  // The previous form here was `merge-tree --write-tree <parent> <HEAD>`, which
  // lets git pick the merge base itself — and since `parent` is an ancestor of
  // HEAD, that base IS `parent`, so the "merge" was a fast-forward that returned
  // HEAD's own tree unchanged. It could not report a conflict under any
  // circumstance. Verified against this repository on 2026-09-14: the tree it
  // produced was byte-identical to `HEAD^{tree}`. It was not a weak check, it
  // was not a check at all, and it had been reporting "applies cleanly" as B5
  // evidence.
  const mt = gitTry(['merge-tree', '--write-tree', '--name-only',
                     `--merge-base=${vanProfileCommit}`, fullHead, parent]);
  if (mt.status === 0) {
    ok('a revert of 39882fa applies cleanly (no conflicts)');
  } else if (mt.status === 1) {
    // Exit 1 is `merge-tree` reporting conflicts — a real answer. The old code
    // collapsed every non-zero exit into "git is too old", so a genuine conflict
    // was reported as a missing tool.
    const files = mt.out.split('\n').slice(1).filter((l) => l && !/^(Auto-merging|CONFLICT|Already)/.test(l));
    bad('a revert-based app rollback CONFLICTS — the procedure is described but not ' +
        `executable as-is${files.length ? ` (in: ${files.join(', ')})` : ''}. Resolve the ` +
        'conflict path before relying on it.');
  } else {
    warn('`git merge-tree --write-tree --merge-base=…` did not run (needs git >= 2.38) — ' +
         'verify the revert manually in a scratch worktree, never on the release branch' +
         (mt.out ? `: ${mt.out.split('\n')[0]}` : ''));
  }
}

// ── 4. Worker rollback — the part with no safe target ───────────────────────
console.log('\n-- worker rollback (Cloudflare service: freightlogic-backup) --');

// The Worker generation has exactly ONE declared source of truth: the parity
// verifier's EXPECTED block. `scripts/deploy-backup-worker.sh` already derives
// from it, for the documented reason that a second hand-maintained copy is the
// copy that refuses the release. This is the same job — "describe whatever
// generation this checkout declares" — so it derives too, rather than becoming
// the fifth copy. (tests/unit/cache-generation.spec.mjs CG-09 pins the Worker
// version BY HAND on purpose, so an unintended Worker bump has to be seen and
// justified by a human. Do not "fix" that one to match this one.)
const parityPath = path.join(REPO_ROOT, 'scripts', 'verify-cloudflare-parity.mjs');
let expectedWorkerVer = null;
try {
  expectedWorkerVer = declaredWorkerVersion(readFileSync(parityPath, 'utf8'));
} catch { /* reported below */ }

const workerSrc = readFileSync(path.join(REPO_ROOT, 'cloud-backup-worker.js'), 'utf8');
const srcWorkerVer = sourceWorkerVersion(workerSrc);

if (!expectedWorkerVer) {
  bad('could not read workerVersion from scripts/verify-cloudflare-parity.mjs — ' +
      'refusing to assert a Worker generation blind');
} else if (srcWorkerVer === expectedWorkerVer) {
  ok(`repository Worker source is v${srcWorkerVer}, matching the parity verifier`);
} else {
  bad(`repository Worker source reports v${srcWorkerVer ?? '?'} but the parity verifier ` +
      `expects v${expectedWorkerVer} — bump them together`);
}

// What makes the current generation the current generation. Probed, not
// asserted: if the rotation endpoint ever leaves the source, this line stops
// claiming it is there.
if (/\/rotate/.test(workerSrc) && /admin\/users/.test(workerSrc)) {
  ok('Worker source carries the in-place rotation endpoint (POST /admin/users/:id/rotate)');
} else {
  bad('Worker source does NOT carry POST /admin/users/:id/rotate — the generation ' +
      'described below is not the generation in this checkout');
}

console.log('');
note('  ', `CURRENT WORKER STATE (v${srcWorkerVer ?? '?'}):`);
note('     ',
  'Worker v15 was directly observed live on 2026-09-13: GET /health HTTP 200 reporting ' +
  'version 15, CORS echoing the exact production origin rather than `*`, backup preflight ' +
  'OPTIONS 204, and an unauthorized admin request denied 401. It carries v14\'s security ' +
  'contract — driver tokens stored only as a SHA-256 hash under `tokh:<hash>`, an ' +
  'HMAC timing-safe admin compare, GET /backup/delta, and canonical-absence projection ' +
  'instead of coercing UNAVAILABLE into REJECT/F/$0.00 — plus POST /admin/users/:id/rotate, ' +
  'which re-keys a driver in place instead of minting a new userId and orphaning that ' +
  'driver\'s entire backup history. Rotation also deletes any legacy v7 plaintext `token:` ' +
  'key immediately, which is what finishes the P-01/P-02 cleanup v14 only did lazily. ' +
  'Authenticated authority/backup smokes against this deployment are NOT RUN and remain a ' +
  'separate open gate.');
console.log('');
console.log('  !! THERE IS NO SAFE WORKER ROLLBACK TARGET.');
note('     ',
  'The only prior deployment of freightlogic-backup is v7 (read from the Cloudflare ' +
  'control plane on 2026-09-12; see AUDIT_REPORT.md P-01..P-07). v7 stores every driver ' +
  'bearer token in KV in PLAINTEXT and returns those tokens from GET /admin/users. ' +
  '`wrangler rollback` on this service is therefore a SECURITY REGRESSION, not a safety ' +
  'net, and it also reintroduces the live X-01 delta-loss defect and a Worker that owns ' +
  'verdict/grade in violation of the v24.0 authority rule. There is no intermediate ' +
  'target: v14 was deployed on 2026-09-13 and superseded by v15 the same generation, so ' +
  '"roll back one" and "roll back to v7" are the same action.');
console.log('');
note('     ',
  `APPROVED WORKER ROLLBACK POLICY: fix forward. If deployed v${srcWorkerVer ?? '15'} ` +
  'misbehaves, deploy a corrected next generation from source via ' +
  '.github/workflows/deploy-backup-worker.yml. Do not roll back to v7 under any ' +
  'circumstance short of a total outage, and if that ever happens, rotate every driver ' +
  'token immediately afterwards because the listing endpoint will have exposed them again.');

// ── 5. Verdict ──────────────────────────────────────────────────────────────
console.log('\n== B5 verdict ==\n');
if (failures) {
  console.log(`${failures} check(s) FAILED — the rollback procedure is NOT verified executable.\n`);
  process.exit(1);
}
console.log('Rollback procedure is VERIFIED EXECUTABLE, with named regressions.\n');
console.log('Approved targets, in order of preference:');
console.log('  1. FIX FORWARD (both components) — the default, and the approved policy.');
console.log('  2. App only, if required: roll forward-most first. a7b7259 (v24.0.8) costs');
console.log('     the pickup-feasibility gate and nothing else; every target behind it adds');
console.log('     the regressions printed above, cumulatively. Whichever is chosen, tell the');
console.log('     operator what it takes away BEFORE it lands — the cargo-fit and silent-');
console.log('     backup regressions are both invisible from inside the app.');
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
