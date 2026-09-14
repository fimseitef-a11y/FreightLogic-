// Rollback evidence generator (gate B5) — that it describes the CURRENT release
// and that its checks mean what they say. Static + pure + subprocess + a
// throwaway git fixture; no browser, no network.
//
// Why this exists. On 2026-09-14 the gpt lane found scripts/verify-rollback.mjs
// carrying `PRODUCTION_CANDIDATE = '8d5b82b8…'` (an obsolete candidate) and
// `if (srcWorkerVer === '14')` while the release had moved to v24.0.9 / Worker
// v15 (.agents/inbox/gpt-to-claude-v2409-rollback-verifier-2026-09-14.md).
// Neither literal was wrong when written. Both went stale in silence, and the
// second made the gate FAIL FOR THE WRONG REASON — reporting a Worker-generation
// mismatch that was really its own staleness. A release gate whose failures do
// not mean what they claim is worse than one that does not run.
//
// So the assertions here are not "the literals are correct now". They are "there
// are no literals to go stale", plus live proof that the gate's own checks can
// actually fail. That second half found two more defects while it was being
// written, both of which had been shipping as B5 evidence:
//
//   1. the revert-cleanliness check was VACUOUS — `merge-tree --write-tree
//      <parent> <HEAD>` lets git pick the merge base, and since parent is an
//      ancestor of HEAD that base IS parent, so the "merge" was a fast-forward
//      returning HEAD's own tree. It could not report a conflict, ever, and had
//      been printing "applies cleanly" as evidence;
//   2. a genuine conflict (merge-tree exit 1) was collapsed by `allowFail` into
//      the same null as a missing binary, and reported as "needs git >= 2.38".
//
// RBV-08 proves both against a purpose-built three-commit repository rather than
// against this one's history, so it is deterministic and survives CI's shallow
// checkout.
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { execFile, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';
import { REPO_ROOT } from '../../scripts/lib/deploy-assets.mjs';
import {
  CANDIDATE_AUTHORITIES,
  candidateShasInText,
  deriveCandidate,
  declaredWorkerVersion,
  sourceWorkerVersion,
} from '../../scripts/lib/release-candidate.mjs';

const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');
const { test, run } = createSuite('unit/rollback-verifier.spec.mjs');
const GATE = 'scripts/verify-rollback.mjs';

/** Source with comments removed, for checks that are about CODE.
 *
 *  This helper exists because both of these assertions failed on their first run
 *  against a correct gate: the header comment quotes the very defect it fixed
 *  (`=== '14'`), and the approved policy text names `wrangler rollback` in order
 *  to forbid it. A check that trips on the file's own explanation teaches the
 *  next author to delete the explanation, which is the opposite of what the
 *  check is for.
 *
 *  Line comments are stripped only where `//` starts the line, so a `https://`
 *  inside a prose string is not mistaken for one. */
function codeOnly(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

/** Run the gate and return its real exit code and output. Async for the same
 *  reason live-parity-runner.spec.mjs documents: the synchronous form blocks
 *  this process's event loop. */
function runGate(args = [], timeoutMs = 120000) {
  return new Promise(resolve => {
    execFile('node', [GATE, ...args],
      { cwd: REPO_ROOT, encoding: 'utf8', timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 },
      (err, stdout, stderr) => {
        resolve({ code: err ? (err.code ?? 1) : 0, out: `${stdout || ''}${stderr || ''}` });
      });
  });
}

/** Does this clone carry the history the gate needs? CI checks out with
 *  actions/checkout@v6 at its default depth of 1, so the answer there is no —
 *  and the gate failing closed in that clone is CORRECT behavior, which RBV-09
 *  asserts rather than skipping. */
function hasDeepHistory() {
  try {
    execFileSync('git', ['rev-parse', '--verify', '39882fa^{commit}'],
      { cwd: REPO_ROOT, stdio: 'ignore' });
    return true;
  } catch { return false; }
}

test('[RBV-01] the gate pins NO release candidate — the stale literal cannot come back', () => {
  const src = read(GATE);
  // A 40-hex literal in this file is a pinned candidate by definition: the four
  // historical rollback targets are named by short SHA, and the current
  // candidate is derived. This is the exact shape of the reported defect.
  const pinned = src.match(/\b[0-9a-f]{40}\b/g) || [];
  eq(pinned.length, 0,
    `the gate must not pin a full candidate SHA; found ${pinned.map(s => s.slice(0, 8)).join(', ')}. ` +
    'Derive it from the release authorities instead — a literal here is what made this ' +
    'gate describe an obsolete build.');
  ok(/deriveCandidate/.test(src), 'the gate must derive the candidate');
  ok(/release-candidate\.mjs/.test(src),
    'the gate must import the SHARED derivation, not keep its own copy — two copies ' +
    'drift and each reports green about the other\'s blind spot');
});

test('[RBV-02] the Worker generation is derived, never compared against a literal', () => {
  const src = codeOnly(read(GATE));
  // The precise defect was `if (srcWorkerVer === '14')`. Catch the SHAPE, not
  // the number: prose in this file legitimately names v7, v14 and v15.
  const literalCmp = src.match(/===\s*['"]\d+['"]/g) || [];
  eq(literalCmp.length, 0,
    `the gate must not compare a version against a literal; found ${literalCmp.join(', ')}. ` +
    'That is what made a stale expectation look like a Worker mismatch.');
  ok(/declaredWorkerVersion/.test(src) && /sourceWorkerVersion/.test(src),
    'the Worker expectation must come from the parity verifier\'s EXPECTED block and be ' +
    'compared against the shipped Worker source');
});

test('[RBV-03] parity verifier, Worker source and the gate agree on one generation', () => {
  const declared = declaredWorkerVersion(read('scripts/verify-cloudflare-parity.mjs'));
  const shipped = sourceWorkerVersion(read('cloud-backup-worker.js'));
  ok(declared !== null, 'scripts/verify-cloudflare-parity.mjs must declare a workerVersion');
  ok(shipped !== null, 'cloud-backup-worker.js must report a version from /health');
  eq(shipped, declared,
    `shipped Worker v${shipped} but the parity verifier expects v${declared} — bump them together`);
  // The deploy script derives from the same single declaration. If it ever goes
  // back to grepping its own literal, the v15 deploy refusal repeats.
  ok(/workerVersion/.test(read('scripts/deploy-backup-worker.sh')),
    'scripts/deploy-backup-worker.sh must keep deriving from the same declaration');
});

test('[RBV-04] the release authorities name exactly one runtime candidate, unanimously', () => {
  const { readings, agreed } = deriveCandidate();
  for (const r of readings) {
    ok(!r.missing, `${r.rel} is missing — it is a release authority and must exist`);
    eq(r.shas.length, 1,
      `${r.rel} must name exactly one runtime candidate, found ${r.shas.length}` +
      (r.shas.length ? `: ${r.shas.map(s => s.slice(0, 8)).join(', ')}` : ''));
  }
  eq(agreed.length, 1,
    `the release record must agree with itself; it names ${agreed.length} candidates ` +
    `(${agreed.map(s => s.slice(0, 8)).join(' vs ')})`);
  eq(CANDIDATE_AUTHORITIES.length, 3, 'three living authorities are corroborating each other');
});

test('[RBV-05] the proximity bound keeps the `main` head out of the candidate reading', () => {
  // The real COMPLETION_RELEASE_PLAN paragraph shape: markdown, so one paragraph
  // is one line, and that line names BOTH the runtime candidate and the
  // repository head. A line-wide match would read both and manufacture a
  // disagreement out of a document that is correct.
  const candidate = 'a'.repeat(40);
  const mainHead = 'b'.repeat(40);
  const para =
    `Exact runtime candidate \`${candidate}\` is FreightLogic v24.0.9. Read-only release ` +
    `tooling subsequently advanced repository \`main\` to \`${mainHead}\` (merged PR #180) ` +
    'without changing shipped runtime files.';
  const got = candidateShasInText(para);
  eq(got.length, 1, `exactly one SHA should be read from that paragraph, got ${got.length}`);
  eq(got[0], candidate, 'the labelled runtime candidate must win, not the repository head');

  // And the other labelled forms the authorities really use must all be read.
  for (const form of [
    `- exact runtime Git candidate: **\`${candidate}\`** (merged PR #175);`,
    `Current runtime candidate: \`${candidate}\` / FreightLogic **v24.0.9**`,
    `- Runtime Git SHA: \`${candidate}\` (merged PR #175).`,
    `Current runtime synchronization point: exact Git SHA \`${candidate}\`, **v24.0.9**`,
    `check attached to exact runtime merge SHA \`${candidate}\` completed successfully`,
  ]) {
    eq(candidateShasInText(form)[0], candidate, `this labelled form must be readable: ${form}`);
  }
});

test('[RBV-06] a contradictory release record is reported, never silently resolved', () => {
  const a = 'a'.repeat(40);
  const b = 'b'.repeat(40);
  const { agreed } = deriveCandidate({
    files: ['one.md', 'two.md'],
    read: (rel) => rel === 'one.md'
      ? `Current runtime candidate: \`${a}\``
      : `Current runtime candidate: \`${b}\``,
  });
  eq(agreed.length, 2,
    'two authorities naming different candidates must surface as a disagreement — picking ' +
    'one would silently certify a build nobody agreed on');

  // Nothing named at all must stay empty rather than falling back to a guess.
  const none = deriveCandidate({ files: ['x.md'], read: () => 'no candidate is named here' });
  eq(none.agreed.length, 0, 'an unlabelled document must yield no candidate');
  const gate = read(GATE);
  ok(/refusing to guess/.test(gate),
    'the gate must refuse to proceed when no authority names a candidate');
});

test('[RBV-07] every named regression carries a probe against the target\'s own bytes', () => {
  const src = read(GATE);
  const block = src.slice(src.indexOf('const APP_TARGETS'), src.indexOf('-- app rollback targets'));
  ok(block.length > 500, 'precondition: the APP_TARGETS block was located');

  const entries = [...block.matchAll(/\btext:\s*\n?\s*['`]/g)];
  ok(entries.length >= 5, `expected several named regressions, found ${entries.length}`);
  let probed = 0;
  for (const m of entries) {
    const tail = block.slice(m.index, m.index + 1800);
    const isConnective = /text:\s*'Everything above, AND:'/.test(tail.slice(0, 60));
    if (isConnective) continue;
    ok(/\bprobe:\s*\(/.test(tail.split(/\btext:\s*\n?\s*['`]/)[1] ?? tail),
      'each named regression must carry a probe — prose in a release artifact goes stale ' +
      'silently, which is the whole defect being fixed here');
    probed++;
  }
  ok(probed >= 4, `expected at least 4 probed regressions, found ${probed}`);
  ok(/is NOT confirmed by this SHA's bytes/.test(src),
    'a probe that stops matching must FAIL the gate, not be ignored');
});

test('[RBV-08] the revert check is a real three-way merge — the old form was vacuous', () => {
  const src = codeOnly(read(GATE));
  // Anchor this to the CALL, not to the file. The first version of this
  // assertion was `/--merge-base=/.test(src)` and it did not fire when the flag
  // was deleted from the invocation, because the gate's own comment and its
  // git-too-old warning both still contain the string. A negative control that
  // does not fire is the finding, not a formality.
  ok(/gitTry\(\[[^\]]*'merge-tree'[^\]]*--merge-base=/.test(src),
    'reverting X into HEAD is the three-way merge base=X, ours=HEAD, theirs=X^, and ' +
    '--merge-base must be passed to the merge-tree CALL. Without it git picks the base ' +
    'itself, the base IS the parent, and the check silently becomes a fast-forward that ' +
    'can never report a conflict.');
  ok(/mt\.status === 1/.test(src),
    'merge-tree exit 1 means CONFLICTS FOUND — a real answer that must be reported as a ' +
    'conflict, not collapsed into "your git is too old"');

  // Now prove it, on a repository built for the purpose. Three commits, each
  // touching the same line, so reverting the middle one genuinely conflicts.
  const dir = mkdtempSync(path.join(tmpdir(), 'fl-revert-'));
  const g = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim();
  const gStatus = (...args) => {
    try { execFileSync('git', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] }); return 0; }
    catch (e) { return typeof e.status === 'number' ? e.status : null; }
  };
  try {
    g('init', '-q', '-b', 'main');
    g('config', 'user.email', 't@example.invalid');
    g('config', 'user.name', 'test');
    const commit = (body, msg) => {
      writeFileSync(path.join(dir, 'x.txt'), body);
      g('add', 'x.txt');
      g('commit', '-q', '-m', msg);
      return g('rev-parse', 'HEAD');
    };
    const A = commit('one\n', 'A');
    const B = commit('two\n', 'B — the commit to revert');
    const C = commit('three\n', 'C — HEAD');

    // Guard: if this git cannot do --write-tree at all, say so instead of
    // passing on a command that never ran.
    if (gStatus('merge-tree', '--write-tree', A, C) === null) {
      ok(false, 'git merge-tree --write-tree is unavailable in this environment (needs >= 2.38)');
      return;
    }

    // The OLD form. merge-base(A, C) is A, so this is a fast-forward and the
    // tree it returns is C's own.
    const oldTree = g('merge-tree', '--write-tree', A, C);
    eq(oldTree, g('rev-parse', 'C^{tree}'.replace('C', C)),
      'the two-argument form returns HEAD\'s own tree — it is not a revert check at all');
    eq(gStatus('merge-tree', '--write-tree', A, C), 0,
      'and it reports success, which is the false green that shipped as B5 evidence');

    // The form the gate now uses. Same commits, real answer.
    eq(gStatus('merge-tree', '--write-tree', '--name-only', `--merge-base=${B}`, C, A), 1,
      'the three-way form must detect the conflict the old form could not see');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('[RBV-11] runtime drift inside one generation FAILS; a newer generation only warns', () => {
  // These are different facts and must not share an outcome.
  //
  // Drift while APP_VERSION stands still is the v24.0.3 defect: CACHE_NAME is
  // `freightlogic-${SW_VERSION}`, so an installed PWA has no new identity to
  // fetch and keeps serving the old shell. The change cannot reach a driver at
  // all. That is a release blocker.
  //
  // Drift with a HIGHER APP_VERSION is ordinary progress on an uncertified
  // line — the release documents are simply behind. Failing there would train
  // the next author to silence the check on a healthy repository, which is how
  // a gate stops being read.
  const src = codeOnly(read(GATE));
  const block = src.slice(src.indexOf('const drifted = []'), src.indexOf('} else {\n      bad('));
  ok(block.length > 400, 'precondition: the drift branch was located');
  ok(/candGen === headGen/.test(block),
    'the gate must compare the candidate and HEAD generations before deciding');
  const sameGen = block.slice(block.indexOf('candGen === headGen'));
  ok(/bad\(/.test(sameGen.slice(0, 900)),
    'drift within one generation must FAIL — the change cannot reach an installed PWA');
  ok(/warn\(/.test(sameGen),
    'drift across generations must only WARN — a stale release record is not a broken build');
  ok(/CACHE_NAME/.test(sameGen),
    'the same-generation failure must say WHY it is undeliverable, not just that it differs');
});

test('[RBV-09] the gate runs, and fails CLOSED when the clone lacks the history', async () => {
  const r = await runGate();
  if (hasDeepHistory()) {
    eq(r.code, 0, `the gate should pass against a full clone; got ${r.code}\n${r.out}`);
    ok(/all present authorities agree/.test(r.out),
      'the derived candidate must be reported in the evidence artifact');
    ok(/Worker source is v\d+, matching the parity verifier/.test(r.out),
      'the Worker generation must be reported as derived agreement, not a pinned expectation');
    ok(/FIX FORWARD \(both components\) — the default/.test(r.out),
      'fix-forward must remain the approved default policy');
    ok(/THERE IS NO SAFE WORKER ROLLBACK TARGET/.test(r.out) && /PLAINTEXT/.test(r.out),
      'v7 must stay explicitly unsafe as a rollback target');
  } else {
    // CI checks out shallow. The gate must then refuse, not invent evidence.
    eq(r.code, 1, 'in a shallow clone the gate must fail closed rather than report B5 evidence');
    ok(/is NOT in this clone|does not resolve/.test(r.out),
      'and it must say the history is missing, so the failure means what it claims');
  }
});

test('[RBV-10] the gate is read-only and says so about an override', async () => {
  const src = codeOnly(read(GATE));
  // Match git MUTATION verbs as invoked commands, not the words: the prose
  // deliberately discusses reverting and rolling back, and a check that trips on
  // its own explanation pushes the next author into deleting the explanation.
  for (const verb of ['checkout', 'revert', 'reset', 'push', 'commit', 'cherry-pick', 'apply']) {
    ok(!new RegExp(`git(?:Try)?\\(\\[\\s*['"]${verb}['"]`).test(src),
      `the gate must never invoke \`git ${verb}\` — it generates evidence, it does not roll back`);
  }
  // Stronger than forbidding named verbs: the only binary this gate may run at
  // all is git. That covers `wrangler deploy`, a shell, and anything invented
  // later, without matching the policy text that names `wrangler rollback` in
  // order to forbid it.
  const spawned = [...src.matchAll(/execFileSync\(\s*['"]([^'"]+)['"]/g)].map(m => m[1]);
  ok(spawned.length > 0, 'precondition: the gate does spawn something');
  for (const bin of spawned) {
    eq(bin, 'git', `the gate may only ever run git; it runs "${bin}"`);
  }
  for (const forbidden of ['spawnSync', 'execSync', 'spawn(']) {
    ok(!src.includes(forbidden),
      `the gate must not use ${forbidden} — one reviewed spawn path, not several`);
  }
  ok(/--write-tree/.test(src), 'the revert check must stay in-memory');

  if (!hasDeepHistory()) return; // the override path needs a resolvable SHA
  const other = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
  const r = await runGate([`--candidate=${other}`]);
  ok(/the override differs from what the release authorities name/.test(r.out) ||
     /explicit --candidate override/.test(r.out),
    'an explicit override must be reported as an override, so the artifact is never filed ' +
    `as evidence about the certified candidate when it is not\n${r.out}`);
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
