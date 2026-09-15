// SC — every spec on disk actually runs, and a quarantined one is self-closing.
//
// Why this exists. `tests/run-all.mjs` enumerates specs through an explicit
// import list and an explicit `specs` array. Nothing compared either of them to
// what is on disk. A spec file could therefore be added and never run — green
// forever, asserting nothing — which is the exact failure this suite has already
// shipped twice: v24.0.8's dead Loads tab was green because no spec touched the
// shell, and v24.0.12's OI-11 passed with the defect reinstated. A spec nobody
// runs is the same defect one level up.
//
// It also gives the ONE legitimate exception a shape. `tests/README.md` says a
// logged-but-not-yet-fixed finding's spec "should either be excluded from
// run-all.mjs's default run or clearly isolated so it doesn't sink an otherwise
// green CI gate" — and that is real: such a spec asserts the CORRECT behaviour
// and therefore fails until the fix lands. But nothing made an exclusion
// temporary, so a quarantined spec could sit unrun forever and the finding be
// forgotten. QUARANTINE below is that exception, and SC-02/SC-04 are what stop
// it becoming permanent.
//
// Cost note: SC-04 spawns the quarantined spec as a real subprocess, which
// launches Chromium. That is deliberate and it is the only assertion here that
// cannot be satisfied by editing a list — see its own comment.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';
import { REPO_ROOT } from '../../scripts/lib/deploy-assets.mjs';

const { test, run } = createSuite('unit/spec-coverage.spec.mjs');
const read = (rel) => readFileSync(path.join(REPO_ROOT, rel), 'utf8');

// A spec may be absent from run-all.mjs ONLY while the defect it proves is an
// OPEN finding in AUDIT_REPORT.md. Adding a row here is not a way to silence a
// failing test: SC-02 requires the finding to be real and still open, and SC-04
// requires the spec to actually fail. Fix the defect, wire the spec into
// run-all.mjs, mark the finding FIXED, and delete the row — in one commit.
const QUARANTINE = [
  {
    spec: 'integration/trip-row-unknown-deadhead.spec.mjs',
    finding: 'D-01',
    why: 'asserts the correct UNKNOWN-deadhead behaviour in tripRow(); app.js is SHARED and was under the gpt lane lock/app-js when the finding was captured',
  },
];

function specsOnDisk(){
  const out = [];
  for (const dir of ['unit', 'integration']){
    for (const f of readdirSync(path.join(REPO_ROOT, 'tests', dir)).sort()){
      if (f.endsWith('.spec.mjs')) out.push(`${dir}/${f}`);
    }
  }
  return out;
}

function parseRunAll(){
  const src = read('tests/run-all.mjs');
  const imports = new Map(); // identifier -> relative spec path
  for (const m of src.matchAll(/import\s*\{\s*runSpec\s+as\s+(\w+)\s*\}\s*from\s*'\.\/(.+?\.spec\.mjs)'/g)){
    imports.set(m[1], m[2]);
  }
  const block = src.match(/const\s+specs\s*=\s*\[([\s\S]*?)\]/);
  ok(block, 'run-all.mjs must declare a `const specs = [...]` array');
  const listed = block[1]
    .split('\n')
    .map(l => l.replace(/\/\/.*$/, '').trim().replace(/,$/, ''))
    .filter(Boolean);
  return { imports, listed };
}

test('[SC-01] every spec file on disk is wired into run-all.mjs, or explicitly quarantined', () => {
  const { imports, listed } = parseRunAll();
  // Deliberately not named `run`: that is the suite runner from createSuite(),
  // and shadowing it inside a test is a trap for whoever edits this next.
  const wired = new Set([...imports.entries()].filter(([id]) => listed.includes(id)).map(([, rel]) => rel));
  const quarantined = new Set(QUARANTINE.map(q => q.spec));
  const orphans = specsOnDisk().filter(rel => !wired.has(rel) && !quarantined.has(rel));
  eq(orphans.join(', '), '',
    'a spec file that no runner imports and lists is never executed — wire it into tests/run-all.mjs, or quarantine it here with its OPEN finding');
  for (const q of quarantined){
    ok(!wired.has(q), `${q} is quarantined AND wired into run-all.mjs — remove the QUARANTINE row, it is running`);
  }
});

test('[SC-02] a quarantine row names a finding AUDIT_REPORT.md still marks OPEN', () => {
  const audit = read('AUDIT_REPORT.md');
  for (const q of QUARANTINE){
    ok(existsSync(path.join(REPO_ROOT, 'tests', q.spec)), `${q.spec} is quarantined but does not exist — delete the row`);
    ok(q.why && q.why.length > 20, `${q.spec}: a quarantine row must say why, in prose`);
    const heading = audit.split('\n').find(l => l.startsWith('#') && new RegExp(`\\b${q.finding}\\b`).test(l));
    ok(heading, `${q.spec}: quarantine names finding ${q.finding}, which has no heading in AUDIT_REPORT.md — a quarantine without a recorded finding is an unrun test with an excuse`);
    ok(/\bOPEN\b/.test(heading) && !/\b(FIXED|CLOSED)\b/.test(heading),
      `${q.finding} is no longer OPEN in AUDIT_REPORT.md (${heading.trim()}) — wire ${q.spec} into run-all.mjs and delete its QUARANTINE row`);
  }
});

test('[SC-03] run-all.mjs imports and its specs array agree exactly', () => {
  const { imports, listed } = parseRunAll();
  // An imported-but-unlisted spec is the silent half of the same defect: the
  // file is referenced, so a coverage grep finds it, but it never executes.
  const unlisted = [...imports.entries()].filter(([id]) => !listed.includes(id)).map(([id, rel]) => `${id} (${rel})`);
  eq(unlisted.join(', '), '', 'imported but absent from the specs array — it never runs');
  const unimported = listed.filter(id => !imports.has(id));
  eq(unimported.join(', '), '', 'listed in the specs array but never imported as a runSpec');
  eq(listed.length, new Set(listed).size, 'a spec listed twice runs twice and double-counts its assertions');
});

test('[SC-04] a quarantined spec must actually FAIL — a passing one is fixed, or vacuous', async () => {
  // This is the assertion that makes a quarantine temporary rather than
  // permanent. SC-01/SC-02 can both be satisfied by editing text; this one
  // cannot. If the spec now passes, either the defect was fixed (wire it in) or
  // the spec asserts nothing (a green test guarding a live defect is exactly
  // what this suite exists to catch — see v24.0.12's OI-11).
  for (const q of QUARANTINE){
    const { code } = await new Promise(resolve => {
      execFile('node', [path.join('tests', q.spec)],
        { cwd: REPO_ROOT, encoding: 'utf8', timeout: 180000 },
        (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, out: `${stdout || ''}${stderr || ''}` }));
    });
    ok(code === 1,
      `${q.spec} exited ${code}; a quarantined spec must exit 1 (its finding ${q.finding} is still open). If it now passes, fix is landed: wire it into run-all.mjs, mark ${q.finding} FIXED, and drop its QUARANTINE row.`);
  }
});

export async function runSpec(){ return run(); }
if (process.argv[1]?.endsWith('spec-coverage.spec.mjs')){ const r = await runSpec(); process.exit(r.fail ? 1 : 0); }
