// X-09 + X-11 (v23.9 Phase 6) — static source checks, no browser needed.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const appJs = () => readFileSync(path.join(REPO_ROOT, 'app.js'), 'utf8');

const { test, run } = createSuite('unit/release-hygiene.spec.mjs');

test('[X-09] the diagnostics Worker-reachability self-test no longer sends a fake "ping" token', () => {
  const text = appJs();
  ok(!/'X-Backup-Token'\s*:\s*'ping'/.test(text), 'a hardcoded, always-invalid "ping" X-Backup-Token must not be sent — it always 403s regardless of actual reachability');
  // The fix reads the real configured token and only pings when one exists.
  const fnMatch = text.match(/\/\/ AI\/Worker endpoint ping[\s\S]*?\n    }\n  }/);
  ok(fnMatch, 'could not locate the diagnostics AI/Worker endpoint ping block to verify the fix');
  ok(fnMatch[0].includes("getSetting('cloudBackupToken'"), 'diagnostics ping must use the real configured cloudBackupToken');
});

/* ── a spec nothing calls is not a gate ──────────────────────────────────────
 *
 * `tests/unit/live-invite-claim-gate.spec.mjs` (13 assertions) landed and was
 * registered in `tests/run-all.mjs` NOWHERE, because that file sat behind a
 * lane exception at the time. It sat unregistered across two merges to `main`
 * and a full CI run, all green, while the thing it guards — the only flow in
 * this app that mints a credential — had no coverage in the gate at all.
 *
 * This repository already holds the identical finding twice: DAC-04, where the
 * parity gate imported the shared asset sweep but had to be proved to actually
 * CALL it, and OI-11, where a spec could not fail on the defect it guarded.
 * The counting is the whole check — `run-all.mjs` prints a spec-file total that
 * reads as coverage, and an unregistered spec silently shrinks it.
 *
 * Deliberately a DIRECTORY SCAN rather than a maintained list: a list has the
 * same failure mode as the thing it is checking. */
test('[RH-01] every spec file on disk is registered in run-all.mjs', () => {
  const runAll = readFileSync(path.join(REPO_ROOT, 'tests/run-all.mjs'), 'utf8');
  const missing = [];
  for (const dir of ['unit', 'integration']) {
    for (const f of readdirSync(path.join(REPO_ROOT, 'tests', dir)).sort()) {
      if (!f.endsWith('.spec.mjs')) continue;
      const rel = `./${dir}/${f}`;
      // Both halves are required. An import with no entry in `specs` never
      // runs, and an entry with no import will not even parse.
      const imported = runAll.includes(`from '${rel}'`);
      const ident = (runAll.match(new RegExp(`runSpec as (\\w+) \\} from '${rel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`)) || [])[1];
      const called = !!ident && new RegExp(`^\\s*${ident},\\s*$`, 'm').test(runAll);
      if (!imported || !called) missing.push(`${rel}${imported ? ' (imported, never in the specs array)' : ''}`);
    }
  }
  eq(missing.join(', '), '', `every spec must be imported AND listed in the specs array — unregistered: ${missing.join(', ')}`);
});

/* ── a negative control left in the tree is a deleted fix ────────────────────
 *
 * PR #213 merged `zero-token-onboarding.spec.mjs` with the body of
 * `claimWizardReady()` replaced by `/* NEGATIVE CONTROL: focus wait removed *​/`.
 * The control had been run deliberately — remove the repair, watch 2/10 runs
 * fail under load, put it back — and the command that put it back died before it
 * ran, on a `pkill` pattern that matched its own shell.
 *
 * It then survived two verifications. `grep -c claimWizardReady` counts an
 * IDENTIFIER and returns the same number whether the body is there or not, and
 * re-running the spec unloaded passes either way, because unloaded is precisely
 * the condition under which that race does not fire. So a merged, documented,
 * "verified" fix was an empty function for a day, and the defect it was supposed
 * to close kept failing CI.
 *
 * Running negative controls is the right practice and this must not discourage
 * it. The cheap structural guard is simply: the marker never reaches `main`. */
test('[RH-02] no spec file carries leftover negative-control scaffolding', () => {
  const offenders = [];
  for (const dir of ['unit', 'integration']) {
    for (const f of readdirSync(path.join(REPO_ROOT, 'tests', dir))) {
      if (!f.endsWith('.spec.mjs')) continue;
      const src = readFileSync(path.join(REPO_ROOT, 'tests', dir, f), 'utf8');
      // The marker as an ACTIVE comment line. Prose that merely discusses
      // negative controls — this very block, and several spec headers that
      // explain which control fires — must not trip it, or the guard gets
      // deleted the first time it cries wolf on its own documentation.
      for (const line of src.split('\n')) {
        if (/^\s*(\/\/|\/\*)\s*NEGATIVE CONTROL\b/i.test(line)) offenders.push(`${dir}/${f}: ${line.trim()}`);
      }
    }
  }
  eq(offenders.join(' | '), '',
    `a negative-control edit was left in a spec — the repair it removed is missing: ${offenders.join(' | ')}`);
});

test('[X-11] the Universal Import UI no longer claims PDF import "uses OCR"', () => {
  const text = appJs();
  ok(!text.includes('Rate confirmation (PDF) — uses OCR'), 'the dead PDF-OCR button label must be removed — importPDFFile() is an unconditional stub');
  ok(!text.includes('PDF: extracts text via OCR and prefills a trip'), 'the misleading OCR hint text must be removed');
  // The stub itself is untouched — this is a UI-honesty fix, not a new feature.
  const stubMatch = text.match(/async function importPDFFile\(file\)\{[\s\S]*?\n\}/);
  ok(stubMatch, 'could not find importPDFFile()');
  ok(stubMatch[0].includes('not supported'), 'importPDFFile() must still honestly report itself as unsupported');
});

export async function runSpec() {
  return await run();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await runSpec();
  process.exit(r.fail > 0 ? 1 : 0);
}
