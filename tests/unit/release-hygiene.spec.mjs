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
