// X-09 + X-11 (v23.9 Phase 6) — static source checks, no browser needed.
import { readFileSync } from 'node:fs';
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
