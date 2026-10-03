import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createSuite, ok, eq } from '../lib/harness.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');
const { test, run } = createSuite('unit/hyperdrive-binding.spec.mjs');

function configText() { return read('scripts/wrangler.backup-worker.jsonc'); }

test('[HD-01] backup Worker binds FREIGHTLOGIC_DB to the existing Hyperdrive resource', () => {
  const src = configText();
  ok(/"hyperdrive"\s*:\s*\[/.test(src), 'backup Worker config must declare a hyperdrive binding');
  ok(/"binding"\s*:\s*"FREIGHTLOGIC_DB"/.test(src), 'binding must be named FREIGHTLOGIC_DB');
  ok(/"id"\s*:\s*"e6926e014c0a4bb6b4e59bb9fea51674"/.test(src),
    'binding must reuse the verified existing Hyperdrive resource id');
});

test('[HD-02] binding change preserves existing production bindings', () => {
  const src = configText();
  for (const marker of ['"binding": "AI"', '"binding": "RATE_LIMITER"', '"binding": "AGENT"', '"binding": "BACKUPS"']) {
    ok(src.includes(marker), `existing binding missing after Hyperdrive integration: ${marker}`);
  }
});

test('[HD-03] repository config never embeds database credentials or local connection strings', () => {
  const src = configText();
  ok(!/localConnectionString/i.test(src), 'localConnectionString must not be committed');
  ok(!/postgres(?:ql)?:\/\//i.test(src), 'database connection strings must not be committed');
  ok(!/freightlogic_hyperdrive\s*[:@]/i.test(src), 'database login secret material must not be committed');
});

test('[HD-04] Hyperdrive binding is configuration-only until an explicit tested query path exists', () => {
  const worker = read('cloud-backup-worker.js');
  ok(!/FREIGHTLOGIC_DB/.test(worker),
    'do not add untested database query behavior as part of the binding-only slice');
});

export async function runSpec() { return run(); }
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const r = await runSpec();
  if (r.fail) process.exitCode = 1;
}
