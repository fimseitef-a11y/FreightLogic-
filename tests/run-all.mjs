// Runs every spec file in this suite against a real headless Chromium
// instance of the app (Playwright) and prints an aggregate summary.
//
// Usage:  node tests/run-all.mjs
// (Requires the sibling node_modules/playwright symlink — see tests/README.md)

import { stopServer } from './lib/harness.mjs';
import { runSpec as unitPureFunctions } from './unit/pure-functions.spec.mjs';
import { runSpec as dzGradeCap } from './integration/dz-exit-grade-cap.spec.mjs';
import { runSpec as taxCsvCorruption } from './integration/tax-export-csv-corruption.spec.mjs';
import { runSpec as pinLockout } from './integration/pin-lockout.spec.mjs';
import { runSpec as flTestsExposure } from './integration/fl-tests-exposure.spec.mjs';
import { runSpec as toctouEdit } from './integration/toctou-concurrent-edit.spec.mjs';
import { runSpec as fieldResilience } from './integration/field-resilience.spec.mjs';

const specs = [
  unitPureFunctions,
  dzGradeCap,
  taxCsvCorruption,
  pinLockout,
  flTestsExposure,
  toctouEdit,
  fieldResilience,
];

const results = [];
for (const runSpecFn of specs) {
  results.push(await runSpecFn());
}
await stopServer();

const totalPass = results.reduce((s, r) => s + r.pass, 0);
const totalFail = results.reduce((s, r) => s + r.fail, 0);
console.log('\n' + '='.repeat(60));
console.log(`TOTAL: ${totalPass} passed, ${totalFail} failed across ${results.length} spec files`);
console.log('='.repeat(60));
const failing = results.flatMap(r => r.failures.map(f => `${r.file} :: ${f.name}`));
if (failing.length) {
  console.log('\nFailing (each documents a specific finding in AUDIT_REPORT.md):');
  for (const f of failing) console.log('  - ' + f);
}
process.exit(0); // non-zero would be wrong here: several specs are EXPECTED to fail (they prove bugs)
