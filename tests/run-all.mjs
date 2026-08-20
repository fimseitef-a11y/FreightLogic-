// Runs every spec file in this suite against a real headless Chromium
// instance of the app (Playwright) and prints an aggregate summary.
//
// Usage:  node tests/run-all.mjs
// (Requires the sibling node_modules/playwright symlink — see tests/README.md)

import { stopServer } from './lib/harness.mjs';
import { runSpec as unitPureFunctions } from './unit/pure-functions.spec.mjs';
import { runSpec as serviceWorkerShell } from './unit/service-worker-shell.spec.mjs';
import { runSpec as releaseHygiene } from './unit/release-hygiene.spec.mjs';
import { runSpec as dzGradeCap } from './integration/dz-exit-grade-cap.spec.mjs';
import { runSpec as taxCsvCorruption } from './integration/tax-export-csv-corruption.spec.mjs';
import { runSpec as pinLockout } from './integration/pin-lockout.spec.mjs';
import { runSpec as flTestsExposure } from './integration/fl-tests-exposure.spec.mjs';
import { runSpec as toctouEdit } from './integration/toctou-concurrent-edit.spec.mjs';
import { runSpec as fieldResilience } from './integration/field-resilience.spec.mjs';
import { runSpec as insuranceMigration } from './integration/insurance-migration.spec.mjs';
import { runSpec as exportChecksumIntegrity } from './integration/export-checksum-integrity.spec.mjs';
import { runSpec as backupRestoreParity } from './integration/backup-restore-parity.spec.mjs';
import { runSpec as dzGateParity } from './integration/dz-gate-parity.spec.mjs';
import { runSpec as xlsxBundledVendor } from './integration/xlsx-bundled-vendor.spec.mjs';
import { runSpec as vanFitPrecheck } from './integration/van-fit-precheck.spec.mjs';
import { runSpec as healthBadge } from './integration/health-badge.spec.mjs';

const specs = [
  unitPureFunctions,
  serviceWorkerShell,
  releaseHygiene,
  dzGradeCap,
  taxCsvCorruption,
  pinLockout,
  flTestsExposure,
  toctouEdit,
  fieldResilience,
  insuranceMigration,
  exportChecksumIntegrity,
  backupRestoreParity,
  dzGateParity,
  xlsxBundledVendor,
  vanFitPrecheck,
  healthBadge,
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
  console.log('\nFailing:');
  for (const f of failing) console.log('  - ' + f);
}
// X-06 (v23.9 Phase 2): every finding this suite covers is now FIXED (see
// AUDIT_REPORT.md) — there is no longer a legitimate reason for a spec in
// this suite to fail, so the aggregate exit code is a real signal CI can
// gate on. A prior version of this file always exited 0 on the reasoning
// that several specs were EXPECTED to fail (they proved still-open bugs);
// that reasoning no longer holds now that this suite only ships fixes with
// passing assertions — see tests/README.md's "Exit code" section.
process.exit(totalFail ? 1 : 0);
