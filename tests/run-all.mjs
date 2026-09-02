// Runs every spec file in this suite against a real headless Chromium
// instance of the app (Playwright) and prints an aggregate summary.
//
// Usage:  node tests/run-all.mjs
// (Requires the sibling node_modules/playwright symlink — see tests/README.md)

import { stopServer } from './lib/harness.mjs';
import { runSpec as unitPureFunctions } from './unit/pure-functions.spec.mjs';
import { runSpec as serviceWorkerShell } from './unit/service-worker-shell.spec.mjs';
import { runSpec as releaseHygiene } from './unit/release-hygiene.spec.mjs';
import { runSpec as laneGuard } from './unit/lane-guard.spec.mjs';
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
import { runSpec as m1DoctrineIntegrity } from './integration/m1-doctrine-integrity.spec.mjs';
import { runSpec as m2ExpenseFuelConcurrency } from './integration/m2-expense-fuel-concurrency.spec.mjs';
import { runSpec as m3ConfidenceEvidence } from './integration/m3-confidence-evidence.spec.mjs';
import { runSpec as m4LoadLifecycle } from './integration/m4-load-lifecycle.spec.mjs';
import { runSpec as m5OpportunityIngestion } from './integration/m5-opportunity-ingestion.spec.mjs';
import { runSpec as m6HistoricalImport } from './integration/m6-historical-import.spec.mjs';
// Issue #119 Batch A — release-integrity hotfix regressions
import { runSpec as batchAReleaseIntegrity } from './integration/batch-a-release-integrity.spec.mjs';
import { runSpec as m3RealEvidenceWiring } from './integration/m3-real-evidence-wiring.spec.mjs';
import { runSpec as batchBM6Reconciliation } from './integration/batch-b-m6-reconciliation.spec.mjs';
// v24.0.2 exact-candidate blockers 1-8
import { runSpec as blockersExactCandidate } from './integration/blockers-exact-candidate.spec.mjs';
import { runSpec as workerCanonicalAbsence } from './unit/worker-canonical-absence.spec.mjs';
import { runSpec as m7RunnerSemantics } from './unit/m7-runner-semantics.spec.mjs';
import { runSpec as liveAuthorityRunner } from './unit/live-authority-runner.spec.mjs';
import { runSpec as swUpdateHandshake } from './integration/sw-update-handshake.spec.mjs';
import { runSpec as diagnosticsInstallIdentity } from './integration/diagnostics-install-identity.spec.mjs';
import { runSpec as preV24Integrity } from './unit/pre-v24-integrity.spec.mjs';
import { runSpec as v24UnifiedDecision } from './unit/v24-unified-decision.spec.mjs';
import { runSpec as v24AuthorityBoundaries } from './integration/v24-authority-boundaries.spec.mjs';
import { runSpec as v24EconomicsBid } from './integration/v24-economics-bid.spec.mjs';

const specs = [
  unitPureFunctions,
  serviceWorkerShell,
  releaseHygiene,
  laneGuard,
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
  m1DoctrineIntegrity,
  m2ExpenseFuelConcurrency,
  m3ConfidenceEvidence,
  m4LoadLifecycle,
  m5OpportunityIngestion,
  m6HistoricalImport,
  batchAReleaseIntegrity,
  m3RealEvidenceWiring,
  batchBM6Reconciliation,
  blockersExactCandidate,
  workerCanonicalAbsence,
  m7RunnerSemantics,
  liveAuthorityRunner,
  swUpdateHandshake,
  diagnosticsInstallIdentity,
  preV24Integrity,
  v24UnifiedDecision,
  v24AuthorityBoundaries,
  v24EconomicsBid,
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
