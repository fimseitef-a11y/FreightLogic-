// Runs every spec file in this suite against a real headless Chromium
// instance of the app (Playwright) and prints an aggregate summary.
//
// Usage:  node tests/run-all.mjs
// (Requires the sibling node_modules/playwright symlink — see tests/README.md)

import { cpus, tmpdir } from 'node:os';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { stopServer, SPEC_CTX } from './lib/harness.mjs';
import { runSpec as unitPureFunctions } from './unit/pure-functions.spec.mjs';
import { runSpec as serviceWorkerShell } from './unit/service-worker-shell.spec.mjs';
import { runSpec as releaseHygiene } from './unit/release-hygiene.spec.mjs';
// Issue #224 — suite readiness contract + lifecycle diagnostics
import { runSpec as harnessReadiness } from './unit/harness-readiness.spec.mjs';
import { runSpec as cacheGeneration } from './unit/cache-generation.spec.mjs';
import { runSpec as deployAssetCoverage } from './unit/deploy-asset-coverage.spec.mjs';
import { runSpec as liveParityRunner } from './unit/live-parity-runner.spec.mjs';
import { runSpec as legacyTokenAudit } from './unit/legacy-token-audit.spec.mjs';
import { runSpec as productionSwGate } from './unit/production-sw-gate.spec.mjs';
import { runSpec as workflowAuthority } from './unit/workflow-authority.spec.mjs';
import { runSpec as rollbackVerifierCurrent } from './unit/rollback-verifier-current.spec.mjs';
import { runSpec as swSubresourceSemantics } from './integration/sw-subresource-semantics.spec.mjs';
import { runSpec as v2404FailClosed } from './integration/v2404-fail-closed.spec.mjs';
import { runSpec as modernShellRouting } from './integration/modern-shell-routing.spec.mjs';
import { runSpec as sixWidthLayout } from './integration/six-width-layout.spec.mjs';
import { runSpec as appleIosAccessibility } from './integration/apple-ios-accessibility.spec.mjs';
import { runSpec as cloudBackupPaused } from './integration/cloud-backup-paused.spec.mjs';
import { runSpec as workerTokenRotation } from './unit/worker-token-rotation.spec.mjs';
import { runSpec as workerPointerRace } from './unit/worker-pointer-race.spec.mjs';
// Issue #221 — canonical-user token authority (Worker v20)
import { runSpec as workerTokenAuthority } from './unit/worker-token-authority.spec.mjs';
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
import { runSpec as pickupFeasibility } from './integration/pickup-feasibility.spec.mjs';
import { runSpec as positionAuthority } from './integration/position-authority.spec.mjs';
// Issue #205 — driver-first UX/IA restructure of Today and More
import { runSpec as todayIA } from './integration/today-ia.spec.mjs';
import { runSpec as screenshotIntake } from './integration/screenshot-intake.spec.mjs';
// Issue #219 — untrusted-import credential trust boundary
import { runSpec as importCredentialTrustBoundary } from './integration/import-credential-trust-boundary.spec.mjs';
// Issue #220 — self-hosted-only executable code
import { runSpec as ocrSelfHosted } from './integration/ocr-self-hosted.spec.mjs';
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
import { runSpec as mergeRestoreConcurrency } from './integration/merge-restore-concurrency.spec.mjs';
import { runSpec as sameMillisecondConcurrency } from './integration/same-millisecond-concurrency.spec.mjs';
import { runSpec as preV24Integrity } from './unit/pre-v24-integrity.spec.mjs';
import { runSpec as v24UnifiedDecision } from './unit/v24-unified-decision.spec.mjs';
import { runSpec as v24AuthorityBoundaries } from './integration/v24-authority-boundaries.spec.mjs';
import { runSpec as v24EconomicsBid } from './integration/v24-economics-bid.spec.mjs';
import { runSpec as economicsAuthorityRefresh } from './integration/economics-authority-refresh.spec.mjs';
import { runSpec as deactivatedOutcome } from './integration/deactivated-outcome.spec.mjs';
import { runSpec as rateBasisSettlement } from './integration/rate-basis-settlement.spec.mjs';

import { runSpec as omegaEconomics } from './integration/omega-economics.spec.mjs';
import { runSpec as releaseGenerationDiscipline } from './unit/release-generation-discipline.spec.mjs';
import { runSpec as fullRepairRegressions } from './integration/full-repair-regressions.spec.mjs';
import { runSpec as workerInviteClaim } from './unit/worker-invite-claim.spec.mjs';
import { runSpec as workerVisionExtract } from './unit/worker-vision-extract.spec.mjs';
import { runSpec as visionBenchmark } from './unit/vision-benchmark.spec.mjs';
import { runSpec as liveInviteClaimGate } from './unit/live-invite-claim-gate.spec.mjs';
import { runSpec as vehicleProfileRace } from './integration/vehicle-profile-race.spec.mjs';
import { runSpec as zeroTokenOnboarding } from './integration/zero-token-onboarding.spec.mjs';
import { runSpec as fieldCertificationRunner } from './integration/field-certification-runner.spec.mjs';
import { runSpec as adminConsole } from './integration/admin-console.spec.mjs';
import { runSpec as driverGlancePreferences } from './integration/driver-glance-preferences.spec.mjs';
import { runSpec as tripDeleteSafety } from './integration/trip-delete-safety.spec.mjs';
import { runSpec as workerWebPush } from './unit/worker-web-push.spec.mjs';
import { runSpec as swPush } from './unit/sw-push.spec.mjs';
import { runSpec as shortcutsDeepLinks } from './integration/shortcuts-deep-links.spec.mjs';
import { runSpec as nextMoveS1 } from './integration/next-move-s1.spec.mjs';
import { runSpec as nextMoveS2 } from './integration/next-move-s2.spec.mjs';
import { runSpec as nextMoveS3 } from './integration/next-move-s3.spec.mjs';
import { runSpec as loadTextParse } from './integration/load-text-parse.spec.mjs';

const specs = [
  fullRepairRegressions,
  omegaEconomics,
  releaseGenerationDiscipline,
  unitPureFunctions,
  serviceWorkerShell,
  releaseHygiene,
  harnessReadiness,
  cacheGeneration,
  deployAssetCoverage,
  liveParityRunner,
  legacyTokenAudit,
  productionSwGate,
  workflowAuthority,
  rollbackVerifierCurrent,
  swSubresourceSemantics,
  v2404FailClosed,
  modernShellRouting,
  sixWidthLayout,
  appleIosAccessibility,
  cloudBackupPaused,
  workerTokenRotation,
  workerPointerRace,
  workerTokenAuthority,
  workerInviteClaim,
  workerVisionExtract,
  workerWebPush,
  swPush,
  visionBenchmark,
  liveInviteClaimGate,
  vehicleProfileRace,
  zeroTokenOnboarding,
  fieldCertificationRunner,
  adminConsole,
  driverGlancePreferences,
  tripDeleteSafety,
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
  pickupFeasibility,
  positionAuthority,
  todayIA,
  screenshotIntake,
  shortcutsDeepLinks,
  nextMoveS1,
  nextMoveS2,
  nextMoveS3,
  loadTextParse,
  importCredentialTrustBoundary,
  ocrSelfHosted,
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
  mergeRestoreConcurrency,
  sameMillisecondConcurrency,
  preV24Integrity,
  v24UnifiedDecision,
  v24AuthorityBoundaries,
  v24EconomicsBid,
  economicsAuthorityRefresh,
  deactivatedOutcome,
  rateBasisSettlement,
];

/* ────────────────────────────────────────────────────────────────────────────
   Execution: a bounded worker pool, not a for-loop.

   MEASURED before changing anything, because the obvious suspect was wrong.
   Chromium launch costs ~300ms per spec (launch 120ms + context/page 100ms +
   close 80ms) — about 15s of a 470s suite, 3%. Pooling browsers would have
   bought almost nothing. The time is inside the specs: real app boots, real
   reloads, and ~136s of deliberate fixed sleeps. That work is overwhelmingly
   I/O- and browser-bound, so it parallelises well on this 4-core host.

   Nothing about any assertion changes. Each spec still launches its own
   browser, so its IndexedDB, Cache Storage and sessionStorage stay isolated
   exactly as before; the only shared thing is the static file server, which
   `ensureServer()` already makes a singleton and which only reads from disk.

   Set FL_TEST_CONCURRENCY=1 to restore the previous strictly-sequential run —
   worth doing when debugging a failure, since serial output is live rather
   than buffered.
   ──────────────────────────────────────────────────────────────────────────── */

const CONCURRENCY = Math.max(1, Number(process.env.FL_TEST_CONCURRENCY ?? Math.min(4, cpus().length || 4)));

/* Longest-first scheduling. With 74 tasks over N workers the makespan is
   dominated by whatever starts last, so a 55s spec picked up at the end adds
   55s to the whole run. Durations are remembered between runs in the OS temp
   dir — deliberately NOT in the repository, so there is no gitignore change,
   no churning tracked file, and no committed number that can go stale and be
   mistaken for a contract. A cold cache (CI) simply runs in declaration order,
   which still parallelises; it just schedules the tail less well. */
const TIMINGS_FILE = path.join(
  tmpdir(),
  `fl-spec-timings-${createHash('sha256').update(fileURLToPath(import.meta.url)).digest('hex').slice(0, 12)}.json`,
);
let timings = {};
try { timings = JSON.parse(readFileSync(TIMINGS_FILE, 'utf8')); } catch (_) { timings = {}; }

const queue = specs.map((fn, i) => ({ fn, i, key: fn.name || `spec_${i}` }));
if (CONCURRENCY > 1) {
  // Unknown duration sorts FIRST: a spec nobody has timed might be the long
  // one, and starting it early is the cheap side of that bet.
  queue.sort((a, b) => (timings[b.key] ?? Infinity) - (timings[a.key] ?? Infinity));
}

/* Output. Concurrent specs writing to one stdout produce an unreadable braid,
   so each spec's lines are captured and flushed as one block when it finishes.
   Attribution rides the AsyncLocalStorage context rather than a global flag,
   which is what makes it correct across awaits. Anything logged with no
   context (a stray listener, a library) passes straight through rather than
   being swallowed — losing a line would be worse than printing it out of
   order. */
const realLog = console.log;
const realErr = console.error;
if (CONCURRENCY > 1) {
  const sink = (fallback) => (...args) => {
    const store = SPEC_CTX.getStore();
    if (store) store.out.push(args);
    else fallback(...args);
  };
  console.log = sink(realLog);
  console.error = sink(realErr);
}

const results = new Array(specs.length);
let cursor = 0;
let done = 0;

async function worker() {
  for (;;) {
    const job = queue[cursor++];
    if (!job) return;
    const store = { label: job.key, out: [] };
    const started = Date.now();
    let r;
    try {
      r = await SPEC_CTX.run(store, () => job.fn());
    } catch (e) {
      // A spec that throws outside its own assertions would otherwise vanish
      // from the totals and the run would exit 0 having tested less than it
      // reported. Surface it as a failure.
      r = { file: job.key, pass: 0, fail: 1, failures: [{ name: `runSpec threw: ${String(e && e.message || e)}` }] };
    }
    timings[job.key] = Date.now() - started;
    results[job.i] = r;
    done++;
    if (CONCURRENCY > 1) {
      for (const args of store.out) realLog(...args);
      realLog(`  [${String(done).padStart(2)}/${specs.length}] ${r.file} — ${((Date.now() - started) / 1000).toFixed(1)}s`);
    }
  }
}

await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));

console.log = realLog;
console.error = realErr;
try { writeFileSync(TIMINGS_FILE, JSON.stringify(timings)); } catch (_) {}

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