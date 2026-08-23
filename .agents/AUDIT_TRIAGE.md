# FreightLogic Audit Triage — current `main`

Triaged against `main` at `0835d06c4415929b24d5684430b957412b026612` on 2026-08-22/23 UTC boundary. Historical labels in `AUDIT_REPORT.md` were treated as claims, not proof. A finding is FIXED/SUPERSEDED only where current source still contains the relevant protection or the v24 architecture removed the old authority path.

## Counts

### Formal numbered findings (21)
- FIXED: 18
- SUPERSEDED: 2
- OPEN: 1
- NEEDS-REVALIDATION: 0

### Residual audit limitations (not part of the 21 numbered findings)
- OPEN implementation-risk follow-up: 1 (`R-TOCTOU-EXPENSE-FUEL`)
- NEEDS-REVALIDATION field/live/usability gaps: 6

## Formal findings

### F-1 — Dead Zone Exit grade cap
STATUS: **SUPERSEDED**

EVIDENCE-SOURCE: `app.js:deriveUnifiedGrade()` now makes the v24 client Unified Decision Engine the canonical grade authority and emits display grade `C` whenever `isDZActive`; `isDeadZoneEligible()` also returns `gradeCap: 'C'`.

EVIDENCE-HISTORY: `213e411c4105801a433dd6502f6c0f524382cf7c` fixed the original dead cap; `5dddefbc9dbef0a586bd60d9d1bd787ec5aaf8f5` subsequently centralized grade authority in v24.

EVIDENCE-TEST: `tests/integration/dz-exit-grade-cap.spec.mjs`; `tests/unit/v24-unified-decision.spec.mjs`; `tests/integration/v24-authority-boundaries.spec.mjs`.

RATIONALE: The original bug was repaired, then its old distributed display-authority model was replaced. v24 canonical grade derivation now owns the result.

### F-2 — `paidDate` validation gap
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:sanitizeTrip()` validates `paidDate` with `isValidISODate()` and falls back only after validation.

EVIDENCE-HISTORY: `dc2e00dd90336a16de2a416fc545184aa48dc953`.

EVIDENCE-TEST: `tests/unit/pure-functions.spec.mjs`.

RATIONALE: Malformed imported `paidDate` values no longer pass through raw into date arithmetic.

### F-2b — `sanitizeStop.date` raw passthrough
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:sanitizeStop()` assigns `date: isValidISODate(raw.date) ? raw.date : ''`.

EVIDENCE-HISTORY: `dc2e00dd90336a16de2a416fc545184aa48dc953`.

EVIDENCE-TEST: `tests/unit/pure-functions.spec.mjs`.

RATIONALE: Stop dates now use the same validation boundary as trip dates.

### F-3 — Schedule C CSV field corruption
STATUS: **FIXED**

EVIDENCE-SOURCE: the F30 tax-export handler in `app.js` calls the shared `downloadCSV(rows, ...)` writer; `downloadCSV()` quotes every field and escapes embedded quotes.

EVIDENCE-HISTORY: `8dfd1a9a681f12edb0c9541936b811475aa2aae9`.

EVIDENCE-TEST: `tests/integration/tax-export-csv-corruption.spec.mjs`.

RATIONALE: City/state commas and other delimiter-bearing values cannot shift tax-export columns because the hand-joined writer was removed.

### F-4 — App Lock brute-force attempts
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:_appLockDelayForAttempt()` plus `requireAppUnlock()` persist fail count/locked-until state, enforce progressive delays, guard concurrent attempts, reset on successful unlock, and expose a confirmation-gated Forgot PIN recovery path.

EVIDENCE-HISTORY: `5ec4f0a4d58c79e3f1bafdf8fbaf0029b4f44033`.

EVIDENCE-TEST: `tests/integration/pin-lockout.spec.mjs`.

RATIONALE: Guessing is no longer unthrottled and reload does not reset the attempt state.

### F-5 — Production exposure of `window.__FL_TESTS`
STATUS: **FIXED**

EVIDENCE-SOURCE: the test-export block in `app.js` is wrapped in `if (typeof window !== 'undefined' && window.__FL_TESTS_ENABLED === true)`.

EVIDENCE-HISTORY: `637edafae7705de2b0df5b1affccc54505366149`.

EVIDENCE-TEST: `tests/integration/fl-tests-exposure.spec.mjs`.

RATIONALE: Production loads no longer expose the internal test surface unless the harness explicitly opts in before page load.

### F-6 — Lost update when two tabs edit one trip
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:sanitizeTrip()` preserves a numeric `updatedAt`; `upsertTrip()` captures the caller's expected stamp, compares it to the stored record inside the same read/write transaction, aborts on mismatch, and throws `FL_CONFLICT`.

EVIDENCE-HISTORY: `b300c011ec75258d5d70f97fc90a4b87947f3abe`.

EVIDENCE-TEST: `tests/integration/toctou-concurrent-edit.spec.mjs`.

RATIONALE: Trip saves now use compare-and-abort optimistic concurrency instead of unconditional last-writer-wins replacement.

### F-7 — GPS error destroys active trip session
STATUS: **FIXED**

EVIDENCE-SOURCE: the geolocation error callback in `app.js` keeps `_activeTracking` alive, records `gpsErrorSince/gpsErrorCode`, persists state, renders a degraded GPS state, and leaves Stop & Save available.

EVIDENCE-HISTORY: `71d73f58f646da82c1e749a3909f3a2117f33dff`.

EVIDENCE-TEST: `tests/integration/field-resilience.spec.mjs`.

RATIONALE: A transient/permission GPS failure no longer tears down the tracking session or exposes only a destructive fresh-start path.

### F-8 — New expense/fuel records fail because `id: undefined` is present
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:sanitizeExpense()` and `sanitizeFuel()` conditionally spread `id` only when one exists; `addExpense()`/`addFuel()` use IndexedDB `add()` on objects with no key-path property for new records.

EVIDENCE-HISTORY: `71d73f58f646da82c1e749a3909f3a2117f33dff`.

EVIDENCE-TEST: `tests/integration/field-resilience.spec.mjs`; sanitizer coverage in `tests/unit/pure-functions.spec.mjs`.

RATIONALE: IndexedDB auto-increment is again allowed to generate the key for newly-created expense and fuel records.

### X-01 — Cloud restore ignores delta syncs
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:cloudFetchDeltas()` retrieves retained deltas and detects pruned/unverifiable coverage; `cloudPullBackup()` applies the base snapshot and then deltas in chronological order and visibly warns on confirmed or unverifiable gaps.

EVIDENCE-HISTORY: `0e242735dfee68ce048321f64dfed47fbe99e575`.

EVIDENCE-TEST: `tests/integration/backup-restore-parity.spec.mjs`.

RATIONALE: Restore no longer silently declares success after reading only the last full backup.

### X-02 — 2026 mileage-rate model cannot represent mid-year rate change
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:MILEAGE_RATES` is date-keyed and contains separate 2026-01-01..06-30 and 2026-07-01..12-31 bands; `getMileageRate()` resolves by trip date.

EVIDENCE-HISTORY: `16245fdc07d2f89855b93ddd246241448f01ad26`.

EVIDENCE-TEST: `tests/unit/pure-functions.spec.mjs`; tax export integration coverage.

RATIONALE: A period spanning the rate boundary no longer applies one flat annual rate to all miles.

### X-03 — Schedule C double-dips standard mileage and actual vehicle costs
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:classifyExpenseTaxBucket()` separates method-sensitive vehicle costs from always-deductible costs; vehicle profiles persist a tax-method election; F30 computes `vehicleDeduction` from exactly one vehicle method and blocks export while the method is unset.

EVIDENCE-HISTORY: `16245fdc07d2f89855b93ddd246241448f01ad26`.

EVIDENCE-TEST: `tests/integration/insurance-migration.spec.mjs`; tax export integration coverage.

RATIONALE: Standard mileage and bucket-A actual vehicle expenses cannot both contribute to the same Schedule C total.

### X-04 — Standalone Midwest engine can grant Dead Zone survival pricing without canonical gates / competing authority
STATUS: **SUPERSEDED**

EVIDENCE-SOURCE: `midwest-stack-authority.js` calls the shared `window.isDeadZoneEligible()` before lowering the survival floor, fails closed if the gate is unavailable, returns `authorityRole: 'ADAPTER_ONLY'`, and labels its UI as advisory. `app.js:deriveUnifiedAuthority()` is the v24 canonical verdict authority.

EVIDENCE-HISTORY: `0a2a68ae32de1891ffc5e80ab2e7ebf1fa761a6b` fixed the shared gate; `5dddefbc9dbef0a586bd60d9d1bd787ec5aaf8f5` removed competing authoritative decision ownership in v24.

EVIDENCE-TEST: `tests/integration/dz-gate-parity.spec.mjs`; `tests/unit/v24-unified-decision.spec.mjs`; `tests/integration/v24-authority-boundaries.spec.mjs`.

RATIONALE: The unsafe gate was fixed and the broader duplicated-authority architecture was subsequently replaced by the v24 single-authority contract.

### X-05 — Export `checksumFull` hashes different settings data than payload writes
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:exportJSON()` builds `exportableSettings` once, strips secret API-key settings, and uses that same array for both `computeExportChecksumFull()` and `payload.settings`.

EVIDENCE-HISTORY: `638bd46f9882904ee874e4f051b9477e49ffbcd8`.

EVIDENCE-TEST: `tests/integration/export-checksum-integrity.spec.mjs`.

RATIONALE: An untampered export is self-consistent instead of warning that its own intentionally-filtered payload was modified.

### X-06 — Aggregate test runner exits zero when assertions fail
STATUS: **FIXED**

EVIDENCE-SOURCE: `tests/run-all.mjs` currently ends with `process.exit(totalFail ? 1 : 0)` and prints the failing file/test list.

EVIDENCE-HISTORY: `4bacebf33cf8c03bd124b66dd2ea75fdd44e4056`.

EVIDENCE-TEST: the runner itself is the release gate; `.github/workflows/tests.yml` invokes the suite.

RATIONALE: A red assertion now produces a non-zero process exit suitable for CI gating.

### X-07 — Cloud push contains stores that merge restore silently drops
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:mergeRestoreData()` explicitly merges settings, receipt metadata, and GPS logs in addition to primary/other stores. GPS logs are deduplicated by `(tripTrackingId,timestamp)` and incoming auto-increment IDs are not reused.

EVIDENCE-HISTORY: `0e242735dfee68ce048321f64dfed47fbe99e575`.

EVIDENCE-TEST: `tests/integration/backup-restore-parity.spec.mjs`.

RATIONALE: The backup contract's pushed stores are now represented in restore semantics instead of being silently omitted.

### X-08 — First offline install can miss the Midwest decision layer
STATUS: **FIXED**

EVIDENCE-SOURCE: `service-worker.js` current `critical` install array includes `midwest-stack-authority.js?v=24.0.0` and `vendor/xlsx.full.min.js` together with the core shell; install awaits `cache.addAll(critical)`.

EVIDENCE-HISTORY: `1399d9ff7a8865f95851fe587add89a4a2913991`.

EVIDENCE-TEST: `tests/unit/service-worker-shell.spec.mjs`.

RATIONALE: A successful first install cannot complete without caching the decision overlay and bundled spreadsheet parser.

### X-09 — Diagnostics Worker check always 403s because it sends literal `ping`
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:openDiagnosticsPanel()` reads the configured `cloudBackupToken`; without one it reports unconfigured, and with one it calls `/status` using the real token plus device ID.

EVIDENCE-HISTORY: `1399d9ff7a8865f95851fe587add89a4a2913991`.

EVIDENCE-TEST: `tests/unit/release-hygiene.spec.mjs`.

RATIONALE: The diagnostic now exercises the actual authenticated status path instead of a credential guaranteed to fail.

### X-10 — Excel import depends on CDN and is unavailable on first offline install
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:loadSheetJS()` loads only `./vendor/xlsx.full.min.js`; `service-worker.js` includes that vendor file in the install-blocking critical shell.

EVIDENCE-HISTORY: `1399d9ff7a8865f95851fe587add89a4a2913991`.

EVIDENCE-TEST: `tests/integration/xlsx-bundled-vendor.spec.mjs`; `tests/unit/service-worker-shell.spec.mjs`.

RATIONALE: Excel parsing no longer needs an external script fetch and is precached before a first offline launch can be considered installed.

### X-11 — UI claims PDF OCR import exists while `importPDFFile()` is a stub
STATUS: **FIXED**

EVIDENCE-SOURCE: `app.js:importPDFFile()` honestly reports PDF import unsupported; the current Universal Import UI no longer offers a dedicated PDF/OCR button or claims OCR support.

EVIDENCE-HISTORY: `1399d9ff7a8865f95851fe587add89a4a2913991`.

EVIDENCE-TEST: `tests/unit/release-hygiene.spec.mjs`.

RATIONALE: Product copy no longer promises a capability the runtime does not implement.

### X-12 — Cloudflare deployment-parity checklist drifts behind release
STATUS: **OPEN**

EVIDENCE: `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` still instructs operators to verify `app.js?v=23.9.0`, `voice-load.js?v=23.9.0`, `sw-bridge.js?v=23.9.0`, `midwest-stack-authority.js?v=23.9.0`, manifest name `FreightLogic v23.9.0`, and SW version `23.9.0`. Current `manifest.json` says `FreightLogic v24.0.0` and current `service-worker.js` uses `SW_VERSION = '24.0.0'` and v24.0.0 cache URLs.

EVIDENCE-HISTORY: `1399d9ff7a8865f95851fe587add89a4a2913991` repaired the same class of release-document drift for v23.9.0; the v24 release subsequently made the checklist stale again.

EVIDENCE-TEST: `tests/unit/release-hygiene.spec.mjs` exists, but current source evidence proves this particular operational checklist drift is present on `main`; a test's existence is not proof otherwise.

RATIONALE: An operator following the checklist literally would verify the wrong release generation. This is the first formal audit item Claude should repair after the extraction round is complete and a separate repair round is approved.

## Residual findings / limitations called out by the audit

These are tracked separately from the 21 formal numbered findings so the headline counts remain comparable to `AUDIT_REPORT.md`.

### R-TOCTOU-EXPENSE-FUEL — Same lost-update class remains outside trips
STATUS: **OPEN**

EVIDENCE: current `app.js:updateExpense()` and `updateFuel()` read the current record for audit logging and then perform an unconditional full-object `put()`; neither compares a caller-observed revision to the stored revision before writing. `sanitizeExpense()` / `sanitizeFuel()` also replace `updatedAt` with `Date.now()` during sanitization, so they do not preserve an expected version analogous to `sanitizeTrip()`.

RATIONALE: `AUDIT_REPORT.md` explicitly left multi-tab TOCTOU beyond trips unverified and noted the same full-object pattern. Current source confirms that the optimistic-concurrency protection added for F-6 remains trip-specific. Do not fix in the extraction round; treat as the next core-data repair after X-12 once a repair round is approved.

### R-FIELD-RESILIENCE
STATUS: **NEEDS-REVALIDATION**

EVIDENCE: the audit and current `tests/README.md` both retain real-device gaps for genuine quota exhaustion, iOS Safari eviction/background behavior, device kill during persistence, and related field conditions. The automated `field-resilience` spec covers a subset only.

WHAT REMAINS UNPROVEN: real iOS/device failure modes that headless Chromium cannot faithfully reproduce.

### R-FULL-E2E-JOURNEYS
STATUS: **NEEDS-REVALIDATION**

EVIDENCE: audit limitation; current suite is regression-focused rather than a timed multi-hour/shift simulation.

WHAT REMAINS UNPROVEN: full operational journeys across long-running sessions, reloads, installs, and mixed workflows.

### R-USABILITY-UNDER-LOAD
STATUS: **NEEDS-REVALIDATION**

EVIDENCE: audit limitation; Playwright assertions do not establish one-handed mobile usability, visual hierarchy, or accessibility under real driving-workflow pressure.

WHAT REMAINS UNPROVEN: field UX/accessibility evaluation.

### R-LIVE-WORKER-INVITE
STATUS: **NEEDS-REVALIDATION**

EVIDENCE: current client uses `#token=` setup links with legacy query fallback and strips the URL after ingest, but the audit/test README explicitly excludes live Cloudflare Worker behavior.

WHAT REMAINS UNPROVEN: deployed Worker rate limiting/auth/invite behavior and real multi-device setup against production bindings/secrets.

### R-EXHAUSTIVE-XSS-IMPORT-SURFACES
STATUS: **NEEDS-REVALIDATION**

EVIDENCE: audit limitation; targeted sanitizer/import checks exist, but the report explicitly did not claim exhaustive stored-XSS coverage across every rendered/imported surface.

WHAT REMAINS UNPROVEN: exhaustive source-to-sink coverage as features have continued to grow.

### R-F20-ACTIVATION-MATRIX
STATUS: **NEEDS-REVALIDATION**

EVIDENCE: v24 added unified authority/boundary suites and superseded distributed decision authority, but the old audit limitation concerned an exhaustive activation-condition matrix rather than a few representative fixtures.

WHAT REMAINS UNPROVEN: exhaustive combination coverage across all Dead Zone activation inputs after v24's authority migration.

## Repair priority after the extraction round

Do not mix these repairs with UI seam extraction.

1. **X-12** — refresh deployment parity documentation and any parity assertions to v24.x current truth; low code risk but operationally important.
2. **R-TOCTOU-EXPENSE-FUEL** — design optimistic concurrency for expense/fuel updates consistent with F-6's trip semantics; requires application-code changes and dedicated regression tests, so it belongs in a separately approved core repair round.
3. Revalidate the six residual field/live/usability gaps according to risk and available execution environment.
