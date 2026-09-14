# FreightLogic Test Ledger

Live execution ledger. This file lives on `agent-coordination` and is never merged to `main`. Log observed runs only; never infer a result from history.

BASELINE: GREEN — observed on final PR #77 integrated head

## Run — 2026-08-23T03:15:56Z

- Purpose: final coordination-setup baseline after the Claude-prompt documentation correction
- Tested SHA: `79d65abfaa4df5c954ae2ee626baa78460aa72bd` (PR #77 merge ref; protocol branch head `de87a2a7263479ce6c27cbeeaa85206af98770be`, base `0835d06c4415929b24d5684430b957412b026612`)
- Command: `node tests/run-all.mjs`
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**
- Full-suite execution window observed in logs: approximately 73.9 seconds (`03:15:56.362Z` through aggregate result at `03:17:10.250Z`)
- Rerun: none; this was a new synchronize run on the final protocol branch head, not a retry of a failed test run
- Environment note: `field-resilience` again reported that `Storage.overrideQuotaForOrigin` is unsupported on this runner; the suite's explicit unsupported-runner detection passed. Genuine device quota pressure remains a field-revalidation gap, not a baseline failure.
- Scope note: this is the final PR integrated merge ref, not yet a post-merge `main` baseline. Claude Code must still run the full suite on the exact current `main`/starting SHA before proposing extraction.

## Prior observed run — 2026-08-23T03:11:20Z

- Purpose: initial coordination-setup baseline / integrated PR gate
- Tested SHA: `483c33084e579b95b8972c5a96922d6db345f4d2` (PR #77 synthetic merge ref; protocol branch head `a8adfe3de0e3d63da1d2b4c793053bb17a46f05d`, base `0835d06c4415929b24d5684430b957412b026612`)
- Command: `node tests/run-all.mjs`
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**
- Full-suite execution window observed in logs: approximately 73.5 seconds (`03:11:20.419Z` through aggregate result at `03:12:33.911Z`)
- Rerun: none

## Required baseline command

`node tests/run-all.mjs`

## Required run fields

- UTC timestamp
- exact tested SHA
- command / relevant environment
- result: pass/fail totals and spec count
- every failing suite/test when red
- duration if observed
- rerun trigger/reason when a rerun occurs

Historical note only, **not a current baseline**: v24.0.0 release commit `5dddefbc9dbef0a586bd60d9d1bd787ec5aaf8f5` recorded 119 passed / 0 failed across 19 spec files on its final PR head.

## Run — 2026-08-23T07:18:12Z

- Purpose: exact-current-main clean-CI baseline after removal of the temporary bank-import repair machinery and merge of the v24.1 docs contract.
- Tested SHA: `971bf26f829c0ca5c9b751cfc82fc1d511ac576b` (PR #83 synthetic merge ref).
- Git tree: `61f5f54a4cca5835661fd06ff5fa255c8df94436`, byte-identical to then-current `main` `eb50bbe743562d18beccef35e3ded26ec47b9167`. After the green run, `main` was fast-forwarded to this exact tested commit with no tree/content change.
- Command: `node tests/run-all.mjs`
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`; workflow token contents permission `read`.
- Workflow evidence: run `32625179952`, job `97159316919`.
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**.
- Full-suite command window observed in logs: approximately 78.7 seconds (`07:18:12.179Z` through aggregate result at `07:19:30.870Z`).
- Rerun: none.
- Environment note: `Storage.overrideQuotaForOrigin` remained unsupported on this hosted runner; the suite's explicit unsupported-runner path passed. Real device quota pressure remains a field-revalidation item.
- Baseline disposition: this is now the exact `main` SHA, not merely tree-parity evidence. Clean-CI and exact-main baseline prerequisites for the behavior-preserving extraction gate are satisfied.

## Run — 2026-08-25T09:39:09Z

- Purpose: fresh post-DAT/current-main runtime baseline while opening docs-only completion-plan PR #90.
- Tested SHA: `de77f9c6990ca3ff11ce3d850fbcad8679c8528e` (PR #90 synthetic merge ref: docs-only head `f85892e4b28057ba55f34dd50adc031d4fd2269b` merged into base `96224bc04ede159ffd09bc57d574a7938e2e927e`).
- Runtime equivalence: PR #90 changes only `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md`; application/runtime/test files are byte-identical to current base main `96224bc04ede159ffd09bc57d574a7938e2e927e`.
- Command: `node tests/run-all.mjs`.
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`; workflow token contents permission `read`.
- Workflow evidence: run `32833036042`, job `97755739019`.
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**.
- Full-suite command window observed in logs: approximately 77.4 seconds (`09:39:09.270Z` through aggregate result at `09:40:26.635Z`).
- Rerun: none.
- Environment note: `Storage.overrideQuotaForOrigin` remained unsupported on the hosted runner; the suite's explicit unsupported-runner path passed. Real device quota pressure remains a field-revalidation item.
- Coverage note: this green baseline does not certify the newly identified Midwest Stack v11 / Level X+ gaps (Toledo/Cincinnati Tier-1 parity, exact standalone `0.90` DZ/F20 floor, and UNKNOWN-vs-zero operational inputs), because the current 19-spec suite does not assert those new requirements yet. Those remain Milestone-1 release blockers and require new core-owned regression coverage.

## Run — 2026-08-26T04:51:03Z

- Purpose: integrated PR #95 gate for GPT-owned operator-truth/provenance/open-question extraction, vision-ingest specification, and duplicate-roadmap retirement.
- Tested SHA: `f55c6c88319b78ea2df373c2f5a8110e4e9e69bd` (PR #95 synthetic merge ref: docs-only head `53a2404b88d503eaa540f909fa930cab7fcfbe13` merged into base `b6eb8d9fd2eb87777609e73cff809ea2a816b861`).
- Merged main after successful gate: `93c45bf52061121c901f074764546587db0f6d84`; merged tree `75719bce539a02871b37ad27ca4dfa2d61a01b17` matches the tested PR merge-ref tree.
- Command: `node tests/run-all.mjs`.
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`; workflow token contents permission `read`.
- Workflow evidence: run `32931726691`, job `98065131187`.
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**.
- Full-suite command window observed in logs: approximately 78.7 seconds (`04:51:03.746Z` through aggregate result at `04:52:22.473Z`).
- Rerun: none.
- Scope note: PR #95 changed GPT-owned documentation only and removed the obsolete duplicate `docs/V24_ROADMAP.md`; no runtime or test source changed and the finite completion-plan milestone order was not modified.

## Run — 2026-08-26T05:30:40Z

- Purpose: integrated PR #96 gate for the operator-approved Gate 0 formalization and Milestone 5 ingestion ordering.
- Tested SHA: `ad4bf17f5891923eb6a801a562faa9edea080d25` (PR #96 synthetic merge ref: docs-only head `eb8436a714e8332dd135d9f568eb2ed26297a260` merged into base `93c45bf52061121c901f074764546587db0f6d84`).
- Merged main after successful gate: `86ae9b1eb60b1452370acb443982d1c35ef66c45`; merged tree `65a92e66e5b486711f6be94fb745e671aacc2bbf` matches the tested PR merge-ref tree.
- Command: `node tests/run-all.mjs`.
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`.
- Workflow evidence: run `32934284234`, job `98072421221`.
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**.
- Full-suite command window observed in logs: approximately 79.8 seconds (`05:30:40.805Z` through aggregate result at `05:32:00.603Z`).
- Rerun: none.
- Scope note: PR #96 changed only `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` and `docs/OPEN_QUESTIONS.md`. Gate 0 was marked complete; runtime Milestones 1–7 retained their order; vision/provider adapters remain non-blocking.

## Run — 2026-08-26T05:40:40Z

- Purpose: integrated PR #97 gate for recording the pending MPG source-of-truth scope proposal without changing runtime scope.
- Tested SHA: `dbe2a2523c6dca7f543828d890a99dd145edee36` (PR #97 synthetic merge ref: docs-only head `2f466b0a0b6d03955e954b5ad2bf7a0f9ebf1bbd` merged into base `86ae9b1eb60b1452370acb443982d1c35ef66c45`).
- Tree parity: tested merge-ref tree `277dd55b99ece2ecde316ea5631ca9955ee105b0` exactly matches merged/fast-forwarded main `2f466b0a0b6d03955e954b5ad2bf7a0f9ebf1bbd` tree `277dd55b99ece2ecde316ea5631ca9955ee105b0`.
- Command: `node tests/run-all.mjs`.
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`; workflow token contents permission `read`.
- Workflow evidence: run `32934945219`, job `98074282712`.
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**.
- Full-suite command window observed in logs: approximately 77.8 seconds (`05:40:40.390Z` through aggregate result at `05:41:58.218Z`).
- Rerun: none.
- Scope note: PR #97 changed only `docs/OPEN_QUESTIONS.md`, recording the `17.5 MPG` Gate-0 truth vs current `MW.mpg: 16.5` fallback conflict as a **pending operator approval**. No runtime, test, storage, service-worker, or completion-plan scope changed.

## Run — 2026-08-26T06:46:48Z

- Purpose: integrated PR #98 gate for recording the operator's explicit approval of the bounded Milestone-1 MPG fallback parity repair.
- Tested SHA: `5d158d2576ea7d6c4d03c72d5ef80c1b37bc0db3` (PR #98 synthetic merge ref: docs-only head `ccecada35c54f9f5f7c1c138cff32fb5faa1fb01` merged into base `2f466b0a0b6d03955e954b5ad2bf7a0f9ebf1bbd`).
- Merged main after successful gate: `762984afb3afe80a9a25d592927d8ec40b0f51ed`.
- Command: `node tests/run-all.mjs`.
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`.
- Workflow evidence: run `32939599895`, job `98087666374`.
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**.
- Full-suite command window observed in logs: approximately 78.1 seconds (`06:46:48.702Z` through aggregate result at `06:48:06.846Z`).
- Rerun: none.
- Scope note: PR #98 changed only `docs/OPEN_QUESTIONS.md`; it converted item 33 from pending to CONFIRMED. It authorized, but did not implement, the `~17.5 MPG` fallback/source-label parity repair with explicit user MPG remaining the higher-priority override.

## Run — 2026-08-26T07:29:25Z

- Purpose: integrated PR #99 gate synchronizing the already-approved MPG parity repair into the single canonical completion roadmap.
- Tested SHA: `b1a215f4e17ccc212e0ba4c954fce7a5b177ee56` (PR #99 synthetic merge ref: docs-only head `b91774f1aa7d7a5fed2eb29cb6e358c1a8961c92` merged into base `762984afb3afe80a9a25d592927d8ec40b0f51ed`).
- Merged main after successful gate: `da62c114885a2549f94bc26059f6d0cc51431e8b`.
- Command: `node tests/run-all.mjs`.
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`.
- Workflow evidence: run `32942947209`, job `98097573111`.
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**.
- Full-suite command window observed in logs: approximately 76.7 seconds (`07:29:25.341Z` through aggregate result at `07:30:41.995Z`).
- Rerun: none.
- Scope note: PR #99 changed only `docs/COMPLETION_RELEASE_PLAN_2026-08-25.md` (9 additions / 6 deletions). It added the approved MPG fallback/override parity item to M1 defect tracking, required outcomes, definition of done, and execution order. No runtime, test, storage, service-worker, or milestone-order change occurred.

## Run — 2026-08-26T10:02:00Z

- Purpose: full-suite verification of the lane-mechanics enforcement change (hooks + CI checks + new unit spec).
- Tested SHA: `510ac8a2203e1eafd9717f87cd911371c4a3d384` on `claude/audit-reconcile-lane-mechanics-hteibi`, based on main `da62c114885a2549f94bc26059f6d0cc51431e8b`.
- Command: `node tests/run-all.mjs`.
- Environment: **local session container, not GitHub Actions.** Node `v22.22.2`; Playwright `1.56.1`. NOTE: CI pins Playwright `1.62.1`, so this run is not environment-equivalent to the CI gate and does not substitute for an Actions run on an integrated PR head.
- Result: **GREEN — 138 passed, 0 failed across 20 spec files**.
- Rerun: none.
- Delta vs the prior recorded baseline (119 passed / 0 failed across 19 specs): +19 assertions, +1 spec file, exactly accounted for by the new `tests/unit/lane-guard.spec.mjs`. No pre-existing assertion changed, was skipped, weakened, or removed.
- Scope note: the change touches no application runtime file — no `app.js`, `index.html`, `service-worker.js`, `manifest.json`, or `styles.css`. `tests/run-all.mjs` gained two lines (import + registration).

## Run — 2026-08-26T11:27Z

- Purpose: Milestone 1 doctrine/money-integrity certification, full suite on the exact implementation head.
- Tested SHA: `b56af9e` on `claude/audit-reconcile-lane-mechanics-hteibi`, based on main `ef3b84014c24e2f1498a1f9ba390183cdbca10bb`.
- Command: `node tests/run-all.mjs`.
- Environment: **local session container, not GitHub Actions.** Node `v22.22.2`; Playwright `1.56.1`. CI pins Playwright `1.62.1`, so this is not environment-equivalent to the CI gate and does not replace an Actions run on an integrated PR head.
- Result: **GREEN — 159 passed, 0 failed across 21 spec files**.
- Rerun: none. Three earlier attempts were discarded before producing a verdict and are NOT counted as runs: two were invalidated by concurrent suite processes contending for the harness server port, and one was killed by a `pkill -f headless_shell` pattern that matched its own wrapper command line. No test code was changed in response to any of them.
- Delta vs prior baseline (138 passed / 0 failed across 20 specs): +21 assertions, +1 spec file, entirely accounted for by the new `tests/integration/m1-doctrine-integrity.spec.mjs`. No pre-existing assertion was changed, skipped, weakened or removed.
- Test-fixture note: `dz-exit-grade-cap`, `dz-gate-parity` and `van-fit-precheck` now fill `#mwDeadMi` with `0`. They never filled it and were relying on blank-means-zero, which M1 removes. Fixtures only — assertions untouched.
- Scope note: v24.0.1 version bump included because `CACHE_NAME` is `freightlogic-${SW_VERSION}` and all cache-busters were `?v=24.0.0`; without it an installed PWA keeps serving the pre-M1 `app.js`/overlay from cache. `index.html`/`_headers` CSP byte-identity re-verified after the bump.

## Run — 2026-08-26T12:05Z

- Purpose: Milestone 2 expense/fuel optimistic-concurrency repair (R-TOCTOU-EXPENSE-FUEL), full suite on the exact implementation head.
- Tested SHA: `e59360e` on `claude/audit-reconcile-lane-mechanics-hteibi`.
- Command: `node tests/run-all.mjs`.
- Environment: **local session container, not GitHub Actions.** Node `v22.22.2`; Playwright `1.56.1` (CI pins `1.62.1`) — not environment-equivalent to the CI gate.
- Result: **GREEN — 166 passed, 0 failed across 22 spec files**.
- Rerun: none.
- Delta vs the M1 head (159 passed / 0 failed across 21 specs): +7 assertions, +1 spec file, entirely accounted for by `tests/integration/m2-expense-fuel-concurrency.spec.mjs`. No pre-existing assertion changed, skipped, weakened or removed.
- Regression note: `tests/integration/toctou-concurrent-edit.spec.mjs` (trip F-6) still passes. That is the load-bearing regression check for this milestone, since M2 modifies the same `updatedAt` preservation pattern F-6 depends on.
- Backup/restore parity: `backup-restore-parity.spec.mjs` green, satisfying the M2 definition of done. Delta-sync and merge-restore both read `updatedAt || updated || created`, so the sanitizer change does not alter their ordering behavior.

## Run — 2026-08-26T12:35Z

- Purpose: Milestone 3 (v24.1 Confidence + Evidence), full suite on the exact implementation head.
- Tested SHA: `03172d5` on `claude/audit-reconcile-lane-mechanics-hteibi`.
- Command: `node tests/run-all.mjs`.
- Environment: **local session container, not GitHub Actions.** Node `v22.22.2`; Playwright `1.56.1` (CI pins `1.62.1`) — not environment-equivalent to the CI gate.
- Result: **GREEN — 183 passed, 0 failed across 23 spec files**.
- Rerun: none.
- Delta vs the M2 head (166 / 0 across 22): +17 assertions, +1 spec file, entirely `tests/integration/m3-confidence-evidence.spec.mjs`. No pre-existing assertion changed, skipped, weakened or removed.
- Regression note: all four v24.0 authority/economics/bid/decision specs remain green, which is the load-bearing check for this milestone — v24.1 must not alter v24.0 authority.
- One in-development failure (M3-13) was a fixture gap in the new spec itself: it omitted `netAfterFuel`/`profitMarginPct`, so the fuel-margin gate correctly returned REJECT. The fixture was completed. No product code changed in response and no assertion was weakened.

## Run — 2026-08-26T20:30Z (M4 complete + M5A/5B)

- Tested SHA: `14671c8` on `claude/audit-reconcile-lane-mechanics-hteibi`.
- Command: `node tests/run-all.mjs`; Node v22.22.2; Playwright 1.56.1 (CI pins 1.62.1 — not CI-equivalent).
- Result: **GREEN — 225 passed, 0 failed across 25 spec files**.
- Progression this session on the branch: 183/23 (M3) → 203/24 (M4 core) → 209/24 (M4b) → 211/24 (M4c, section 16.8) → 225/25 (M5A/5B).
- New specs since main: m4-load-lifecycle (28), m5-opportunity-ingestion (14). No pre-existing assertion changed, skipped, or weakened.

## Run — 2026-08-27T (M6 real import + fingerprint fix)

- Tested SHA: `d9d01a7` on `claude/audit-reconcile-lane-mechanics-hteibi`.
- Command: `node tests/run-all.mjs`; Node v22.22.2; Playwright 1.56.1 (CI pins 1.62.1).
- Result: **GREEN — 240 passed, 0 failed across 26 spec files** (+1: M6-15 long-provenance idempotency regression).
- Real-data validation (harness, not a committed test): the operator's 2026-08-27 bundle imported through the merged importHistoricalOpportunities() — 142 lifecycle rows, deterministic checksum 70d378b, fully idempotent on re-import after the fix (142/142 duplicatesSkipped).

## Run — 2026-09-02T19:20Z (v24.0.2 exact-current main)

- Purpose: exact-current-main completion baseline after PR #124 runtime and PR #125 release-doc merges.
- Tested SHA: `fa63be5430b2f89e85c0df14df7ab7a6294c974d` on `main`.
- Command/environment: GitHub Actions `node tests/run-all.mjs`; run `33672667233`, job `100389810421`.
- Result: **RED — 316 passed, 2 failed across 32 spec files**.
- Failures:
  - `integration/m4-load-lifecycle.spec.mjs` :: `[M4-23] settlement is derived from the trip without inferring PAID from delivery` — expected `INVOICED`, actual `OVERDUE`.
  - `integration/m4-load-lifecycle.spec.mjs` :: `[M4-24] saving a trip dual-writes execution and settlement, leaving the trip authoritative` — expected `INVOICED`, actual `OVERDUE`.
- Classification: deterministic test-fixture time bomb. Both fixtures hard-code 2026-08-03 as the effective invoice date; production's existing 30-day terms rule correctly returns `OVERDUE` on 2026-09-02. No product regression is evidenced by these failures.
- Rerun: none. An unchanged rerun is not justified; the fixtures require a Claude/test-lane repair followed by the full suite.
- Local workspace note: one local attempt could not execute because this workspace denies the suite's network/live-origin activity. It is not counted as a product/test result.

| 2026-09-03T21:40:30Z | claude | 5f77b69 | v24.0.3 cache-generation freeze | full suite | 350 pass / 0 fail / 38 spec files | parity --static-only PASS; live half UNOBSERVED |

| 2026-09-03T23:37:54Z | claude | ff9d9ab | v24.0.4 "Fail Closed" core slice (items 1-7) | full suite | 369 pass / 0 fail / 40 spec files | parity --static-only PASS at 24.0.4; live half UNOBSERVED; 3 existing tests strengthened, 0 weakened |

| 2026-09-12T04:55:00Z | claude | 556f5b0 | post-#148/#149 harness change re-baseline (docs-only work on top) | full suite | 372 pass / 0 fail / 40 spec files | parity --static-only PASS at 24.0.5; m7-certify 13/13 automated gates, NOT CERTIFIABLE; live half UNOBSERVED (proxy refuses CONNECT to both deployed origins) |

| 2026-09-12T06:25:00Z | claude | a2a6bc1 | independent verification of Worker v14 production-origin repair (gpt PR #153) | full suite | 373 pass / 0 fail / 40 spec files | parity --static-only PASS at app 24.0.5 / Worker 14; +1 assertion vs 372 baseline (new W-01b CORS test); live half UNOBSERVED — proxy refuses both origins, now GPT's Gate 2 |

| 2026-09-12T06:30:00Z | claude | 39882fa | van-profile reconciliation to operator vehicle truth (PR #155) | full suite | 376 pass / 0 fail / 40 spec files | +3 vs 373 baseline (OPS-01/02/03); negative controls fire both ways; CI playwright-suite green on the merged head; parity --static-only PASS |

## 2026-09-13 — GPT observes v24.0.8 completion baseline

- Claude source head bd1a9c81c47022b23f9804fbb5ef9274d6969531; PR #172 Tests run 34783435831 / job 103794494149: node tests/run-all.mjs, GitHub Actions Chromium, **406 PASS / 0 FAIL / 43 specs**; verified from completed job logs. No rerun requested.
- Inspected production/source baseline c02ed36bcc6c81a182c81aec0d6358d39fc90bbf: verify-cloudflare-parity.mjs **24 PASS / 0 FAIL**, exit 0; m7-certify.mjs --skip-suite **13 PASS / 0 FAIL / 1 SKIP**, NOT CERTIFIABLE.
- Independent live byte/header probe: eleven files match; admin-driver-ui.js HTTP 404. Product deployment defect, not a red full-suite baseline. PR #173 removes its explicit .assetsignore exclusion.
- verify-live-authority.mjs: exit 2, UNOBSERVED, missing FL_BACKUP_TOKEN. No authenticated checks, no OpenAI calls, no account data written.
- Local Chromium installation timed out; browser tool stalled. No local full-suite or six-width run claimed; no tests skipped/rewritten to manufacture a pass. PR #173 own CI result pending.

## 2026-09-13 — PR #173 final integrated gate

- Final source head: 577d552612260000d34ad38881bcc246fdc71e85; base c02ed36bcc6c81a182c81aec0d6358d39fc90bbf; integrated PR ref 5595354a1fcb090ba30a7384b7efa805e0e52015.
- GitHub Tests run 34784017292, job 103796091494: node tests/run-all.mjs, **406 passed / 0 failed across 43 spec files** (job log total at 21:33:21 UTC).
- Lanes run 34784017263: success. No failed assertion, quarantine, or safety-net edits. Earlier PR CI was superseded by the final field-checklist documentation synchronization.
- Merged as d751500eed8c7e4c29dd23e32ed9c21883889fe9. Production restored-admin-asset and controlled-PWA cache verification remain pending; this source/CI result is not a deployment PASS.

## 2026-09-13 — deploy-asset coverage (claude/repo-review-9lpj28)

- Head 4018a56, branched from main d751500. Local run against real headless Chromium: **411 passed / 0 failed across 44 spec files**, exit 0.
- Delta from the 406/43 PR #173 baseline is exactly the new `tests/unit/deploy-asset-coverage.spec.mjs` (+1 spec file, +5 assertions, DAC-01…DAC-05). No existing assertion was changed, skipped, quarantined or weakened.
- `scripts/verify-cloudflare-parity.mjs --static-only`: PASS, now reporting `No runtime asset is excluded from deployment by .assetsignore (23 declared)` alongside the CSP byte-identity check.
- Live half NOT run — this lane's proxy still refuses to tunnel to both deployed origins. The sweep was instead driven end-to-end against a real local origin serving the repo: all 23 assets PASS; deleting `admin-driver-ui.js` reproduces `HTTP 404 (requested by service-worker.js CORE, service-worker.js ADMIN_UI_TAG (injected))` and exits 1; an origin serving `index.html` for a missing `.js` is caught by the content-type check rather than passing as 200.
- Negative controls, all confirmed to fire: `admin-driver-ui.js` re-added to `.assetsignore` (DAC-02, DAC-05); a `vendor/` directory entry (DAC-02); an `icon*.png` glob (DAC-02); the `cloud-backup-worker.js` exclusion removed (DAC-03); the sweep call commented out, and the shared import removed (DAC-04); a bogus identifier in `CORE` (DAC-01/02/05, as an unparseable declaration rather than a silently shorter inventory).
- No shipped file changed: `APP_VERSION`/`SW_VERSION` 24.0.8, DB 15, Worker v15 all untouched. This is a source/CI result and a tooling change; it is not a deployment PASS and claims nothing about the live gates.

## 2026-09-14 — v24.0.9 pickup feasibility (claude/repo-review-9lpj28)

- Head 3dc407e, branched from main a7b7259. Local run against real headless Chromium: **431 passed / 0 failed across 45 spec files**, exit 0.
- Delta from the 411/44 baseline is exactly the new work: `tests/integration/pickup-feasibility.spec.mjs` (+1 spec file, +8) and 12 new `[PF]` cases in `tests/unit/pure-functions.spec.mjs`. No existing assertion was changed, skipped, quarantined or weakened.
- Release identity: `tests/unit/cache-generation.spec.mjs` 13/13 green at `24.0.9`; `scripts/verify-cloudflare-parity.mjs --static-only` PASS (CSP byte-identity + 23 declared assets, none excluded). `DB_VERSION` 15 and Worker v15 unchanged, asserted by CG-09.
- Negative controls, all confirmed to fire: `getPlanningAvgMph()` falling back to `55` fails PF-01 and the `getPlanningAvgMph` unit case; an unstated deadhead coerced to `0` fails the UNKNOWN-deadhead case; dropping the range check so an out-of-range speed clamps fails the out-of-range case; neutralizing the block so economics render for an unreachable pickup fails PF-02/03/05.
- Three defects found in this lane's own new code during self-review and fixed BEFORE commit, each with a test added: an unreachable `Number.isFinite` guard after `knownNum()`, a missing clock reported as `NO_CUTOFF_SUPPLIED` instead of its own `NO_CLOCK`, and `cutoffPassed` reading true at exactly zero slack (reachable and cutoffPassed simultaneously). The full suite above ran on the corrected, committed tree — not on the pre-cleanup state.
- Live gates untouched and unclaimed. This is a source/CI result, not a deployment PASS.

## 2026-09-14 — live-parity runner (claude/repo-review-9lpj28)

- Head `0356219`, branched from main `0feb82f`. Full suite against real headless Chromium: **442 passed / 0 failed across 46 spec files**, exit 0.
- Delta from the 431/45 v24.0.9 baseline is exactly `tests/unit/live-parity-runner.spec.mjs` (+1 spec file, +11: LPR-01…LPR-11). No existing assertion was changed, skipped, quarantined or weakened. An intermediate run at `039fbd9` recorded 441/46; the +1 to 442 is LPR-11, added with the shell-injection fix in `a2f7a9f`.
- `scripts/verify-cloudflare-parity.mjs --static-only` PASS at `24.0.9` (CSP byte-identity + 23 declared assets, none excluded), now ending in an explicit `VERDICT: PASS` line.
- No runtime file changed: `APP_VERSION`/`SW_VERSION` `24.0.9`, DB 15, Worker v15 untouched. This is tooling, not a release.
- **Verdict semantics are exercised, not asserted from source text.** LPR-05…LPR-10 spawn the real verifier and read its real exit code: `--static-only` → 0; `https://unreachable.invalid` (RFC 2606, deterministic offline) → 2 UNOBSERVED; a local origin that 404s everything → 1 FAILURE; a local origin that answers once then destroys every connection → 1 FAILURE. Exit 2 is non-zero, so `deploy-backup-worker.yml`, `scripts/deploy-backup-worker.sh` and `m7-certify` all keep failing closed.
- Negative controls, all confirmed to fire: collapsing UNOBSERVED into FAILURE fails LPR-06/08; a `push:` trigger fails LPR-01; `contents: write` fails LPR-02; dropping the response record fails LPR-10; restoring `${{ inputs.x }}` inside `run:` fails LPR-11.
- **Two controls were silent before they were real, and both are recorded because a test that cannot fail is the defect this suite exists to catch.** (1) Dropping the "a response arrived" record failed nothing — an all-404 origin produces no transport errors, so the verdict was already right by another route; only the partial case depends on it, which is why LPR-10 exists. (2) LPR-11's first implementation parsed `run:` blocks with a lazy regex that truncated every block to its first line, so it inspected almost nothing and its control did not fire; rewritten per line, it does.
- Live gates untouched and unclaimed. The workflow has NOT been dispatched from this lane and nothing here is evidence about production.
