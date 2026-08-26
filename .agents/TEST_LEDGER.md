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
- Tested SHA: `483c33084e579b95b8972c5a96922d6db345f4d2` (PR #77 merge ref; protocol branch head `a8adfe3de0e3d63da1d2b4c793053bb17a46f05d`, base `0835d06c4415929b24d5684430b957412b026612`)
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
