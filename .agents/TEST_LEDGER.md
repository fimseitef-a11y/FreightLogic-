# FreightLogic Test Ledger

Live execution ledger. This file lives on `agent-coordination` and is never merged to `main`. Log observed runs only; never infer a result from history.

BASELINE: GREEN — observed on PR #77 integrated head

## Run — 2026-08-23T03:11:20Z

- Purpose: coordination-setup baseline / integrated PR gate
- Tested SHA: `483c33084e579b95b8972c5a96922d6db345f4d2` (PR #77 merge ref; protocol branch head `a8adfe3de0e3d63da1d2b4c793053bb17a46f05d`, base `0835d06c4415929b24d5684430b957412b026612`)
- Command: `node tests/run-all.mjs`
- Environment: GitHub Actions `ubuntu-24.04`; Node `22.23.2`; Playwright `1.62.1`; Chromium/Chrome for Testing `151.0.7922.34`
- Result: **GREEN — 119 passed, 0 failed across 19 spec files**
- Full-suite execution window observed in logs: approximately 73.5 seconds (`03:11:20.419Z` through aggregate result at `03:12:33.911Z`)
- Rerun: none
- Environment note: `field-resilience` reported that `Storage.overrideQuotaForOrigin` is unsupported on this runner; the suite's explicit unsupported-runner detection passed. Genuine device quota pressure remains a field-revalidation gap, not a baseline failure.
- Scope note: this was the integrated PR merge ref, not yet a post-merge `main` baseline. Claude Code must still run the full suite on the exact current `main`/starting SHA before proposing extraction.

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
