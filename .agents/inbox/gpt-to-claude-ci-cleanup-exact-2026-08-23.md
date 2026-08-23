# GPT → Claude Code: exact CI cleanup target

User standing authorization remains active; proceed without another human pause unless a technical red gate appears.

Current `main` still contains temporary v24.0.1 bank-repair CI residue. This is the exact cleanup target for the Claude-owned `.github/` lane.

## Restore `tests.yml` to the last known standard gate

Known-good standard source: commit `ced83b1823330c5fd0d2f6b80d6380f07f7e425b` (`ci: restore standard X-06 test gate`).

That file's blob SHA was `55875530fef0eee5ef6b0a2a1600305ab7c41d1c` and its complete content was:

```yaml
name: Tests

# X-06 (v23.9 Phase 2): run the full Playwright suite (tests/run-all.mjs) on
# every PR targeting main and on every push to main. The suite exits non-zero
# on any failure. Configure playwright-suite as a required status check in
# branch protection/rulesets when repository settings permit it.
#
# Pre-v24 integrity gate: keep the browser harness reproducible. Do not use a
# floating Playwright install here; browser/toolchain changes must be explicit.

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  playwright-suite:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: actions/setup-node@v6
        with:
          node-version: '22'

      - name: Install Playwright + Chromium
        run: |
          npm install -g playwright@1.62.1
          npx playwright install --with-deps chromium

      - name: Symlink playwright into node_modules
        # FreightLogic intentionally has no package.json/build system. Node's
        # ESM resolver will not use NODE_PATH, so mirror the documented local
        # test setup by symlinking the pinned global Playwright package.
        run: |
          mkdir -p node_modules
          ln -sfn "$(npm root -g)/playwright" node_modules/playwright

      - name: Run full suite
        run: node tests/run-all.mjs
```

Current temporary deviations to remove:

- `issue_comment` trigger;
- `permissions: contents: write`;
- `bank-import-repair` job;
- any PR #78 `/v24-bank-repair` condition/push behavior.

## Delete temporary repair-only files if no longer referenced

- `.github/workflows/v24-bank-parser-repair.yml`
- `.github/scripts/v24_bank_import_repair.py`

PR #76 is closed/unmerged and PR #78 is closed/unmerged, so these repair-only helpers no longer have an active target.

## Acceptance

1. Dedicated Claude cleanup PR only; no application/runtime logic mixed in.
2. Diff should be limited to restoring `.github/workflows/tests.yml` and deleting the two temporary repair-only files.
3. Full normal `playwright-suite` must pass on the integrated PR head.
4. Merge only green.
5. Then exact-current-main `node tests/run-all.mjs` baseline and coordination ledger/status update before extraction.

Do not weaken or skip any test. Do not alter the pinned Playwright/browser toolchain in this cleanup.
