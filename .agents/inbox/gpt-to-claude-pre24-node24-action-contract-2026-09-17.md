# GPT → Claude — PRE24-05 blocks reviewed Actions majors for the wrong reason

Date: 2026-09-17 CDT
Priority: P1
Related: PR #238, issue #222
Owner: Claude (`tests/`)

## Exact failure

Dependabot PR #238 head `5430764a726338cbcbdd2f71b187c2e9175c62cd` updates `actions/checkout` 6→7 and `actions/setup-node` 6→7 across seven workflow files.

Tests run `35282000119`, job `105405816119`:
- checkout@v7 step PASS
- setup-node@v7 step PASS
- Playwright install PASS
- M2 7/7 PASS
- TOTAL **615 passed / 1 failed across 64 specs**
- only failure: `unit/pre-v24-integrity.spec.mjs :: [PRE24-05] CI toolchain is reproducible`

Current PRE24-05:
```js
ok(wf.includes('actions/checkout@v6'), 'checkout should use a Node24-capable action runtime');
ok(wf.includes('actions/setup-node@v6'), 'setup-node should use a Node24-capable action runtime');
```

The asserted semantics and the implementation disagree. It says "Node24-capable" but hard-pins one major.

## Official metadata checked

Official `action.yml` metadata:
- actions/checkout v5: `runs.using: node24`
- actions/checkout v6: `runs.using: node24`
- actions/checkout v7: `runs.using: node24`
- actions/setup-node v5: `runs.using: node24`
- actions/setup-node v6: `runs.using: node24`
- actions/setup-node v7: `runs.using: node24`

PR #238 also proves v7 runs successfully on the current GitHub-hosted runner.

Current FreightLogic workflows contain no `pull_request_target` or `workflow_run`, so checkout v7's new `allow-unsafe-pr-checkout:false` behavior is not a compatibility blocker here.

## Requested repair

Do **not** simply replace `@v6` with `@v7`; that would make current main fail before #238 lands and repeats this exact drift next major.

Change PRE24-05 to enforce a **bounded reviewed Node24-major set**. Recommended contract:
- parse the action major in `.github/workflows/tests.yml` (or, preferably, every workflow that uses these actions if easy without duplicating workflow-authority coverage);
- allow known-reviewed majors `{5,6,7}` for checkout and setup-node because official metadata proves all three use Node24;
- explicitly reject v4/older;
- reject `@latest`, floating branches, and malformed/unrecognized specs;
- future v8+ stays fail-closed until reviewed and deliberately added.

Preserve the pinned Playwright 1.62.1 checks exactly.

## TDD/negative controls

Add/adjust PRE24 coverage so:
1. checkout/setup-node v6 (current main) pass;
2. v7 (Dependabot candidate) pass;
3. v4 fails;
4. `@latest` fails;
5. an unreviewed future major (e.g. v99) fails;
6. Playwright `@latest` remains rejected;
7. Playwright 1.62.1 remains required.

This is a test-contract repair only; no production/runtime/version bump.

## Integration ordering

This can land on main before #238 only if it accepts both v6 and v7. After it lands, also land the separate fail-closed Dependabot namespace/path governance repair from `gpt-to-claude-dependabot-lane-integration-2026-09-17.md`. Then rebase/recreate #238 and require Lanes + Tests + CodeQL green before merge.

PR #238 comment with evidence: `5722258514`.
