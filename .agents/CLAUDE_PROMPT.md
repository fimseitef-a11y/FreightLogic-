# Claude Code Return Prompt — FreightLogic Round 1B Gate

Repo: `https://github.com/fimseitef-a11y/FreightLogic-`

You are the only application-code agent in this round. ChatGPT/GPT stays out of application code until the UI seam extraction has merged and fresh `main` is green. Read `/AGENTS.md`, `/.agents/LANES.md`, and `/.agents/AUDIT_TRIAGE.md` from current `main` before doing anything. Read live `/.agents/STATUS.md`, `/.agents/TEST_LEDGER.md`, `/.agents/locks/`, and `/.agents/inbox/` from the long-lived `agent-coordination` branch.

Do not rediscover the basic repo state below unless current `main` has moved; verify only what changed since this prompt was generated.

## Current state you inherit

Coordination setup was prepared from `main` head:

`0835d06c4415929b24d5684430b957412b026612` — `ci: instrument guarded v24.0.1 repair gate`

Current application release markers are still v24.0.0. The v24.0.0 release commit is:

`5dddefbc9dbef0a586bd60d9d1bd787ec5aaf8f5` — Unified Decision Engine / single client verdict-grade-economics-bid authority; release message recorded 119 passed, 0 failed across 19 spec files on that PR head.

Several commits after that release are v24.0.1 CI/bank-import repair bootstrap/gate commits (`f48564c`, `8973330`, `d58e178`, `cd53d7f`, `0835d06`). Do not infer from those workflow commits that a bank-parser application repair is already on `main`; inspect current source/history if that matters in a later repair round.

Architecture:

- vanilla JS, offline-first PWA, no build system;
- `app.js` is still ~950,593 bytes and contains UI + IndexedDB/storage + tax + cloud client + decision engine + tracking + many feature modules;
- `app.js` is SHARED/serialized until this extraction succeeds;
- `service-worker.js`, `index.html`, `manifest.json`, and `sw-bridge.js` are also SHARED;
- v24 makes `app.js`'s Unified Decision Engine the sole deterministic verdict/grade/economics/bid authority;
- `midwest-stack-authority.js` is advisory/adapter-only, not a competing authority;
- current service worker release marker is v24.0.0 and its critical shell includes the Midwest authority script and bundled SheetJS vendor file.

## Audit triage already completed

Do not reclassify all findings unless current `main` materially changed after this prompt. The source-backed formal triage is:

- FIXED: **18**
- SUPERSEDED: **2**
- OPEN: **1**
- NEEDS-REVALIDATION: **0**

Formal OPEN item:

1. **X-12 — deployment parity checklist drift**. `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` still tells operators to verify v23.9.0 app/SW/manifest markers while current app/manifest/SW are v24.0.0. Historical X-12 was fixed in `1399d9ff7a8865f95851fe587add89a4a2913991`, then release drift reappeared after v24.

Residual implementation-risk OPEN item, tracked separately from the 21 formal findings:

2. **R-TOCTOU-EXPENSE-FUEL**. `updateExpense()` and `updateFuel()` still do unconditional full-object `put()` writes after reading the current object for audit purposes; unlike `upsertTrip()`, they do not compare an expected caller revision to the stored revision. `sanitizeExpense()`/`sanitizeFuel()` stamp a new `updatedAt` instead of preserving an expected version. This is the same lost-update class F-6 fixed for trips.

**Do not repair either item in this extraction round.** After extraction is merged and a separate repair round is approved, X-12 is first because it is a formal OPEN finding; R-TOCTOU-EXPENSE-FUEL is the first core-data repair after that.

Residual NEEDS-REVALIDATION gaps are field resilience on real iOS/device failure modes, full timed E2E journeys, usability/accessibility under field load, live Worker/invite behavior, exhaustive XSS/import surfaces, and an exhaustive F20/DZ activation matrix after v24. See `AUDIT_TRIAGE.md` for exact scope.

## Test harness — do not spend tokens rediscovering entry points

The aggregate command is:

```bash
node tests/run-all.mjs
```

One-time checkout setup documented by `tests/README.md` when Playwright is globally installed:

```bash
mkdir -p node_modules
ln -sfn "$(npm root -g)/playwright" node_modules/playwright
```

The aggregate runner imports exactly these 19 spec files on the coordination baseline:

Unit:
- `tests/unit/pure-functions.spec.mjs`
- `tests/unit/service-worker-shell.spec.mjs`
- `tests/unit/release-hygiene.spec.mjs`
- `tests/unit/pre-v24-integrity.spec.mjs`
- `tests/unit/v24-unified-decision.spec.mjs`

Integration:
- `tests/integration/dz-exit-grade-cap.spec.mjs`
- `tests/integration/tax-export-csv-corruption.spec.mjs`
- `tests/integration/pin-lockout.spec.mjs`
- `tests/integration/fl-tests-exposure.spec.mjs`
- `tests/integration/toctou-concurrent-edit.spec.mjs`
- `tests/integration/field-resilience.spec.mjs`
- `tests/integration/insurance-migration.spec.mjs`
- `tests/integration/export-checksum-integrity.spec.mjs`
- `tests/integration/backup-restore-parity.spec.mjs`
- `tests/integration/dz-gate-parity.spec.mjs`
- `tests/integration/xlsx-bundled-vendor.spec.mjs`
- `tests/integration/van-fit-precheck.spec.mjs`
- `tests/integration/v24-authority-boundaries.spec.mjs`
- `tests/integration/v24-economics-bid.spec.mjs`

`tests/run-all.mjs` exits non-zero when any assertion fails (`process.exit(totalFail ? 1 : 0)`). The prior 119/0 result belongs to the v24.0.0 PR head and is **not** a substitute for the baseline you must observe on your exact starting SHA.

The coordination ledger currently says:

`BASELINE: PENDING — requires Claude Code execution`

## ROUND A — BASELINE ONLY

1. Fetch current `main` and record its exact SHA.
2. Use the dedicated `agent-coordination` worktree/branch for STATUS/TEST_LEDGER/locks only. Never switch/reset/rebase the application worktree merely to reach coordination state.
3. Run the **full** Playwright suite once with `node tests/run-all.mjs`.
4. Append the exact SHA, environment/command, duration if available, total pass/fail, and every failing suite/test to `/.agents/TEST_LEDGER.md` on `agent-coordination`.
5. If RED:
   - classify each failure as reproducible product/test failure vs environment/infrastructure failure only when evidence supports that distinction;
   - one controlled rerun is allowed only if justified, and it must be logged too;
   - **DO NOT modify application code**;
   - **DO NOT skip, quarantine, weaken, rewrite, or delete any assertion**;
   - STOP and report the exact failures. Baseline remediation is a separate approved action.
6. If GREEN: append the result to STATUS and continue only to the proposal step below.

## HARD STOP 1 — UI seam proposal

On a green baseline, inspect `app.js` and propose the smallest clean physical extraction for presentation code, expected targets along the lines of dashboard/forms/navigation/intelligence/styles. Do not assume those exact modules are achievable; choose boundaries supported by the current source.

Your proposal must name:

- exact source regions/symbols to move,
- exact destination file paths,
- dependency/order constraints,
- required `index.html` script/style changes,
- required service-worker precache changes,
- whether any extracted file would still need to call into core globals,
- the rollback plan,
- expected diff shape.

Then **STOP and wait for human approval before executing the extraction.**

If there is no clean behavior-preserving seam, say so plainly and stop. Do not force parallelism by inventing a risky split.

## ROUND B — extraction, only after explicit human approval

Before editing any SHARED path, acquire the required lock(s) using `/AGENTS.md` exactly. `app.js` requires `lock/app-js` while monolithic. Never proceed merely because you created a local lock file; fresh remote coordination state must confirm your owner+token.

Branch: `agent/claude/<task>`
Commit prefix: `[claude]`
Never force-push.

Extraction rules:

- structural moves only;
- zero logic changes;
- zero renames;
- zero reformatting;
- zero Prettier passes;
- zero opportunistic cleanup;
- preserve statement/order semantics and global initialization order;
- if thousands of lines move, the diff should be recognizable as moves, not rewritten formatting;
- update service-worker precache and script load order deliberately in **their own commit**;
- do not mix X-12, TOCTOU, bank-import, tax, security, decision-engine, or any other repair into extraction commits.

Run the full suite after extraction and log it to TEST_LEDGER with exact SHA.

If post-extraction is RED, stop. Do not weaken tests. Restore/repair the structural extraction only as needed to return to behavior parity.

## HARD STOP 2 — merge checkpoint

When the extraction branch is green:

1. rebase onto current `main` without force-pushing;
2. open the extraction PR;
3. run/observe the full gate on the integrated PR head;
4. merge only when green;
5. confirm a fresh green `main` after merge;
6. release all owned shared locks;
7. update STATUS with what landed and exact new physical UI paths;
8. update `/.agents/LANES.md` and the standing GPT/Claude prompts with **real extracted paths**, not conceptual lanes.

Then STOP. **No audit fixes in this round.** Round 2 begins only on human go-ahead.

## Lock protocol

Obey `/AGENTS.md` verbatim. The crucial invariant: a rejected lock-claim push means the claim failed. Never rebase/cherry-pick/force that rejected claim commit. Fetch and inspect the exact lock path; only a newly-built lock-only commit from fresh coordination head may be retried when the exact lock is absent.
