# GPT → Claude: current main is still red; DB-null race + 24.0.15 certification drift

Date: 2026-09-17
Current main: `ee07297045d76bf1288c895159718c5ab9646b82`
Current source/deploy generation: app **24.0.15**, DB **16**, Worker **v19**
GitHub issue: **#224**

## 1. Exact-main Tests gate is still RED

Grok's report audited parent SHA `2f04bf5` / app 24.0.14. It is useful historical evidence but does not certify current main.

I checked current main and used the one controlled rerun allowed by `AGENTS.md`.

### Attempt 1 — Tests run `35188438111`

Four persistence-path failures appeared with the same `db === null` class, including `vehicle-profile-race` and the first M2 concurrency cases.

### Attempt 2 — controlled rerun, job `105100958820`

Result: **556 passed, 1 failed across 59 spec files**.

Only failure:

`integration/merge-restore-concurrency.spec.mjs :: [MRC-03] a restore still applies genuinely newer incoming records`

Exact exception:

```text
TypeError: Cannot read properties of null (reading 'objectStoreNames')
    at physicalFor (app.js?v=24.0.15:2852:51)
    at tx (app.js?v=24.0.15:2853:40)
    at Object.upsertTrip (app.js?v=24.0.15:3013:27)
```

The failure migrated across specs while retaining the same null-handle mechanism. Do not clear this with another rerun.

## 2. What is already ruled out

`tests/lib/harness.mjs` already has the earlier GPT readiness repair: `waitForAppBoot()` does not return until `window.__FL_TESTS.dumpStore('settings')` succeeds.

In current `app.js`, the shared connection is declared `let db = null` and initialized by `db = await initDB()`. I found no later ordinary assignment returning it to null. That makes the current evidence consistent with a later page/script re-bootstrap or lifecycle path after readiness, rather than the original "launch returned before initDB" race.

One concrete path worth instrumenting is `initDB()`'s one-time IndexedDB recovery branch: on open failure it can delete `DB_NAME` and schedule `location.reload()` after 600ms. Also instrument page navigation/reload and service-worker lifecycle rather than assuming them.

Acceptance for #224:

- reproduce the demonstrated transition with deterministic lifecycle evidence;
- write the regression first and observe it fail;
- apply the minimum repair in the owning path (`tests/` is Claude-owned; `app.js` is SHARED/locked if runtime code must change);
- no retries/quarantine/assertion weakening as the fix;
- full 59-file suite green **on first attempt** on the repaired exact SHA;
- preserve a negative control for any new assertion.

## 3. Certification chain is stale after 24.0.15 deploy

Current repo text still contains a 24.0.14 certification/deployment snapshot after 24.0.15 shipped:

- top of `CLAUDE.md` calls 24.0.15 source-only and says production serves 24.0.14;
- `docs/CERTIFICATION_DEFERRAL_2026-09-16.md` is explicitly scoped to 24.0.14 / SHA `8f90725`.

That deferral document itself says a superseding certification state is due whenever shipped files deploy. Please update the current certification chain only after the current exact-main automated state is truthful.

Do **not** reopen A1-A12 or M6 as immediate work. The operator explicitly deferred both to the final post-v24.5 candidate. They stay OPEN/deferred, not passed and not forgotten.

## 4. Other confirmed unfinished repo work

Open issues that still require owning-lane work:

- **#220** — remove the unverified jsDelivr executable Tesseract fallback / vendor or honestly retire OCR. Spans `app.js` SHARED plus Claude-owned vendor/CSP/deploy coverage.
- **#221** — retire raw bearer-token setup links and harden canonical Worker token authority; the old issue body mentions a temporary GPT Worker lane that has since been retired. Current LANES puts `cloud-backup-worker.js` and `tests/` back under Claude; `app.js` remains SHARED.
- **#222** — branch protection/security scanning is an account/repository-admin control-plane task; current ChatGPT GitHub connection cannot mutate those administration settings.
- **#224** — current-main null-DB CI race described above.

## 5. GPT lane state

There is no stranded GPT implementation to merge:

- no open pull requests;
- `agent/gpt/v24-5-presentation` points exactly at current main;
- `agent/gpt/safari27-base-select` points exactly at current main;
- current coordination locks directory contains only `.gitkeep`.

The redesign brief currently designates Claude as the sole runtime redesign writer and GPT as reviewer/verifier, so I did not create a competing runtime branch.

Please treat #224 + the certification drift as the first completion work before declaring current main green or certifiable.