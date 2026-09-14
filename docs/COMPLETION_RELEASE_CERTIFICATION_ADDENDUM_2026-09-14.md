# Completion release certification addendum — v24.0.9

Date: 2026-09-14
Supersedes: `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-13.md`
Status: **HOLD — v24.0.9 SOURCE + PRODUCTION BUILD ARE GREEN; LIVE PARITY RUNNER IS MERGED BUT NOT YET DISPATCHED; AUTHENTICATED SMOKES, PRIVATE-HISTORY RECONCILIATION, SIX-WIDTH VISUAL ACCEPTANCE, PHYSICAL-iPHONE EVIDENCE, AND FINAL ROLLBACK/FIX-FORWARD EVIDENCE REMAIN**

## Exact candidate

- Runtime Git SHA: `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` (merged PR #175).
- Current repository `main` after tooling/docs integration: `578acaeec1c67e25bad2e58967d81138186dae5f`.
- FreightLogic app/PWA/service-worker generation: **24.0.9**.
- IndexedDB schema: **15**.
- backup/API Worker source generation: **15**.
- Production app origin: `https://freightlogic-v2.fimseitef.workers.dev`.
- Production backup/API Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`.

PRs #177 and #178 changed verifier/workflow/tests/docs only; they did not change shipped runtime files or the v24.0.9 app/PWA/cache generation. This document remains the current certification authority. The September 13 state/addendum documents are historical evidence and must not be read as the current candidate.

## What changed after the September 13 addendum

### 1. The deployment-asset blind spot was closed in source

The prior addendum found a real defect: `admin-driver-ui.js` returned 404 in production even though the then-current parity check was green. The source-side deployment exclusion was repaired, and PR #174 replaced the curated live-asset list with a derived runtime inventory shared by static deployment coverage tests and the live parity verifier.

For the current candidate, source tests assert that every runtime-requested asset exists, no runtime asset is excluded by `.assetsignore`, the live parity verifier sweeps the same derived inventory, and `admin-driver-ui.js` is specifically present/deployable. The current derived inventory is **23 runtime assets**.

This closes the source/test defect class. It does **not** by itself prove that the production origin serves all 23 current bytes correctly.

### 2. v24.0.9 pickup feasibility landed

PR #175 integrates the completed "Can You Even Get There" gate. The evaluator checks pickup-time feasibility after dimensional fit and before economics when — and only when — the operator has supplied enough facts.

Important authority rules remain explicit:

- there is **no invented default planning speed**;
- unset/out-of-range planning speed makes the check inapplicable rather than guessing;
- missing deadhead remains UNKNOWN, never zero;
- explicit zero deadhead remains a real zero;
- no cutoff means no pickup-time block;
- an unreachable or already-passed pickup blocks before economics;
- a reachable but narrow window is advisory only and does not alter canonical verdict/grade/bid economics.

The optional pickup-cutoff field and Trip Planning speed setting therefore do not change existing decisions until the operator explicitly supplies a planning speed. PR #178 also reconciled the backup contract so an explicitly set `planningAvgMph` is durable while a missing/cleared value stays absent and may not be invented or clamped during restore/import.

### 3. Integrated CI is green and the live-runner safety contract is covered

PR #175 full Playwright run `34796439138` completed successfully with **431 passed, 0 failed across 45 spec files** on the exact runtime candidate. After merge, `main` run `34796618850` also completed SUCCESS on that runtime SHA.

PR #177 then added the read-only live-parity runner and explicit PASS/FAILURE/UNOBSERVED verifier semantics. PR #178 updated the backup contract only. Current `main` run `34799469734` completed **442 passed, 0 failed across 46 spec files**. The added `unit/live-parity-runner.spec.mjs` contributes 11 assertions covering:

- manual-dispatch-only workflow policy;
- `contents: read` and no secret use;
- dispatch inputs never reaching the shell through unsafe direct interpolation;
- execution of the real verifier rather than a curated substitute;
- PASS exit 0;
- FAILURE exit 1 for an observed mismatch;
- UNOBSERVED exit 2 only when no HTTP observation can be made;
- any actual HTTP response, including 404/500, counting as observed;
- static failures outranking network unreachability.

Successful test runs are source/tooling evidence, not live-origin evidence.

### 4. Cloudflare built the exact runtime candidate successfully

Cloudflare's GitHub check for exact runtime SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` completed **SUCCESS** for production service `freightlogic-v2`:

- Build ID: `8caa3ac9-511f-4d9d-835f-cf6ba916cca7`
- Version ID: `ba1edf4d-f9c5-4836-a1b8-e2be1d0f6b0f`

Subsequent tooling/docs `main` builds also succeeded, but they do not create a new FreightLogic runtime generation because the shipped runtime files did not change.

A successful Cloudflare build proves that Cloudflare accepted/deployed the source tree; it does **not** substitute for a live all-asset origin comparison.

### 5. A production-network runner now exists, but its result is still unobserved

PR #177 merged `.github/workflows/verify-live-parity.yml`, a manual-only, read-only **Verify Live Parity** workflow that runs the real `scripts/verify-cloudflare-parity.mjs` from a GitHub-hosted runner. It performs no deploy and no repository write and needs no driver/admin secret.

The exact v24.0.9 all-asset live parity sweep remains **NOT RUN / UNOBSERVED** until that workflow is actually dispatched on `main` with its optional origins left blank and a run result is recorded. The ChatGPT GitHub connector used in this session can inspect and rerun existing Actions jobs but does not expose creation of a `workflow_dispatch` run, so this missing observation is not promoted to PASS.

## Worker v15 evidence carried forward

The backup/API Worker did not change in v24.0.9. On 2026-09-13 the production Worker was directly observed at generation 15 with:

- `GET /health` HTTP 200 / version 15;
- exact production-app-origin CORS on health GET;
- backup preflight OPTIONS HTTP 204 with exact production origin;
- unauthorized admin request denied with HTTP 401.

The earlier requirement to redeploy Worker v15 remains discharged. Authenticated behavior is separate and remains open.

## Current blocking checklist

- [x] v24.0.9 source integrated through PR #175.
- [x] PR #175 lane/ownership gate passed.
- [x] Exact runtime suite passed: **431/0 across 45 specs**.
- [x] Merged-runtime `main` test run `34796618850` passed on exact runtime SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2`.
- [x] Cloudflare production build succeeded for exact runtime SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2`.
- [x] Source deployment inventory covers every declared runtime asset and no longer excludes `admin-driver-ui.js`.
- [x] Worker v15 health/CORS/unauthorized-admin free checks were observed on 2026-09-13 and Worker source is unchanged.
- [x] Manual/read-only **Verify Live Parity** workflow merged through PR #177 with explicit PASS/FAILURE/UNOBSERVED semantics.
- [x] Current post-tooling `main` suite passed: **442/0 across 46 specs** in run `34799469734`.
- [x] Backup contract reconciled through v24.0.9, including optional `planningAvgMph`, via PR #178.
- [ ] Dispatch **Verify Live Parity** on `main` with blank optional origins and record the actual live verdict, runtime-asset count, and any failed checks.
- [ ] Verify service-worker-controlled reload/offline cache behavior on the exact v24.0.9 production candidate, including the previously missing admin script.
- [ ] Run authenticated `/evaluate` and `/extract` authority smokes with a dedicated non-published test identity.
- [ ] Run authenticated full/delta backup, restore, and in-place token-rotation smokes without exposing credentials or risking real data.
- [ ] Reconcile the recovered private-history bundle through the actual application import/reload/export/idempotence/conflict path.
- [ ] Complete six-width visual acceptance (320, 375, 390, 393, 430, 440), dark/light, touch targets, and overflow on the same candidate.
- [ ] Complete physical iPhone Safari + installed-PWA checks on the same candidate, including the pickup-feasibility surface.
- [ ] Repair and run the final rollback/fix-forward evidence generator against v24.0.9 / Worker v15.

## Private-history status

The recovered August 27 M6 bundle remains outside the public repository. Existing preflight evidence says 216 source rows deterministically produce 149 candidate records, but those candidates have **not** completed the required application round trip, idempotence run, and source-conflict review in this certification session.

The raw bundle is not mounted in the current execution session and searches of the connected File Library, Dropbox, and Google Drive did not find the bundle under its recorded bundle/source filenames. Therefore the real-data round-trip remains NOT RUN. The separate 125-row master also remains unavailable. Do not reconstruct either dataset from summaries. Do not fill unknown deadhead with zero, promote quote observations to completed trips, or infer broker identity/revenue without evidence.

## Authentication limits

No valid dedicated test driver token is available in this session. Therefore authenticated evaluate/extract/backup/restore/rotation behavior is **NOT RUN**, not PASS. Tokens must not be pasted into repository files, PR comments, logs, or public documentation.

## Rollback/fix-forward evidence is currently tooling-blocked, not failed

The current `scripts/verify-rollback.mjs` still carries an obsolete production-candidate literal and a stale Worker-v14 expectation even though the current release uses Worker v15. This can make the verifier fail for the wrong reason. A bounded Claude-owned correction was requested through the coordination inbox.

Until that correction lands and is observed, the B5 rollback/fix-forward gate is **NOT RUN / TOOLING STALE**. The default policy remains fix-forward unless a genuinely safe rollback target is proved; an older known-regression build may not be labelled safe merely because it exists.

## Canada-floor conflict is not silently resolved

The repository contains materially different Canada rate narratives with different provenance. Current recovered context does not prove that they have the same authority or describe the same thing (protective floor, target, or market observation). No Canada protective floor is changed in v24.0.9. The conflict remains item 34 in `docs/OPEN_QUESTIONS.md` and may be resolved only by explicit operator correction or stronger primary evidence.

## Administrative cleanup

- PR #171 was closed unmerged as superseded.
- PR #170, the non-blocking brand-source staging PR, was closed unmerged on 2026-09-14 and deferred until after completion certification. Its branch remains available for future post-release branding work; runtime icons/cache generation were deliberately not changed during the certification freeze.
- PRs #177 and #178 are merged and are tooling/docs only.

## Final rule

FreightLogic remains **HOLD**. Source completeness, green CI, a successful Cloudflare production build, and a correctly engineered live-parity runner are necessary but insufficient. The hold may be cleared only by a later authoritative certification document after actual live parity, controlled service-worker/offline production behavior, authenticated authority/backup smokes, real private-history reconciliation, six-width visual acceptance, physical-iPhone/PWA evidence, and truthful rollback/fix-forward evidence are all observed on one named final candidate.
