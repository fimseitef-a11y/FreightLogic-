# Completion release certification addendum — v24.0.9

Date: 2026-09-14
Supersedes: `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-13.md`
Status: **HOLD — v24.0.9 SOURCE + PRODUCTION BUILD ARE GREEN; EXACT LIVE ASSET PARITY, AUTHENTICATED SMOKES, PRIVATE-HISTORY RECONCILIATION, SIX-WIDTH VISUAL ACCEPTANCE, AND PHYSICAL-iPHONE EVIDENCE REMAIN**

## Exact candidate

- Runtime Git SHA: `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` (merged PR #175).
- FreightLogic app/PWA/service-worker generation: **24.0.9**.
- IndexedDB schema: **15**.
- backup/API Worker source generation: **15**.
- Production app origin: `https://freightlogic-v2.fimseitef.workers.dev`.
- Production backup/API Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`.

This document is the current certification authority once merged. The September 13 state/addendum documents remain historical evidence and must not be read as the current candidate.

## What changed after the September 13 addendum

### 1. The deployment-asset blind spot was closed in source

The prior addendum found a real defect: `admin-driver-ui.js` returned 404 in production even though the then-current parity check was green. The source-side deployment exclusion was repaired, and PR #174 replaced the curated live-asset list with a derived runtime inventory shared by static deployment coverage tests and the live parity verifier.

For the current candidate, source tests assert that every runtime-requested asset exists, no runtime asset is excluded by `.assetsignore`, the live parity verifier sweeps the same derived inventory, and `admin-driver-ui.js` is specifically present/deployable. The current derived inventory is **23 runtime assets**.

This closes the source/test defect class. It does **not** by itself prove that the production origin serves all 23 current bytes correctly.

### 2. v24.0.9 pickup feasibility landed

PR #175 integrates the completed "Can You Even Get There" gate. The evaluator now checks pickup-time feasibility after dimensional fit and before economics when — and only when — the operator has supplied enough facts.

Important authority rules remain explicit:

- there is **no invented default planning speed**;
- unset/out-of-range planning speed makes the check inapplicable rather than guessing;
- missing deadhead remains UNKNOWN, never zero;
- explicit zero deadhead remains a real zero;
- no cutoff means no pickup-time block;
- an unreachable or already-passed pickup blocks before economics;
- a reachable but narrow window is advisory only and does not alter canonical verdict/grade/bid economics.

The new optional pickup-cutoff field and Trip Planning speed setting therefore do not change existing decisions until the operator explicitly supplies a planning speed.

### 3. Integrated CI is green

PR #175 full Playwright run **34796439138** completed successfully with **431 passed, 0 failed across 45 spec files**. The lane/ownership workflow also completed successfully. The run includes the new pickup-feasibility unit/integration matrix, deployment-asset coverage, cache-generation parity, service-worker update/offline behavior, lifecycle/evidence/import/backup authority checks, and the existing completion-release regression suite.

A successful test run is source evidence, not live-origin evidence.

### 4. Cloudflare built the exact merged candidate successfully

Cloudflare's GitHub check for exact `main` SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` completed **SUCCESS** for production service `freightlogic-v2`:

- Build ID: `8caa3ac9-511f-4d9d-835f-cf6ba916cca7`
- Version ID: `ba1edf4d-f9c5-4836-a1b8-e2be1d0f6b0f`

This proves that Cloudflare accepted and built/deployed the exact merged candidate. It does **not** substitute for `node scripts/verify-cloudflare-parity.mjs`, which must fetch the live origin and compare every declared runtime asset.

The exact v24.0.9 all-asset live parity sweep is **NOT RUN / UNOBSERVED** in this GPT session because the available execution/web path cannot directly reach the production Workers origin. That limitation is recorded rather than converted into a PASS.

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
- [x] PR #175 full suite passed: **431/0 across 45 specs**.
- [x] Cloudflare production build succeeded for exact merged `main` SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2`.
- [x] Source deployment inventory covers every declared runtime asset and no longer excludes `admin-driver-ui.js`.
- [x] Worker v15 health/CORS/unauthorized-admin free checks were observed on 2026-09-13 and Worker source is unchanged.
- [ ] Run the v24.0.9 live all-asset parity sweep against the production origin and record every derived runtime asset as exact-match/valid-content.
- [ ] Verify service-worker-controlled reload/offline cache behavior on the exact v24.0.9 production candidate, including the previously missing admin script.
- [ ] Run authenticated `/evaluate` and `/extract` authority smokes with a dedicated non-published test identity.
- [ ] Run authenticated full/delta backup, restore, and in-place token-rotation smokes without exposing credentials or risking real data.
- [ ] Reconcile the recovered private-history bundle through the actual application import/reload/export/idempotence/conflict path.
- [ ] Complete six-width visual acceptance (320, 375, 390, 393, 430, 440), dark/light, touch targets, and overflow on the same candidate.
- [ ] Complete physical iPhone Safari + installed-PWA checks on the same candidate, including the new pickup-feasibility surface.

## Private-history status

The recovered August 27 M6 bundle remains outside the public repository. Existing preflight evidence says 216 source rows deterministically produce 149 candidate records, but those candidates have **not** completed the required application round trip, idempotence run, and source-conflict review in this certification session.

The separate 125-row master remains unavailable. Do not reconstruct it from summaries. Do not fill unknown deadhead with zero, promote quote observations to completed trips, or infer broker identity/revenue without evidence.

## Authentication limits

No valid dedicated test driver token is available in this session. Therefore authenticated evaluate/extract/backup/restore/rotation behavior is **NOT RUN**, not PASS. Tokens must not be pasted into repository files, PR comments, logs, or public documentation.

## Canada-floor conflict is not silently resolved

The repository currently contains two materially different Canada rate narratives: a June broker relay with lower observed/quoted ranges and later policy material carrying a substantially higher U.S.→Canada protective floor/target. Current recovered context does not prove that both figures have the same authority. No Canada protective floor is changed in v24.0.9. The conflict belongs in `docs/OPEN_QUESTIONS.md` until an explicit operator correction or primary authority resolves it.

## Administrative cleanup

PR #171 was closed unmerged as superseded because later main history already carries the Worker-v15 state and the branch had become materially stale. PR #170 remains a separate docs-only brand-source change and is not a runtime/certification blocker.

## Final rule

FreightLogic remains **HOLD**. Source completeness, green CI, and a successful Cloudflare production build are necessary but insufficient. The hold may be cleared only by a later authoritative certification document after exact live parity, authenticated authority/backup smokes, real private-history reconciliation, six-width visual acceptance, and physical-iPhone/PWA evidence are actually observed on one named final candidate.
