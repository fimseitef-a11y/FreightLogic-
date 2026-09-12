# FreightLogic Completion Release — Certification State

Date: 2026-09-12
Candidate source base: `d34cdd9c7075a9466ebc5423a38ebbf7bb80cf92` plus the bounded Worker-v14 production-origin repair in this change
Runtime identity: **FreightLogic v24.0.5 / IndexedDB v15 / Worker v14 source**
Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-11.md
Status: **HOLD — APP/PWA PRODUCTION PARITY OBSERVED; BACKUP/API WORKER MUST BE REDEPLOYED AS V14; PRIVATE-HISTORY AND PHYSICAL-IPHONE EVIDENCE REMAIN**

This record supersedes the 2026-09-11 state because a real production probe produced new evidence. Historical state files remain immutable evidence.

## What the production probe proved

A temporary branch-only GitHub Actions probe ran from a GitHub-hosted network and was removed/reset after use. It did not modify production source.

Observed production app origin: `https://freightlogic-v2.fimseitef.workers.dev`.

The old verifier default `https://freightlogic.pages.dev` did not resolve and is not the current production app origin.

Against the real production app origin, the existing parity verifier passed the app/PWA checks for v24.0.5:

- index: HTTP 200;
- `app.js?v=24.0.5`;
- `voice-load.js?v=24.0.5`;
- `sw-bridge.js?v=24.0.5`;
- service worker: HTTP 200 and version 24.0.5;
- critical shell includes Midwest authority + bundled SheetJS;
- authority config is present and the retired rate-overrides asset is absent;
- Midwest overlay loads and exposes its expected API;
- manifest loads and identifies `FreightLogic v24.0.5`;
- source/deployed CSP checks passed.

Cloudflare Git metadata also tied the exact merged v24.0.5 main candidate to a successful `freightlogic-v2` production build.

Therefore **production app/PWA/static parity is observed PASS for v24.0.5**. This does not certify the separate backup/API Worker or the physical device.

## Live backup/API Worker finding

Production Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`.

Observed:

- unauthenticated `/admin/users` returns 401: **PASS**;
- `/health` returns 401 `{"ok":false,"error":"Missing token"}`: **FAIL** against current source contract;
- the response exposed `Access-Control-Allow-Origin: *`, which also differs from current source behavior.

Worker v13 source defines `/health` as an unauthenticated route before driver-token enforcement. The production response therefore proves the deployed backup/API Worker is stale or otherwise not the current repository source.

The same probe exposed a source-side deployment hazard: v13 still defaulted CORS to the dead `freightlogic.pages.dev` origin. This bounded repair advances Worker source to **v14** and:

- makes `https://freightlogic-v2.fimseitef.workers.dev` the production/default CORS origin;
- keeps the old Pages origins only as legacy accepted origins;
- keeps `/health` unauthenticated and advances its source version to `14`;
- updates the live verifier default to the real production app origin and expects Worker `14`;
- adds regression coverage for the production-origin CORS contract.

The app/PWA generation remains v24.0.5 and DB remains v15.

## Automated/source gate for this repair

Before this state can be treated as the current source-ready candidate, the exact Worker-v14 repair PR must pass:

- full Playwright/Node suite;
- lane/path/lock enforcement;
- static parity;
- Worker health/CORS regressions;
- all existing v24.0.5 authority/UNKNOWN/backup/import/export regressions.

No source change is allowed to be called complete merely because the live v13 deployment is stale.

## Remaining blocking evidence

### 1. Deploy and observe Worker v14

The repository does not contain a safe standalone deployment configuration for `cloud-backup-worker.js`: `wrangler.jsonc` deploys the separate `freightlogic-v2` app/assets service. Do not overwrite that service or guess KV namespace/binding identifiers.

After Worker v14 is deployed through the actual backup-Worker deployment path, rerun the live verifier. PASS requires:

- `/health` HTTP 200 with `version: "14"`;
- exact CORS behavior for the real app origin;
- unauthenticated admin/driver boundaries remain denied as designed;
- authenticated `/evaluate`, `/extract` where enabled, backup/full-delta/restore smokes preserve the canonical contracts.

Until then, backup/API Worker parity remains **FAIL / REDEPLOY REQUIRED**.

### 2. Private operator-history reconciliation

The raw row-level operator master dataset is not present in the accessible repository/File Library. A recovered handoff says a 125-row master existed, but explicitly warns not to reconstruct missing rows from summaries. The gate is therefore **SOURCE FILE MISSING / NOT RUN**, not PASS or FAIL.

### 3. Physical iPhone certification

Run the finite blocking checks in `FIELD_TEST_CHECKLIST.md` on the exact production app + Worker-v14 candidate. Do not clear Safari site data or delete the existing PWA merely to force an update because that can destroy IndexedDB evidence.

## Certification rule

The release remains **HOLD**. It may be frozen only after:

1. the exact Worker-v14 source repair is green and merged;
2. the backup/API Worker is actually redeployed and live parity passes;
3. the private-history gate is run from the real raw source bundle;
4. the physical iPhone gate passes on the same named candidate;
5. a later certification-state record explicitly supersedes this HOLD and records release + rollback SHAs.

Controlling sequence: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT**.
