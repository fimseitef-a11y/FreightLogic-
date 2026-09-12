# FreightLogic Completion Release — Certification Addendum

Date: 2026-09-12 06:45 UTC
Exact candidate source: `8d5b82b8cfaf9d2264d0220d49e598e7ce705eec`
Runtime identity: **FreightLogic v24.0.5 / IndexedDB v15 / Worker v14 source**
Supersedes: COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-12.md, COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-02.md
Status: **HOLD — APP/PWA EXACT PRODUCTION PARITY PASS; BACKUP/API WORKER V14 IS NOT DEPLOYED; PRIVATE-HISTORY AND PHYSICAL-IPHONE EVIDENCE REMAIN**

This addendum records the exact post-merge candidate and live recheck. It also explicitly closes the still-current 2026-09-02 branch left by the 2026-09-03 record's path-formatted supersession value; historical state files remain immutable evidence.

## Exact-candidate source and CI evidence

GitHub `main` at `8d5b82b8cfaf9d2264d0220d49e598e7ce705eec` includes the Worker-v14 production-origin repair, the operator-measured van profile, and the parity-verifier reporting repair.

GitHub Actions run `34678494045` passed for this exact candidate:

- **376 passed / 0 failed across 40 spec files**;
- lane/path/lock enforcement passed;
- static Cloudflare parity passed;
- all required workflow jobs completed successfully.

The source and repository-governance gate is **PASS** for this exact SHA. That result does not prove that the separate backup/API Worker was deployed.

## Exact production app parity

Observed production app origin: `https://freightlogic-v2.fimseitef.workers.dev`.

Direct production retrieval on 2026-09-12 showed HTTP 200, the expected security policy, and exact byte parity between the live responses and candidate `8d5b82b8cfaf9d2264d0220d49e598e7ce705eec`:

| Asset | Candidate/live SHA-256 |
|---|---|
| `index.html` | `4d14b7c63fd0b6ebf8c1079b1e3bc65d24c5f7d96cb8353368f952f817fc87c0` |
| `app.js` | `ba2169228efc83f4b89dc557833596e0f5fca4c129802ca01a6c49793cc2e611` |
| `service-worker.js` | `9f4a470fa8f65f09d5a7811df275de1a8ec253377c840e268a91e84a5358bfc9` |
| `manifest.json` | `2c437d7a6fb65a5f68e402304b2d7d58360c6d1fbcc7ba6b2c52f3273b8e92e2` |
| `voice-load.js` | `057cb244e27efecb7ac41cd256ec7bc52417abb77f6269265efec7021c2d79b9` |
| `sw-bridge.js` | `44e34e3e49cfd85d74b97843c3851b9c9af1f0a86a6733f36130b2f74c92fcdf` |
| `midwest-stack-authority.js` | `d3f271a53442de82608c5938bf40c9b2772229a72499ecab6f06dda04d414d5f` |
| `midwest-stack-config.json` | `99fb3cd3b62604321e6fec17c94468d07435800c4b3d152f3edc917738a31001` |

The live index, manifest, cache generation, app runtime, and service worker all identify v24.0.5. The live app also contains the operator-measured **54.8-inch wheel-well width** and **3,000-pound payload** constraints merged in this candidate.

Therefore the production app/PWA exact-candidate parity gate is **PASS**.

## Backup/API Worker remains a live failure

Observed production Worker origin: `https://freightlogic-backup.fimseitef.workers.dev`.

The post-merge live recheck produced:

- `GET /health` with the real app origin -> HTTP 401, `{"ok":false,"error":"Missing token"}`: **FAIL**;
- that response returned `Access-Control-Allow-Origin: *`: **FAIL**;
- `OPTIONS /backup` with the real app origin -> HTTP 204 with `Access-Control-Allow-Origin: *`: **FAIL**;
- unauthenticated `GET /admin/users` -> HTTP 401: **PASS**;
- unauthenticated `POST /evaluate` -> HTTP 401: **PASS**.

Running the current live verifier against both production origins exits non-zero with exactly the Worker health/version failures; every app check and the unauthenticated admin boundary pass.

Current Worker-v14 source makes `/health` unauthenticated, reports `version: "14"`, and returns the allowed production origin rather than `*`. The observed response therefore proves that Worker v14 is **not deployed** at the backup/API Worker origin. Gate 2 remains **FAIL / REDEPLOY REQUIRED**.

## Deployment-control boundary

The repository's `wrangler.jsonc` configures the separate `freightlogic-v2` app/assets service. It is not a safe deployment configuration for `cloud-backup-worker.js`, and the repository does not expose the production `BACKUPS` KV namespace identifier. No deployment was attempted with guessed bindings or against the app service.

An authenticated Cloudflare control-plane session is required to deploy the merged Worker-v14 source through the existing `freightlogic-backup` deployment path while preserving:

- `BACKUPS` KV binding;
- `ADMIN_TOKEN` secret;
- `OPENAI_API_KEY` secret where extraction is enabled;
- optional `OPENAI_MODEL` configuration;
- `ALLOWED_ORIGIN=https://freightlogic-v2.fimseitef.workers.dev`.

After deployment, rerun unauthenticated health/CORS/auth checks and authenticated evaluate/extract/backup/delta/restore smokes with a valid non-published token. Do not publish bindings, tokens, secrets, or private payloads as evidence.

## Other unresolved blocking evidence

### Private operator history

The repository and all supplied project archives were checked for the real raw row-level operator master; none contains it. Summaries mention a 125-row master but are not a substitute for the source. This gate remains **SOURCE FILE MISSING / NOT RUN**. Do not reconstruct rows from summaries.

### Physical iPhone

The finite checks in `FIELD_TEST_CHECKLIST.md` have not been run on this exact candidate. This gate remains **NOT RUN**. Do not clear Safari website data or delete the installed PWA merely to force an update, because that can destroy IndexedDB evidence.

## Certification rule and next actions

The release remains **HOLD**. The shortest valid sequence is:

1. deploy Worker v14 through the authenticated backup-Worker path without disturbing the app/assets service;
2. prove Worker-v14 health, exact production-origin CORS, auth boundaries, canonical authority, and backup/restore parity;
3. recover or re-export the real private row-level history and run the current reconciliation machinery;
4. run the physical-iPhone checklist against the same named production candidate;
5. record an executable rollback SHA/procedure;
6. create a later certification state/addendum that explicitly supersedes this HOLD and records release and rollback SHAs.

Controlling sequence: **EVIDENCE -> TEST -> CHALLENGE -> RECONCILE -> CERTIFY -> ADOPT**.
