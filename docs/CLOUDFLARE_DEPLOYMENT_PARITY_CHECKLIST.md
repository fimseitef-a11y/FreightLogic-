# Cloudflare Deployment Parity Checklist

Purpose: prove that the **production** Cloudflare app and backup/API Worker serve the exact FreightLogic completion candidate. Green source CI or a successful Cloudflare build is not enough by itself.

Current candidate:

- app / PWA / service worker: **24.0.5**;
- IndexedDB schema: **15**;
- backup/API Worker source: **14**;
- exact Git candidate: **`8d5b82b8cfaf9d2264d0220d49e598e7ce705eec`**;
- production app origin: **`https://freightlogic-v2.fimseitef.workers.dev`**;
- backup/API Worker origin: **`https://freightlogic-backup.fimseitef.workers.dev`**;
- certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-12.md`;
- status: **HOLD**.

Important: `https://freightlogic.pages.dev` was probed on 2026-09-12 and did not resolve. It is a legacy/stale origin, not the production app origin. Do not use it as the default certification target.

## 1. Exact app deployment

Record:

- GitHub `main` SHA;
- Cloudflare production build/version identifier;
- production app origin;
- production backup/API Worker origin;
- rollback SHA.

The 2026-09-12 post-merge recheck proved the checked production app assets are byte-for-byte identical to exact candidate `8d5b82b8cfaf9d2264d0220d49e598e7ce705eec`. Repeat after any later source change.

## 2. App / PWA generation

PASS requires production to serve:

- `app.js?v=24.0.5`;
- `voice-load.js?v=24.0.5`;
- `sw-bridge.js?v=24.0.5`;
- `midwest-stack-authority.js?v=24.0.5`;
- `manifest.json?v=24.0.5` identifying `FreightLogic v24.0.5`;
- `service-worker.js` with `SW_VERSION = '24.0.5'`;
- bundled `vendor/xlsx.full.min.js`;
- matching CSP/security headers;
- no failed JavaScript/static request answered with HTML shell fallback.

The 2026-09-12 production recheck passed these checks for v24.0.5 and exact main candidate `8d5b82b8cfaf9d2264d0220d49e598e7ce705eec`.

## 3. Worker v14 live checks

Expected backup/API Worker source generation: **14**.

PASS requires:

- `GET /health` returns HTTP 200 and JSON with `version: "14"`;
- no-origin fallback and requests from `https://freightlogic-v2.fimseitef.workers.dev` receive the real production app origin in `Access-Control-Allow-Origin`;
- unauthorized admin requests are denied;
- unauthorized driver/evaluate/extract/backup requests are denied;
- authenticated `/evaluate` preserves canonical available and `UNAVAILABLE` decisions;
- `/extract`, when enabled, returns bounded evidence only;
- authenticated full backup, delta backup, and restore smoke paths succeed without changing the data/authority contract;
- no token or secret is exposed in client-visible output.

### Current observed Worker state

The 2026-09-12 post-merge production recheck found:

- `/admin/users` without token -> 401: **PASS**;
- `/health` -> 401 `Missing token`: **FAIL**;
- `/health` response CORS `*`: **FAIL**;
- `OPTIONS /backup` from the real app origin -> 204 with CORS `*`: **FAIL**;
- unauthenticated `/evaluate` -> 401: **PASS**.

Those responses prove Worker v14 is not deployed at the backup/API Worker origin. Worker v14 must be deployed through the actual backup-Worker deployment path before this section can pass.

## 4. Canonical authority smoke

Use non-sensitive fixtures only.

PASS requires:

- canonical verdict, grade, True RPM/economics, and bid range remain client-owned;
- Midwest overlay remains advisory;
- an incomplete canonical decision remains `UNAVAILABLE` with unknown grade, null True RPM, and no invented bid;
- missing deadhead remains UNKNOWN while explicit `0` remains real zero;
- blank/underspecified market text cannot manufacture favorable geography;
- Gary, Indiana stays the intended U.S. Midwest Tier-1 market;
- 121-inch default cargo boundary remains enforced;
- precise True Profit is not asserted without defensible cost/mileage inputs.

## 5. Lifecycle / evidence durability

With synthetic data:

- manual/email-compatible intake persists normalized evidence before linkage;
- provenance, source times, mileage semantics, and price semantics survive reload;
- external IDs never become destructive internal identity;
- non-carrier prices do not become canonical revenue without allowed evidence;
- UNKNOWN mileage/deadhead never becomes zero;
- lifecycle progression remains evidence-backed;
- full backup + deltas + restore preserve protected records without downgrade/duplication;
- local export/import preserves lifecycle/evidence and excludes credentials/PIN/lockout state.

## 6. Automated helpers

Source-side:

- `node tests/run-all.mjs`
- `node scripts/verify-cloudflare-parity.mjs --static-only`
- `node scripts/m7-certify.mjs --suite`

Live production, from a network that can reach Cloudflare:

- `node scripts/verify-cloudflare-parity.mjs`

The live verifier now defaults to the real app origin `freightlogic-v2.fimseitef.workers.dev` and backup/API Worker origin `freightlogic-backup.fimseitef.workers.dev`.

Authenticated authority checks when a valid non-published driver token is available:

- `FL_BACKUP_TOKEN=... node scripts/verify-live-authority.mjs`
- add `--paid` only when explicitly appropriate for quota-spending extraction checks.

Network inability is `UNOBSERVED`, not PASS and not product failure.

## 7. Completion rule

Live Cloudflare parity is complete only when the same named candidate has:

- production app/PWA v24.0.5 parity PASS;
- backup/API Worker v14 `/health` and CORS parity PASS;
- auth boundaries PASS;
- canonical `/evaluate`/`/extract` checks PASS where applicable;
- authenticated backup/delta/restore smoke PASS;
- rollback evidence recorded.

Only after this live gate, the real private-history reconciliation, and the physical iPhone checklist all pass may a later certification-state document clear HOLD.
