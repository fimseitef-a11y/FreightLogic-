# Cloudflare Deployment Parity Checklist

Purpose: prove that the **production** Cloudflare app and backup/API Worker serve the exact FreightLogic completion candidate. Green source CI, a successful Cloudflare build, or a source version bump is not enough by itself.

Current runtime candidate:

- app / PWA / service worker source: **24.0.9**;
- IndexedDB schema: **15**;
- backup/API Worker source: **15**;
- exact runtime Git candidate: **`5446b097fe8791f3d7c79b5a5833a0930ee83cf2`** (merged PR #175);
- production app origin: **`https://freightlogic-v2.fimseitef.workers.dev`**;
- backup/API Worker origin: **`https://freightlogic-backup.fimseitef.workers.dev`**;
- Cloudflare production build for this exact Git SHA: **SUCCESS**, build `8caa3ac9-511f-4d9d-835f-cf6ba916cca7`, version `ba1edf4d-f9c5-4836-a1b8-e2be1d0f6b0f`;
- certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-14.md` once merged;
- status: **HOLD**.

Important: `https://freightlogic.pages.dev` is a legacy/stale origin and is not the production app origin.

## 1. Exact app deployment

Record:

- GitHub `main` runtime SHA;
- Cloudflare production build/version identifier;
- production app origin;
- production backup/API Worker origin;
- rollback/fix-forward reference.

### Current source/deploy evidence

For v24.0.9, GitHub/Cloudflare reports a successful production Workers build for exact `main` SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2`. That is deployment-build evidence only; it is **not** a substitute for a live origin parity run.

The prior v24.0.8 admin-script defect is repaired in source: `.assetsignore` no longer excludes `admin-driver-ui.js`, and the deploy-asset regression gate now derives the complete runtime inventory and asserts that every requested runtime asset exists and is deployable. The current derived source inventory is 23 assets. A full live-green parity run must fetch **every derived runtime asset**, not a curated subset, and must reject an HTML shell returned with HTTP 200 for a JavaScript/CSS/JSON/image request.

The exact v24.0.9 all-asset live sweep remains **NOT RUN / UNOBSERVED** in this GPT session because the available network path cannot reach the production Workers origin directly. Do not infer PASS from the successful Cloudflare build.

## 2. App / PWA generation

PASS requires production to serve:

- `app.js?v=24.0.9`;
- `voice-load.js?v=24.0.9`;
- `sw-bridge.js?v=24.0.9`;
- `midwest-stack-authority.js?v=24.0.9`;
- `manifest.json?v=24.0.9` identifying `FreightLogic v24.0.9`;
- `service-worker.js` with `SW_VERSION = '24.0.9'`;
- `admin-driver-ui.js?v=24.0.9` and every other asset derived by the runtime inventory;
- current `modern-shell.js` bytes from the named candidate;
- bundled `vendor/xlsx.full.min.js`;
- the current `styles.css` visual layer;
- matching CSP/security headers;
- no failed JavaScript/static request answered with an HTML shell fallback.

Do not reuse the v24.0.5 or v24.0.8 production observations as exact-generation evidence for v24.0.9.

## 3. Worker v15 live checks

Expected backup/API Worker source generation: **15**.

PASS requires:

- `GET /health` returns HTTP 200 and JSON with `version: "15"`;
- requests from `https://freightlogic-v2.fimseitef.workers.dev` receive that exact origin in `Access-Control-Allow-Origin`;
- unauthorized admin requests are denied;
- unauthorized driver/evaluate/extract/backup requests are denied;
- authenticated `/evaluate` preserves canonical available and `UNAVAILABLE` decisions;
- `/extract`, when enabled, returns bounded evidence only;
- authenticated full backup, delta backup, and restore smoke paths succeed without changing the data/authority contract;
- no token or secret is exposed in client-visible output;
- in-place token rotation preserves the existing user identity and backup history.

### Current observed Worker state

On 2026-09-13 Worker v15 was observed at the production origin: health HTTP 200/version 15, exact production-origin CORS on health GET and backup OPTIONS (204), and unauthorized admin HTTP 401. Worker source/generation did not change in v24.0.9, so no Worker redeploy is required by the app-generation bump.

Authenticated evaluate/extract/full-delta-restore/token-rotation checks remain **NOT RUN** because no dedicated non-published test token is available in this session. The manual `Deploy Backup Worker` workflow remains the intended deployment boundary and must remain explicit/manual.

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
- 54.8-inch wheel-well width and 3,000-pound practical payload limits remain enforced;
- precise True Profit is not asserted without defensible cost/mileage inputs;
- v24.0.9 pickup feasibility remains fail-closed: no planning speed means no invented reachability verdict; unknown deadhead never becomes zero; once an operator planning speed and pickup cutoff are supplied, an unreachable pickup blocks before economics.

## 5. Structural shell parity

Production parity must confirm:

- primary navigation is **Today / Loads / Evaluate / Trips / Money**;
- Loads uses the existing canonical load inbox/state rather than a second queue;
- Evaluate still maps to canonical `#omega`;
- direct `#loads` launch renders correctly;
- More still exposes the secondary tools/settings surfaces;
- offline precache contains the structural adapter and the app launches offline without a blank shell;
- the Trip Planning setting and optional pickup-cutoff field introduced in v24.0.9 are present without changing the default decision when planning speed is unset.

## 6. Lifecycle / evidence durability

With synthetic data:

- manual/email/notification-compatible intake persists normalized evidence before linkage;
- provenance, source times, mileage semantics, and price semantics survive reload;
- external IDs never become destructive internal identity;
- non-carrier prices do not become canonical revenue without allowed evidence;
- UNKNOWN mileage/deadhead never becomes zero;
- lifecycle progression remains evidence-backed;
- full backup + deltas + restore preserve protected records without downgrade/duplication;
- local export/import preserves lifecycle/evidence and excludes credentials/PIN/lockout state.

## 7. Automated helpers

Source-side:

- `node tests/run-all.mjs`
- `node scripts/verify-cloudflare-parity.mjs --static-only`
- `node scripts/m7-certify.mjs --suite`

Live production, from a network that can reach Cloudflare:

- `node scripts/verify-cloudflare-parity.mjs`

The live verifier now derives the current app generation from source and is expected to verify app/PWA **24.0.9**, Worker **15**, and every declared runtime asset. The current source inventory is 23 assets; the inventory is derived rather than maintained as a hand-written list.

Authenticated authority checks when a valid non-published driver token is available:

- `FL_BACKUP_TOKEN=... node scripts/verify-live-authority.mjs`
- `FL_BACKUP_TOKEN=... node scripts/verify-live-backup.mjs`

Network inability is `UNOBSERVED`, not PASS and not product failure.

## 8. Completion rule

Live Cloudflare parity is complete only when the same named final candidate has:

- exact production app/PWA generation parity PASS;
- all derived runtime assets fetched successfully from the production origin, with no HTML-shell masquerade;
- structural-shell parity PASS;
- backup/API Worker v15 `/health` and CORS parity PASS;
- auth boundaries PASS;
- canonical `/evaluate`/`/extract` checks PASS where applicable;
- authenticated backup/delta/restore/rotation smoke PASS;
- rollback/fix-forward evidence recorded.

Only after this live gate, the real private-history reconciliation, and the physical-iPhone checklist all pass may a later certification-state document clear HOLD.
