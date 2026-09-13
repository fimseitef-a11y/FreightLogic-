# Cloudflare Deployment Parity Checklist

Purpose: prove that the **production** Cloudflare app and backup/API Worker serve the exact FreightLogic completion candidate. Green source CI, a successful preview/production build, or a source version bump is not enough by itself.

Current runtime candidate:

- app / PWA / service worker source: **24.0.8**;
- IndexedDB schema: **15**;
- backup/API Worker source: **15**;
- exact runtime Git candidate: **`c02ed36bcc6c81a182c81aec0d6358d39fc90bbf`**;
- production app origin: **`https://freightlogic-v2.fimseitef.workers.dev`**;
- backup/API Worker origin: **`https://freightlogic-backup.fimseitef.workers.dev`**;
- certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-13.md`;
- status: **HOLD**.

Important: `https://freightlogic.pages.dev` is a legacy/stale origin and is not the production app origin.

## 1. Exact app deployment

Record:

- GitHub `main` runtime SHA;
- Cloudflare production build/version identifier;
- production app origin;
- production backup/API Worker origin;
- rollback/fix-forward reference.

Live verification on 2026-09-13 after PR #172: 24/24 standard parity checks pass, and eleven checked production assets match source byte for byte. However, `admin-driver-ui.js` returns 404 because `.assetsignore` excludes it. Full asset parity remains blocked until the repair is deployed and re-probed. See the current addendum for exact hashes and CI evidence.

## 2. App / PWA generation

PASS requires production to serve:

- `app.js?v=24.0.8`;
- `voice-load.js?v=24.0.8`;
- `sw-bridge.js?v=24.0.8`;
- `midwest-stack-authority.js?v=24.0.8`;
- `manifest.json?v=24.0.8` identifying `FreightLogic v24.0.8`;
- `service-worker.js` with `SW_VERSION = '24.0.8'`;
- `admin-driver-ui.js?v=24.0.8` (must not be excluded from deployment);
- current `modern-shell.js` bytes from the named candidate;
- bundled `vendor/xlsx.full.min.js`;
- the current `styles.css` visual layer;
- matching CSP/security headers;
- no failed JavaScript/static request answered with an HTML shell fallback.

Do not reuse the v24.0.5 exact-byte PASS as evidence for v24.0.8.

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

On 2026-09-13 this session observed Worker v15 at the production origin: health HTTP 200/version 15, exact production-origin CORS on health GET and backup OPTIONS (204), and unauthorized admin HTTP 401. The earlier redeploy requirement is closed. Authenticated evaluate/extract/full-delta-restore/token-rotation checks remain **NOT RUN** because no test token is available.

The manual `Deploy Backup Worker` workflow remains the intended deployment boundary and must remain explicit/manual.

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
- precise True Profit is not asserted without defensible cost/mileage inputs.

## 5. Structural shell parity

The structural UI pass is now merged, not pending. Production parity must confirm:

- primary navigation is **Today / Loads / Evaluate / Trips / Money**;
- Loads uses the existing canonical load inbox/state rather than a second queue;
- Evaluate still maps to canonical `#omega`;
- direct `#loads` launch renders correctly;
- More still exposes the secondary tools/settings surfaces;
- offline precache contains the structural adapter and the app launches offline without a blank shell.

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

The live verifier currently expects app/PWA **24.0.8** and Worker **15**.

Authenticated authority checks when a valid non-published driver token is available:

- `FL_BACKUP_TOKEN=... node scripts/verify-live-authority.mjs`
- `FL_BACKUP_TOKEN=... node scripts/verify-live-backup.mjs`

Network inability is `UNOBSERVED`, not PASS and not product failure.

## 8. Completion rule

Live Cloudflare parity is complete only when the same named final candidate has:

- exact production app/PWA generation parity PASS;
- structural-shell parity PASS;
- backup/API Worker v15 `/health` and CORS parity PASS;
- auth boundaries PASS;
- canonical `/evaluate`/`/extract` checks PASS where applicable;
- authenticated backup/delta/restore/rotation smoke PASS;
- rollback/fix-forward evidence recorded.

Only after this live gate, the real private-history reconciliation, and the physical-iPhone checklist all pass may a later certification-state document clear HOLD.
