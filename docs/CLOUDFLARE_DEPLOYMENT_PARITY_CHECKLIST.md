# Cloudflare Deployment Parity Checklist

Purpose: prove that the **production** Cloudflare app and backup/API Worker serve the exact FreightLogic completion candidate. Green source CI, a successful preview build, or a source version bump is not enough by itself.

Current source candidate:

- app / PWA / service worker source: **24.0.7**;
- IndexedDB schema: **15**;
- backup/API Worker source: **15**;
- exact Git source candidate at this synchronization point: **`03c97b64af354fa83fcb15881b320bfdfbf1e20a`**;
- production app origin: **`https://freightlogic-v2.fimseitef.workers.dev`**;
- backup/API Worker origin: **`https://freightlogic-backup.fimseitef.workers.dev`**;
- certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-13.md`;
- status: **HOLD**.

Important: `https://freightlogic.pages.dev` is a legacy/stale origin and is not the production app origin.

## 1. Exact app deployment

Record:

- GitHub `main` SHA;
- Cloudflare production build/version identifier;
- production app origin;
- production backup/API Worker origin;
- rollback/fix-forward reference.

The last exact-byte production app parity observation was for v24.0.5 on 2026-09-12. Source has since advanced through v24.0.6 and v24.0.7, including the current native presentation pass. Therefore **v24.0.7 production parity is UNOBSERVED until it is re-probed**. A successful Cloudflare PR/branch preview is useful deployment evidence but is not a substitute for production parity.

## 2. App / PWA generation

PASS requires production to serve:

- `app.js?v=24.0.7`;
- `voice-load.js?v=24.0.7`;
- `sw-bridge.js?v=24.0.7`;
- `midwest-stack-authority.js?v=24.0.7`;
- `manifest.json?v=24.0.7` identifying `FreightLogic v24.0.7`;
- `service-worker.js` with `SW_VERSION = '24.0.7'`;
- bundled `vendor/xlsx.full.min.js`;
- the current `styles.css` visual layer;
- matching CSP/security headers;
- no failed JavaScript/static request answered with an HTML shell fallback.

Do not reuse the v24.0.5 exact-byte PASS as evidence for v24.0.7.

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

Worker v14 was successfully deployed on 2026-09-13 before the v15 source bump. The later v15 deploy attempt was **refused before `wrangler deploy`** because the deploy preflight still contained a stale hardcoded v14 assertion. PR #163 removed that stale deploy-path pin and merged as `03c97b64af354fa83fcb15881b320bfdfbf1e20a`.

Therefore, at this synchronization point:

- Worker v15 source: **READY IN REPO**;
- deploy preflight stale-pin defect: **CLOSED**;
- live Worker v15 deployment: **NOT YET OBSERVED / REDEPLOY REQUIRED**;
- authenticated v15 backup/evaluate/rotation smokes: **NOT RUN**.

The manual `Deploy Backup Worker` workflow remains the intended deployment boundary. It is intentionally `workflow_dispatch` only and requires the explicit `DEPLOY` confirmation. Do not change it into a push/comment-triggered or self-pushing workflow merely to automate this gate.

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

## 5. Lifecycle / evidence durability

With synthetic data:

- manual/email/notification-compatible intake persists normalized evidence before linkage;
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

The live verifier currently expects app/PWA **24.0.7** and Worker **15**, and defaults to the real Workers origins.

Authenticated authority checks when a valid non-published driver token is available:

- `FL_BACKUP_TOKEN=... node scripts/verify-live-authority.mjs`
- `FL_BACKUP_TOKEN=... node scripts/verify-live-backup.mjs`
- add quota-spending extraction checks only when explicitly appropriate.

Network inability is `UNOBSERVED`, not PASS and not product failure.

## 7. Approved UI structural pass

The operator approved a further structural UI pass after v24.0.7: real **Today / Loads / Evaluate / Trips / Money** navigation, dedicated Loads, Today reordering, unified Money, and coherent Settings. That work is handed to the Claude/source lane in `.agents/inbox/gpt-to-claude-modern-ui-structural-pass-2026-09-13.md`.

Do **not** spend the final physical-device certification on an intermediate layout if that structural pass is still pending. When it lands, update this checklist to the resulting exact generation/SHA and rerun production parity.

## 8. Completion rule

Live Cloudflare parity is complete only when the same named final candidate has:

- exact production app/PWA generation parity PASS;
- backup/API Worker v15 `/health` and CORS parity PASS;
- auth boundaries PASS;
- canonical `/evaluate`/`/extract` checks PASS where applicable;
- authenticated backup/delta/restore/rotation smoke PASS;
- rollback/fix-forward evidence recorded.

Only after this live gate, the real private-history reconciliation, the approved structural UI pass, and the physical iPhone checklist all pass may a later certification-state document clear HOLD.
