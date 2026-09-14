# Cloudflare Deployment Parity Checklist

Purpose: prove that the **production** Cloudflare app and backup/API Worker serve the exact FreightLogic completion candidate. Green source CI, a successful Cloudflare build, or a source version bump is not enough by itself.

Current runtime candidate:

- app / PWA / service worker source: **24.0.9**;
- IndexedDB schema: **15**;
- backup/API Worker source: **15**;
- exact runtime Git candidate: **`5446b097fe8791f3d7c79b5a5833a0930ee83cf2`** (merged PR #175);
- current repository `main` after read-only tooling/docs integration: **`a1a5f7dc8fda8472e2dc0b4cd6ad4f2dda62abb6`** (merged PR #180);
- production app origin: **`https://freightlogic-v2.fimseitef.workers.dev`**;
- backup/API Worker origin: **`https://freightlogic-backup.fimseitef.workers.dev`**;
- GitHub-attached Cloudflare build check for the exact runtime Git SHA: **SUCCESS**, check `103831029587`, build `d66b1b47-9ca6-4736-994a-ff02fc6f5490`, version `7582ec81-bbc6-40b4-b85b-7b5e34c3ad70`;
- version-specific preview for that check: **`https://7582ec81-freightlogic-v2.fimseitef.workers.dev`**;
- current merged source/tooling suite: **442 passed / 0 failed across 46 spec files** in main run `34800434526`;
- certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_ADDENDUM_2026-09-14.md`;
- status: **HOLD**.

Important: `https://freightlogic.pages.dev` is a legacy/stale origin and is not the production app origin.

## 1. Exact app deployment

Record:

- GitHub runtime SHA;
- current repository/tooling SHA used to run the verifier;
- Cloudflare production build/version identifier;
- production app origin;
- production backup/API Worker origin;
- rollback/fix-forward reference.

### Current source/deploy evidence

For v24.0.9, GitHub's Cloudflare check attached to runtime merge SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` completed successfully as check run `103831029587`, build `d66b1b47-9ca6-4736-994a-ff02fc6f5490`, version `7582ec81-bbc6-40b4-b85b-7b5e34c3ad70`. The earlier checklist draft named a different build/version pair; re-reading the exact SHA's check-runs showed that pair was not the check currently attached to `5446b097...`, so the release record now uses only the directly observable SHA-bound metadata. Subsequent PRs #177 through #180 changed verification tooling/tests/docs only; they did not change shipped runtime files or the app/PWA/cache generation. Build evidence is **not** a substitute for a live origin parity run.

The prior v24.0.8 admin-script defect is repaired in source: `.assetsignore` no longer excludes `admin-driver-ui.js`, and the deploy-asset regression gate derives the complete runtime inventory and asserts that every requested runtime asset exists and is deployable. The current derived source inventory is 23 assets. A full live-green parity run must fetch **every derived runtime asset**, not a curated subset, and must reject an HTML shell returned with HTTP 200 for a JavaScript/CSS/JSON/image request.

PR #177 added a repository-hosted, **manual-only and read-only** GitHub Actions runner named **Verify Live Parity**. It executes the real `scripts/verify-cloudflare-parity.mjs` from a GitHub-hosted runner, uses no secrets, performs no deploy/repository write, and preserves three explicit outcomes:

- `PASS` / exit 0 — live checks were observed and passed;
- `FAILURE` / exit 1 — the origin was observed and one or more parity checks failed;
- `UNOBSERVED` / exit 2 — no HTTP observation could be made because of transport/network unreachability.

HTTP error responses such as 404/500 count as **observed failures**, not UNOBSERVED. A static/source defect also outranks network unreachability and remains FAILURE.

The exact v24.0.9 all-asset live sweep remains **NOT RUN / UNOBSERVED** until an actual **Verify Live Parity** workflow run is dispatched and its result is recorded. Do not infer PASS from Cloudflare build success or from the verifier's static-only tests.

### Manual dispatch procedure

From the repository UI:

1. Open **Actions**.
2. Select **Verify Live Parity**.
3. Choose **Run workflow** on `main`.
4. Leave both optional origin inputs blank so the verifier uses the production defaults above.
5. Run the workflow.
6. Record the run ID, checked-out SHA, `VERDICT: PASS|FAILURE|UNOBSERVED`, derived runtime-asset count, and any failed checks.

Do not add a push/comment/schedule trigger merely to avoid this explicit release-gate action.

## 2. App / PWA generation

PASS requires production to serve:

- `app.js?v=24.0.9`;
- `voice-load.js?v=24.0.9`;
- `sw-bridge.js?v=24.0.9`;
- `midwest-stack-authority.js?v=24.0.9`;
- `manifest.json?v=24.0.9` identifying `FreightLogic v24.0.9`;
- `service-worker.js` with `SW_VERSION = '24.0.9'`;
- `admin-driver-ui.js?v=24.0.9` and every other asset derived by the runtime inventory;
- current `modern-shell.js` bytes from the named runtime candidate;
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
- local export/import preserves lifecycle/evidence and excludes credentials/PIN/lockout state;
- the optional `planningAvgMph` setting, when explicitly set, round-trips as a durable setting; absent/cleared remains absent and must not be invented or clamped during restore/import.

## 7. Automated helpers

Source-side:

- `node tests/run-all.mjs`
- `node scripts/verify-cloudflare-parity.mjs --static-only`
- `node scripts/m7-certify.mjs --suite`

Current repository baseline after PRs #177 through #180:

- main SHA `a1a5f7dc8fda8472e2dc0b4cd6ad4f2dda62abb6`;
- run `34800434526`;
- **442 passed / 0 failed across 46 spec files**;
- includes 11 dedicated live-parity-runner assertions.

Live production, from a network that can reach Cloudflare:

- preferred: **Actions → Verify Live Parity → Run workflow** with blank optional origins;
- equivalent CLI: `node scripts/verify-cloudflare-parity.mjs`.

The live verifier derives the current app generation from source and is expected to verify app/PWA **24.0.9**, Worker **15**, and every declared runtime asset. The current source inventory is 23 assets; the inventory is derived rather than maintained as a hand-written list.

Authenticated authority checks when a valid non-published driver token is available:

- `FL_BACKUP_TOKEN=... node scripts/verify-live-authority.mjs`
- `FL_BACKUP_TOKEN=... node scripts/verify-live-backup.mjs`

Network inability is `UNOBSERVED`, not PASS and not product failure. Any actual HTTP response makes the target observed and therefore eligible for PASS or FAILURE.

## 8. Rollback / fix-forward evidence

The final release must record a truthful rollback/fix-forward artifact. As of this checklist revision, `scripts/verify-rollback.mjs` is **not yet valid final B5 evidence** because its current source still carries an older hard-coded production candidate and a stale Worker-v14 expectation. Current release source/live Worker generation is v15.

A bounded Claude-owned tooling correction has been requested. Until that correction is integrated and observed, B5 remains **NOT RUN / TOOLING STALE** rather than a false failure caused by an obsolete expectation.

No older build may be labelled a safe rollback merely because it exists. Known-regression older generations require explicit defect disclosure; the default policy remains fix-forward unless a genuinely safe rollback target is proved.

## 9. Completion rule

Live Cloudflare parity is complete only when the same named final candidate has:

- exact production app/PWA generation parity PASS;
- all derived runtime assets fetched successfully from the production origin, with no HTML-shell masquerade;
- structural-shell parity PASS;
- backup/API Worker v15 `/health` and CORS parity PASS;
- auth boundaries PASS;
- canonical `/evaluate`/`/extract` checks PASS where applicable;
- authenticated backup/delta/restore/rotation smoke PASS;
- truthful rollback/fix-forward evidence recorded.

Only after this live gate, the real private-history reconciliation, six-width visual acceptance, and the physical-iPhone checklist all pass may a later certification-state document clear HOLD.
