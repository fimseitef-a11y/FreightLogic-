# Cloudflare Deployment Parity Checklist

Purpose: prove that the **production** Cloudflare app and backup/API Worker serve the exact FreightLogic completion candidate. Green source CI, a successful Cloudflare build, or a source version bump is not enough by itself.

Current runtime candidate (evidence observed 2026-09-14):

- app / PWA / service worker: **24.0.10**;
- IndexedDB schema: **15**;
- backup/API Worker source and observed deployment: **17**;
- exact runtime/source candidate: **`d58bfbea3b6f5d0ebc100795d1320c033a1a5bc0`** (merged PR #193);
- production app origin: **`https://freightlogic-v2.fimseitef.workers.dev`**;
- backup/API Worker origin: **`https://freightlogic-backup.fimseitef.workers.dev`**;
- exact merged-main suite: **457 passed / 0 failed across 49 spec files**, [run 34884711942](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884711942);
- live parity: **PASS**, [run 34885000070](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34885000070), app24.0.10 / Worker17 / all 23 declared assets;
- certification authority: `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-14.md`;
- status: **HOLD** for the remaining gates recorded there.

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

PR #192 delivered app/PWA v24.0.10. PR #193 then integrated Worker v17 and the derived rollback verifier at the named candidate. [Deploy Backup Worker 34884719806](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884719806) completed successfully and its post-deploy health response reported version 17.

[Verify Live Parity 34885000070](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34885000070) checked out `d58bfbea3b6f5d0ebc100795d1320c033a1a5bc0` and recorded **VERDICT: PASS** at 19:07:58Z: the expected app generation, Worker17, all **23 declared runtime assets**, and no HTML-shell response masking a static asset. The earlier push-triggered run 34884711957 failed before this successful post-deploy observation.

The inventory is derived from runtime declarations. PASS proves the verifier's marker, delivery, content-type/fallback and source/security checks; it is not a cryptographic comparison of every live asset against source bytes, nor an installed-PWA offline test.

**Verify Live Parity** is read-only and currently runs on both pushes to `main` and manual dispatch. It uses no secrets and performs no deploy/repository write. Its outcomes remain:

- `PASS` / exit 0 — the checks ran and passed;
- `FAILURE` / exit 1 — an observed mismatch or source defect;
- `UNOBSERVED` / exit 2 — no HTTP observation was possible.

An HTTP 404/500 is observed evidence. A source defect outranks network unreachability. A push-triggered run can precede Cloudflare deployment; retain that result and record a new observation after deployment.

### Manual dispatch procedure

From the repository UI:

1. Open **Actions**.
2. Select **Verify Live Parity**.
3. Choose **Run workflow** on `main`.
4. Leave both optional origin inputs blank so the verifier uses the production defaults above.
5. Run the workflow.
6. Record the run ID, checked-out SHA, `VERDICT: PASS|FAILURE|UNOBSERVED`, derived runtime-asset count, and any failed checks.

The existing push trigger supplements this manual procedure; neither trigger deploys the Worker.

## 2. App / PWA generation

PASS requires production to serve:

- `app.js?v=24.0.10`, `voice-load.js?v=24.0.10`, and `sw-bridge.js?v=24.0.10`;
- `midwest-stack-authority.js?v=24.0.10` and `admin-driver-ui.js?v=24.0.10`;
- `manifest.json?v=24.0.10` naming `FreightLogic v24.0.10`;
- `service-worker.js` with `SW_VERSION = '24.0.10'`;
- current `modern-shell.js`, `styles.css`, bundled `vendor/xlsx.full.min.js`, and every other derived runtime asset;
- matching CSP/security policy and no HTML shell masking a static request failure.

Current verifier outcome: **PASS**, run 34885000070. Older-generation observations do not replace evidence for this candidate. Device-controlled update/offline behavior remains a separate check.

## 3. Worker v17 live checks

Expected backup/API Worker generation: **17**.

PASS requires:

- `GET /health` HTTP 200 with `version: "17"`;
- exact production-origin CORS;
- denied unauthorized admin/driver/evaluate/extract/backup requests;
- canonical available and UNAVAILABLE decisions preserved by authenticated `/evaluate`;
- bounded `/extract` evidence where enabled;
- authenticated full/delta backup and restore preserving data/authority semantics;
- no secret exposure;
- in-place token rotation preserving user identity/history and invalidating the old token.

### Current observed Worker state

Deployment run 34884719806 observed health version 17; parity run 34885000070 subsequently passed. Authenticated run [34884786623](https://github.com/fimseitef-a11y/FreightLogic-/actions/runs/34884786623), on the same candidate, recorded:

- **5 authority passes, 0 failures, 3 NOT RUN**: the paid complete-decision, REJECT/F, and extraction probes were explicitly skipped;
- **21 synthetic backup passes, 0 failures, 0 skipped**: byte-exact snapshot/delta retrieval, ordering, counters, scoped listing, unauthorized denial, and cleanup.

These results do not prove paid-model behavior, token rotation, or restore through the installed app UI. Those applicable checks retain their open status. The Worker deployment boundary remains the explicit/manual **Deploy Backup Worker** workflow.

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

Current exact candidate baseline:

- SHA `d58bfbea3b6f5d0ebc100795d1320c033a1a5bc0`;
- Tests run **34884711942**;
- **457 passed / 0 failed across 49 spec files**.

For a new live observation use **Actions → Verify Live Parity → Run workflow** with blank optional origins, or `node scripts/verify-cloudflare-parity.mjs`. The current source expects app/PWA **24.0.10**, Worker **17**, and all derived runtime assets.

Authenticated helpers use a valid non-published test identity:

- `FL_BACKUP_TOKEN=... node scripts/verify-live-authority.mjs`
- `FL_BACKUP_TOKEN=... node scripts/verify-live-backup.mjs`

Record explicit NOT RUN results as well as passes. Neither an overall workflow SUCCESS nor a free-mode authority pass proves a probe that was skipped.

## 8. Rollback / fix-forward evidence

PR #193 repaired `scripts/verify-rollback.mjs`: the candidate derives from HEAD, app/Worker versions from source, and the previous app generation from history. Its six regressions passed in run 34884711942. The old Worker-v14/v15 hard-coded-expectation description is obsolete.

Standalone final B5 evidence remains **NOT RUN in this documentation pass**. Run the read-only verifier with repository history available and preserve output naming the final release SHA. Tooling regression success alone is not that standalone evidence.

Default recovery policy remains **FIX FORWARD**. A verifier PASS does not approve an older app/Worker release as a safe rollback target.

## 9. Completion rule

Live Cloudflare parity is complete only when the same named final candidate has:

- exact production app/PWA generation parity PASS;
- all derived runtime assets fetched successfully from the production origin, with no HTML-shell masquerade;
- structural-shell parity PASS;
- backup/API Worker v17 `/health` and CORS parity PASS;
- auth boundaries PASS;
- canonical `/evaluate`/`/extract` checks PASS where applicable;
- authenticated backup/delta/restore/rotation smoke PASS;
- truthful rollback/fix-forward evidence recorded.

The observed passing rows and remaining scope are recorded in `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-14.md`. Only after the applicable live authority/rotation/restore checks, real private-history reconciliation, complete mobile acceptance, physical-iPhone checklist, and final recovery evidence pass may a later certification record clear HOLD.
