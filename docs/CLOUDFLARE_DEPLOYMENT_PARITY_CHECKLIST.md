# Cloudflare Deployment Parity Checklist

Purpose: prove that the **production** Cloudflare app and backup/API Worker serve the exact FreightLogic completion candidate. Green source CI, a successful Cloudflare build, or a source version bump is not enough by itself.

**v24.0.19 IS DEPLOYED AND OBSERVED, and so is Worker v20.** This is the first
fully-green live parity in the v24.0.x line: every prior run in this release line
failed at least one check, most recently the Worker v19-vs-v20 mismatch.

Observation of record: live parity run `35291475396`, `workflow_dispatch` on `main`
@ `eac5994`, job `105435050613`, **`VERDICT: PASS`** with every check green —
`index.html` referencing `app.js` and `sw-bridge.js` at **24.0.19**, `index.html`
**not** referencing `voice-load.js` (the inverted #230 assertion, observed live),
service worker **24.0.19**, `sw-bridge` importing and the worker precaching
`modern-shell.js` at 24.0.19, manifest name `FreightLogic v24.0.19`, Worker
`/health` returning `{"ok":true,"version":"20"}`, all **22** declared runtime
assets loading with none served as HTML, CSP byte-identity, the unauthenticated
admin boundary still denying, and **20 repository-only paths confirmed non-public
(Issue #228's live half)**.

Worker v20 was deployed by run `35291404482` on the same SHA, with its own
post-deploy checks green: `/health` at the expected version, CORS on the real app
origin, and both unauthenticated boundaries still returning 401.

*Earlier revisions of this block described 24.0.15/24.0.14, and before that
24.0.13/24.0.12 — four and two app generations stale respectively. Corrected
rather than overwritten, because a parity document that keeps a superseded
deployment claim is exactly the drift it exists to catch. The rule that prevents
it is unchanged: a superseding record is due the day a shipped file deploys, not
the day it merges.*

Current runtime state (what production serves TODAY):

- app / PWA / service worker: **24.0.20**, deployed and observed live — live parity run
  `35329623870` and production service-worker run `35329629590`, both `workflow_dispatch` on
  `main` @ `c72b521`, both `VERDICT: PASS`. The 24.0.19 observation recorded above remains
  permanent provenance for the tree its runs looked at;
- repository source generation: **24.0.22** — source is AHEAD of production again, by the
  Issue #252 screenshot-intake generation, which is **not deployed and not live-observed**.
  (The 24.0.20 source-ahead gap this line previously recorded lasted about one hour, from
  merge to deploy, and was closed by the two re-dispatched gates named above.) **Deploy order
  is not optional here: Worker v21 FIRST.** The app's screenshot path calls
  `POST /extract-image`, which does not exist on the deployed v20, so shipping the app first
  gives every driver who taps Screenshot a 404 — the inverse of the v24.0.17 mismatch, and
  avoidable by sequencing rather than by discovering it in a parity run;
- IndexedDB schema: **16**;
- backup/API Worker: **20 deployed and observed live; 21 in source, NOT deployed.**
  v21 adds the `POST /extract-image` vision route (#252) and must deploy before the
  24.0.22 app generation, for the reason given above;
- exact runtime Git candidate: **`c72b521`** (the 24.0.20 merge, which is what production
  serves and what both live gates observed);
- production app origin: **`https://freightlogic-v2.fimseitef.workers.dev`**;
- backup/API Worker origin: **`https://freightlogic-backup.fimseitef.workers.dev`**;
- status: **HOLD**, and now for exactly one reason — the physical-iPhone gate
  **A1-A13** (A13 is #252's screenshot flow, added in v24.0.22), deferred by
  the operator's 2026-09-16 decision to the final
  post-v24.5 candidate. Every automatable and live-origin gate is observed and
  passing. Section C (M6 private history) has run; see `FIELD_TEST_CHECKLIST.md`.

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

**v24.0.11 live parity is OBSERVED, not inferred.** Run `34929870640` (Verify Live
Parity, attempt 2) on `fb408a0a8635d89ee0ed44a471ca11ef032a71a5` reports the Pages
index and its `app.js`, `voice-load.js` and `sw-bridge.js` references at `24.0.11`,
the service worker at `24.0.11`, `sw-bridge` importing `modern-shell.js` `24.0.11`
and the worker precaching it, the manifest name at `24.0.11`, Worker `/health`
returning `{"ok":true,"version":"17"}`, all **23** declared runtime assets loading
from the app origin, and none served as HTML. `VERDICT: PASS`. The production
service-worker gate (`34929870633`) and the full suite (`34929870661`) are green on
the same SHA.

**v24.0.12 live parity is now OBSERVED.** The paragraph that stood here said 24.0.12 had
not been observed live and that its parity run must be re-dispatched after it deployed.
That re-dispatch happened and passed; the paragraph is replaced rather than left standing,
because a checklist asserting "not deployed" about a generation production is serving is
worse than one that says nothing.

Run `34939229143` (Verify Live Parity, `workflow_dispatch` on `main` @
`4f2daf22819feb8d7aeba40324e53ce971f22418`, 2026-09-15T06:56:35Z) reports `sw-bridge`
importing `modern-shell.js` `24.0.12` with the worker precaching it at that generation,
the manifest name `FreightLogic v24.0.12`, the overlay and shell each loading and
exposing their globals, the SW critical shell still carrying `midwest-stack-authority.js`
and `vendor/xlsx.full.min.js`, Worker `/health` returning `{"ok":true,"version":"17"}`,
the admin endpoint rejecting an unauthenticated request with 401, all **23** declared
runtime assets loading from the app origin, and none served as HTML. `VERDICT: PASS`.

The production service-worker gate (`34939417958`, **16 checks / 0 failures**,
`VERDICT: PASS`) confirms it from the browser side on the same SHA: precache
`freightlogic-24.0.12` holding all 23 assets, the cached shell requesting `?v=24.0.12`,
`admin-driver-ui.js` and `midwest-stack-authority.js` injected **and fetchable as
script** (HTTP 200, `text/javascript`), an offline subresource miss answered `504
text/plain` rather than the HTML shell, a drifted `?v=` self-healing to the real file,
and exactly one generation cache surviving. The full suite (`34938834977`) is green on
the same SHA.

**The push-race recurred and is recorded so it is not mistaken for a release defect.**
Both workflows also fired on the push at 06:51Z and both FAILED — `34938834929` and
`34938834924` — about five minutes before the dispatched runs above passed. They
observed the previous generation still being served while Cloudflare finished deploying.
Re-dispatch and record the later run; do not dismiss the earlier one and do not cite
it.

This entry records generations and directly observed run evidence only. It is **not**
a certification: physical iPhone A1-A11 and section C private-history reconciliation
remain open, and neither is reachable from a hosted runner.


For v24.0.9, GitHub's Cloudflare check attached to runtime merge SHA `5446b097fe8791f3d7c79b5a5833a0930ee83cf2` completed successfully as check run `103831029587`, build `d66b1b47-9ca6-4736-994a-ff02fc6f5490`, version `7582ec81-bbc6-40b4-b85b-7b5e34c3ad70`. The earlier checklist draft named a different build/version pair; re-reading the exact SHA's check-runs showed that pair was not the check currently attached to `5446b097...`, so the release record now uses only the directly observable SHA-bound metadata. Subsequent PRs #177 through #180 changed verification tooling/tests/docs only; they did not change shipped runtime files or the app/PWA/cache generation. Build evidence is **not** a substitute for a live origin parity run.

The prior v24.0.8 admin-script defect is repaired in source: `.assetsignore` no longer excludes `admin-driver-ui.js`, and the deploy-asset regression gate derives the complete runtime inventory and asserts that every requested runtime asset exists and is deployable. The current derived source inventory is 23 assets. A full live-green parity run must fetch **every derived runtime asset**, not a curated subset, and must reject an HTML shell returned with HTTP 200 for a JavaScript/CSS/JSON/image request.

PR #177 added a repository-hosted, **manual-only and read-only** GitHub Actions runner named **Verify Live Parity**. It executes the real `scripts/verify-cloudflare-parity.mjs` from a GitHub-hosted runner, uses no secrets, performs no deploy/repository write, and preserves three explicit outcomes:

- `PASS` / exit 0 — live checks were observed and passed;
- `FAILURE` / exit 1 — the origin was observed and one or more parity checks failed;
- `UNOBSERVED` / exit 2 — no HTTP observation could be made because of transport/network unreachability.

HTTP error responses such as 404/500 count as **observed failures**, not UNOBSERVED. A static/source defect also outranks network unreachability and remains FAILURE.

That NOT RUN / UNOBSERVED state is closed and has been since 2026-09-14: the all-asset live sweep has been dispatched and recorded at every generation from 24.0.10 onward, most recently `34939229143` at 24.0.12 above. The standing rule it carried is unchanged and still binding — do not infer PASS from Cloudflare build success, from a version bump, or from the verifier's static-only tests. Only a dispatched run against the production origin closes this.

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

## 3. Worker live checks

**Read the expected generation from `cloud-backup-worker.js`'s own header rather than from this
heading.** This section stood at **v15** while source reached v21 — six generations stale, in the
one document whose job is catching exactly that. It is written as a derivation now for the same
reason `scripts/verify-rollback.mjs` stopped pinning its candidate SHA: a number transcribed here
goes stale at the next Worker bump, and the release that bumps it is precisely when nobody
remembers to edit this file. `tests/unit/cache-generation.spec.mjs` CG-09 already asserts that the
header, `/health` and the parity gate's `workerVersion` all name the same number, so there is one
source of truth and this is not it.

Current source generation at the time of writing: **21** (adds `POST /extract-image`, Issue #252).
Production serves **20**.

PASS requires:

- `GET /health` returns HTTP 200 and JSON whose `version` equals the source header's generation;
- unauthenticated `POST /extract-image` is denied — it sits **inside** the driver-token gate,
  unlike `POST /claim`, because it spends a limited provider allocation;
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

Current repository baseline at the 24.0.12 candidate:

- main SHA `4f2daf22819feb8d7aeba40324e53ce971f22418`;
- run `34938834977` (push on `main`), and `34933327774` on the PR head `aaa3569`;
- **483 passed / 0 failed across 52 spec files**, reproduced locally against real headless Chromium at the same total;
- includes 11 dedicated live-parity-runner assertions and the 14 cache-generation assertions.

Live production, from a network that can reach Cloudflare:

- preferred: **Actions → Verify Live Parity → Run workflow** with blank optional origins;
- equivalent CLI: `node scripts/verify-cloudflare-parity.mjs`.

The live verifier derives the current app generation from source, so this line states what it is currently expected to observe rather than a value it reads: app/PWA **24.0.12**, Worker **17**, and every declared runtime asset. Both were confirmed by run `34939229143`. The current source inventory is 23 assets; the inventory is derived rather than maintained as a hand-written list.

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
- backup/API Worker `/health` and CORS parity PASS **at the generation
  `cloud-backup-worker.js`'s header names** — not at a number written here, for the reason
  section 3 gives;
- auth boundaries PASS, including unauthenticated `POST /extract-image` denied;
- canonical `/evaluate`/`/extract`/`/extract-image` checks PASS where applicable;
- authenticated backup/delta/restore/rotation smoke PASS;
- truthful rollback/fix-forward evidence recorded.

Only after this live gate, the real private-history reconciliation, six-width visual acceptance, and the physical-iPhone checklist all pass may a later certification-state document clear HOLD.
