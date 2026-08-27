# Cloudflare Deployment Parity Checklist

Use this checklist after every FreightLogic repository update.

## Current release hold — 2026-08-27

**Do not certify or freeze the current `main` generation yet.** PR #105 merged v24.2 lifecycle and Milestone 5A/5B, but post-merge source review found release-blocking runtime defects and stale generation markers:

- `app.js` still reports `APP_VERSION = '24.0.1'` even though v24.1 Confidence + Evidence and v24.2 Load Lifecycle are present;
- `cloud-backup-worker.js` is still Worker v12;
- Worker `/evaluate` still rejects the canonical `UNAVAILABLE` shape produced when material decision facts are unknown;
- the v24.2 lifecycle delta path can reference `lc` before declaration;
- the real JSON import path and current-generation export checksum do not yet cover `loadLifecycle` correctly;
- DB-v14 lifecycle-index creation and lifecycle identity/concurrency paths require the post-merge integrity hotfix recorded in coordination.

The corrective core PR must choose one coherent final app/PWA/cache generation appropriate to the v24.2 runtime (expected to be a v24.2.x release rather than retaining v24.0.1) and a corrected Worker generation (v13 or later). **Replace every `<FINAL_APP_VERSION>` / `<FINAL_WORKER_VERSION>` marker below with those exact landed values before calling deployment parity green.**

## Goal

Prove that the live Cloudflare Pages site and Cloudflare Worker are running the same corrected generation as GitHub `main`. Automate as much of this as possible with `scripts/verify-cloudflare-parity.mjs` (run it first — it covers the version-marker and CSP-parity checks below without manual clicking).

## Pages / PWA checks

- Confirm the post-hotfix GitHub `main` SHA is the exact source being certified.
- Open the deployed Pages URL in a private/incognito browser session.
- Open DevTools or Safari Web Inspector if available.
- Confirm `index.html` loads without console syntax errors.
- Confirm `app.js?v=<FINAL_APP_VERSION>` loads.
- Confirm `voice-load.js?v=<FINAL_APP_VERSION>` loads.
- Confirm `sw-bridge.js?v=<FINAL_APP_VERSION>` loads.
- Confirm `midwest-stack-authority.js?v=<FINAL_APP_VERSION>` loads after service-worker activation.
- Confirm `manifest.json?v=<FINAL_APP_VERSION>` loads, and its visible version/name metadata agrees with the same release generation.
- Confirm `vendor/xlsx.full.min.js` loads (X-10, v23.9 — bundled SheetJS, no CDN fallback).
- Confirm icons load with 200 status.
- Confirm `_headers` security headers are visible on the deployed site.
- Confirm `index.html`'s CSP `<meta>` tag and the `_headers` `Content-Security-Policy` line are byte-identical. `verify-cloudflare-parity.mjs` must assert this locally before the live check.

## Service worker checks

- Confirm `service-worker.js` contains `SW_VERSION = '<FINAL_APP_VERSION>'` (or the exact deliberately chosen cache generation if the implementation contract documents a distinct value).
- Confirm `CORE` includes `midwest-stack-authority.js?v=<FINAL_APP_VERSION>` and `vendor/xlsx.full.min.js`.
- Confirm the install-blocking critical shell also includes the authority overlay and bundled SheetJS.
- Confirm old caches are deleted after activation.
- Confirm a device already on the pre-hotfix generation upgrades to the corrected cache rather than continuing to serve v24.0.1 assets.
- Confirm offline reload still opens the app shell.
- Confirm Excel import (.xlsx) works offline immediately after a fresh install.
- Confirm the service worker does not cache cross-origin API responses.
- Confirm share-target POST flow still redirects to `./index.html#share`.

## Decision / confidence authority checks

- Confirm evaluator verdict, grade, economics, and bid range come only from the canonical client-owned Unified Decision Engine.
- Confirm categorical Confidence + Evidence remains descriptive only and cannot relax floors, change True RPM, change grade, or create a bid.
- Confirm a fully known decision projects through Worker `/evaluate` without a competing Worker calculation.
- Confirm a canonical `UNAVAILABLE` decision with null True RPM / unknown grade / suppressed bid remains `UNAVAILABLE` through the Worker review boundary; the Worker must not reject it merely because the bid range is absent and must not manufacture `0`, `F`, `REJECT`, or `$0` values.
- Confirm failed/unavailable evidence sources remain visibly unavailable/LOW rather than being interpreted as favorable no-signal evidence.

## v24.2 lifecycle checks

- Confirm a real v13→v14 IndexedDB upgrade creates the `loadLifecycle` store **and** its required indexes.
- Confirm `EXPIRED` and `CANCELLED` stay outside the ordinary `WON + LOST` win-rate denominator.
- Confirm repeated/reused broker order numbers do not select or merge a lifecycle solely by order number.
- Confirm the UI stage chip/correction path resolves a stable lifecycle identity or exact internal source reference; ambiguous legacy links remain unresolved.
- Confirm background lifecycle dual-write cannot downgrade a newer user-confirmed state after a revision conflict.
- Confirm lifecycle delta backup executes both zero-change and changed-lifecycle cases without a runtime exception.
- Confirm full backup + retained deltas + restore preserves lifecycle rows and de-duplicated `sourceRefs`.
- Confirm JSON export → the real user-facing JSON import round-trip preserves lifecycle rows.
- Confirm current-generation integrity verification detects a lifecycle-only export mutation.
- Confirm a pre-v24.2 backup/import with no lifecycle section is still accepted.

## Milestone 5A/5B ingestion checks

- Confirm manual and email-derived intake feed the same normalized opportunity contract.
- Confirm `SHIPPER_BOOKABLE_PRICE`, `OPERATOR_BID`, and unknown price semantics remain evidence and do **not** become canonical carrier revenue.
- Confirm only proven carrier-payout/settled semantics or an explicit operator revenue confirmation populate canonical revenue.
- Confirm missing material facts remain null/UNKNOWN rather than zero.
- Confirm displayed-total mileage never silently becomes loaded mileage.
- Confirm reused external order/quote identifiers do not collapse separate normalized opportunities.
- Confirm manual/email intake works offline and does not fabricate provider API authorization.

## Midwest Stack overlay checks

- Open the Evaluate view.
- Confirm the Midwest Stack authority overlay is advisory only and cannot replace canonical verdict/grade/economics/bid authority.
- Enter revenue, loaded miles, and deadhead miles and confirm the canonical decision updates deterministically.
- Confirm Dead Zone Exit does not reach a take/accept verdict unless the canonical DZ gates pass, including the exact `0.90` absolute floor.
- Confirm Cincinnati and Toledo remain Tier 1 and Level X+ grade boundaries remain exact.

## Worker checks

Expected corrected source generation: `cloud-backup-worker.js` **`<FINAL_WORKER_VERSION>`**, v13 or later.

- `GET /health` returns `{ ok: true, version: '<FINAL_WORKER_VERSION>', ... }` matching source.
- Admin routes reject without `X-Admin-Token`.
- Driver backup/evaluate/extract routes reject without `X-Backup-Token`.
- `GET /backup/delta` returns `{ ok: true, deltas: [...], retainedCount, totalCreated }` for an authenticated user+device.
- `POST /evaluate` preserves the client-owned canonical authority for both available and unavailable decisions.
- Worker confidence context is client-owned/explanatory only.
- `OPTIONS` preflight returns 204.
- CORS allows only the configured Pages origin.
- Worker secrets exist:
  - `ADMIN_TOKEN`
  - `OPENAI_API_KEY`
- Worker bindings/vars exist:
  - KV binding `BACKUPS`
  - `ALLOWED_ORIGIN`
  - optional `OPENAI_MODEL`

## Automated gate

Before any live-device certification:

- full `node tests/run-all.mjs` must be green on the exact corrective head;
- lane/path/lock checks must be green;
- Worker build must be green;
- `scripts/verify-cloudflare-parity.mjs` static checks must be green using the exact final version markers;
- no acceptance assertion may be weakened merely to make the hotfix pass.

## Live / field gate

The GitHub connector cannot prove the Cloudflare dashboard deployed the latest Worker or Pages assets. After the corrective source is green:

- verify the production Pages deployment SHA/generation;
- verify live `/health` Worker generation;
- smoke authenticated `/evaluate`, `/extract`, full backup, delta backup, and restore;
- verify unauthorized admin denial;
- run the physical-iPhone Safari/offline/GPS/background field checklist.

Until those checks pass, Cloudflare and field parity remain **UNVERIFIED**, not assumed green from repository CI.
