# Cloudflare Deployment Parity Checklist

Use this checklist after every FreightLogic repository update.

## Current corrective release candidate — 2026-08-28

**Candidate generation: FreightLogic v24.0.2 / Cloud Backup Worker v13.** Do not certify or freeze this generation until the exact candidate SHA passes the automated, live Cloudflare, and physical-device gates below.

The v24.0.2 corrective candidate addresses the post-v24.2 integrity defects that held the prior generation:

- `app.js` / PWA / cache markers are coherently bumped to `24.0.2`;
- `cloud-backup-worker.js` is Worker v13 and preserves canonical `UNAVAILABLE` / unknown-grade / null-True-RPM / suppressed-bid absence instead of manufacturing a negative decision;
- lifecycle delta selection no longer references lifecycle data before declaration;
- DB lifecycle/evidence store indexes are created and repaired on fresh and upgrade paths;
- lifecycle and normalized evidence participate in full/delta backup, restore, JSON export/import, and protected integrity checks;
- reused external IDs are treated as candidate signals, not internal identity;
- historical reconciliation preserves dry runs, unknown deadhead, source timestamps, per-field provenance, and authority precedence;
- evaluator confidence/evidence assembly now uses the actual applied fuel source, real lane/broker history, real vehicle-fit state, and distinguishes successful zero-alert NWS observations from missing/failed weather observations.

These are **candidate facts, not certification**. Repository CI, live deployment parity, and field checks remain required.

## Goal

Prove that the live Cloudflare Pages site and Cloudflare Worker are running the same corrected generation as GitHub `main`. Automate as much of this as possible with `scripts/verify-cloudflare-parity.mjs` (run it first — it covers the version-marker and CSP-parity checks below without manual clicking).

## Pages / PWA checks

- Confirm the post-hotfix GitHub `main` SHA is the exact source being certified.
- Open the deployed Pages URL in a private/incognito browser session.
- Open DevTools or Safari Web Inspector if available.
- Confirm `index.html` loads without console syntax errors.
- Confirm `app.js?v=24.0.2` loads.
- Confirm `voice-load.js?v=24.0.2` loads.
- Confirm `sw-bridge.js?v=24.0.2` loads.
- Confirm `midwest-stack-authority.js?v=24.0.2` loads after service-worker activation.
- Confirm `manifest.json?v=24.0.2` loads, and its visible version/name metadata agrees with the same release generation.
- Confirm `vendor/xlsx.full.min.js` loads (X-10, v23.9 — bundled SheetJS, no CDN fallback).
- Confirm icons load with 200 status.
- Confirm `_headers` security headers are visible on the deployed site.
- Confirm `index.html`'s CSP `<meta>` tag and the `_headers` `Content-Security-Policy` line are byte-identical. `verify-cloudflare-parity.mjs` must assert this locally before the live check.

## Service worker checks

- Confirm `service-worker.js` contains `SW_VERSION = '24.0.2'`.
- Confirm `CORE` includes `midwest-stack-authority.js?v=24.0.2` and `vendor/xlsx.full.min.js`.
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

## v24.2 lifecycle + v24.0.2 durability checks

- Confirm a real pre-v14→v15 IndexedDB upgrade creates the `loadLifecycle` and `normalizedEvidence` stores **and** their required indexes.
- Confirm `EXPIRED` and `CANCELLED` stay outside the ordinary `WON + LOST` win-rate denominator.
- Confirm repeated/reused broker order numbers do not select or merge a lifecycle solely by order number.
- Confirm the UI stage chip/correction path resolves a stable lifecycle identity or exact internal source reference; ambiguous legacy links remain unresolved.
- Confirm background lifecycle dual-write cannot downgrade a newer user-confirmed state after a revision conflict.
- Confirm lifecycle/evidence delta backup executes zero-change and changed-only cases without a runtime exception.
- Confirm full backup + retained deltas + restore preserves lifecycle rows, normalized evidence, provenance, and de-duplicated `sourceRefs`.
- Confirm JSON export → the real user-facing JSON import round-trip preserves lifecycle and normalized-evidence rows.
- Confirm current-generation `checksumProtected` integrity verification detects lifecycle/evidence-only export mutation.
- Confirm a pre-v24.2 backup/import with no lifecycle/evidence sections is still accepted.

## Milestone 5A/5B ingestion checks

- Confirm manual and email-derived intake feed the same normalized opportunity contract.
- Confirm `SHIPPER_BOOKABLE_PRICE`, `OPERATOR_BID`, `BOARD_TARGET_RATE`, `POSTED_RATE`, `MARKET_BENCHMARK`, and unknown price semantics remain evidence and do **not** become canonical carrier revenue.
- Confirm only proven carrier-payout/settled semantics or an explicit operator revenue confirmation populate canonical revenue.
- Confirm missing material facts remain null/UNKNOWN rather than zero.
- Confirm displayed-total mileage never silently becomes loaded mileage.
- Confirm reused external order/quote identifiers do not collapse separate normalized opportunities.
- Confirm manual/email intake works offline and does not fabricate provider API authorization.
- Confirm manual revenue confirmation promotes only the amount/revenue fact it actually confirms; it must not promote unrelated fields to top authority.
- Confirm durable semantic evidence exists even when lifecycle linking remains unresolved or fails.

## Historical reconciliation checks

- Confirm raw historical rows are not pre-collapsed by external order number alone.
- Confirm a reused order number with incompatible route/time evidence remains separate.
- Confirm ambiguous `customer` / `carrier` text is never promoted into canonical broker identity.
- Confirm authority precedence is field-specific and later high-authority corrections can supersede lower-authority populated values without deleting the losing evidence.
- Confirm DRY RUN rows are preserved as operational history and excluded from ordinary win-rate/rate calibration.
- Confirm unrecognized statuses remain unknown/tri-state rather than manufacturing a win or loss.
- Confirm full source timestamps retain clock precision; undated observations stay undated and do not receive full-current recency weight.
- Confirm lifecycle `updatedAt` is never substituted for source observation time.
- Confirm identical historical re-import is idempotent under the bounded SHA-256 fingerprint.

## Evaluator real-evidence wiring checks

- Confirm the fuel-price evidence source describes the price actually applied: operator setting vs applied EIA observation vs static baseline.
- Confirm an EIA health record alone never relabels a manually entered fuel price as EIA.
- Confirm personal lane sample count/last-seen values come from the fetched `laneHistory` record.
- Confirm broker sample/recency comes from the fetched `bidHistory` record, and an inapplicable no-broker domain does not lower confidence.
- Confirm a successful NWS route fetch with zero alerts is represented as a successful zero observation.
- Confirm offline/timeout/HTTP failure/no-route-point weather remains unknown/unavailable, never “0 alerts.”
- Confirm vehicle-fit evidence reports unchecked/partial/complete based on dimensions actually supplied; no-dimensions loads must not claim a completed fit check.
- Confirm evaluation history stores a bounded, secret-free evidence/confidence snapshot and old entries without one render as not recorded, never confident.

## Midwest Stack overlay checks

- Open the Evaluate view.
- Confirm the Midwest Stack authority overlay is advisory only and cannot replace canonical verdict/grade/economics/bid authority.
- Enter revenue, loaded miles, and deadhead miles and confirm the canonical decision updates deterministically.
- Confirm Dead Zone Exit does not reach a take/accept verdict unless the canonical DZ gates pass, including the exact `0.90` absolute floor.
- Confirm Cincinnati and Toledo remain Tier 1 and Level X+ grade boundaries remain exact.

## Worker checks

Expected corrected source generation: `cloud-backup-worker.js` **Worker v13**.

- `GET /health` returns `{ ok: true, version: '13', ... }` matching source.
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
- `scripts/verify-cloudflare-parity.mjs` static checks must be green using exact app `24.0.2` / Worker `13` markers;
- no acceptance assertion may be weakened merely to make the hotfix pass.

## Live / field gate

Repository CI alone cannot prove that the production Cloudflare origins and a physical iPhone are running the exact candidate. After the corrective source is green:

- verify the production Pages deployment SHA/generation;
- verify live `/health` Worker generation `13`;
- smoke authenticated `/evaluate`, `/extract`, full backup, delta backup, and restore;
- verify unauthorized admin denial;
- run the physical-iPhone Safari/offline/GPS/background field checklist.

Until those checks pass, Cloudflare and field parity remain **UNVERIFIED**, not assumed green from repository CI.
