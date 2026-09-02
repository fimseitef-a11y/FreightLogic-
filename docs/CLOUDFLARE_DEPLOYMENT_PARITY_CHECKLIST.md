# Cloudflare Deployment Parity Checklist

Use this checklist after every FreightLogic repository update.

## Current completion candidate — 2026-09-02

The expected completion generation is **FreightLogic v24.0.2 / IndexedDB v15 / Worker v13**. The Batch A/B/C defects and eight exact-candidate blocker corrections tracked in Issue #119 are implemented and covered by regression tests. A later physical A1 check showed the installed iPhone PWA still on **v23.7.0**, indicating an installed-origin/production-deployment or update-path failure; source review also exposed an untested v24.0.2 update/reload handshake defect. The deployed origin and update path must be verified, repaired, and re-tested before this generation is a completion candidate.

**This document does not certify the release.** The canonical state is `docs/COMPLETION_RELEASE_CERTIFICATION_STATE_2026-09-02.md` and remains **HOLD** until the exact merged `main` generation is proven live and the finite physical-iPhone checks are performed. Historical HOLD documents remain evidence; a later certification state must explicitly supersede the current HOLD after proof exists.

Expected generation markers for this candidate:

- App / PWA / service worker: **`24.0.2`**
- IndexedDB schema: **`15`**
- Cloudflare Worker: **`13`**
- Rollback source generation: **`07d7e4ae46a8765bd60b21c18a7b920503782ff7`** (last v24.0.1 generation)

## Goal

Prove that the live Cloudflare deployment is running the same corrected generation as GitHub `main`, and that the PWA/Worker boundary preserves FreightLogic's canonical authority and absence semantics. Run `scripts/verify-cloudflare-parity.mjs` first; it automates the source/version/CSP checks that do not require a physical device.

## Pages / PWA checks

- Confirm the GitHub `main` SHA being certified is the exact merged release SHA.
- Open the deployed app in a private/incognito browser session.
- Confirm `index.html` loads without console syntax errors.
- Confirm `app.js?v=24.0.2` loads.
- Confirm `voice-load.js?v=24.0.2` loads.
- Confirm `sw-bridge.js?v=24.0.2` loads.
- Confirm `midwest-stack-authority.js?v=24.0.2` loads after service-worker activation.
- Confirm `manifest.json?v=24.0.2` loads and its visible version/name metadata agrees with the release generation.
- Confirm `vendor/xlsx.full.min.js` loads; there is no CDN fallback.
- Confirm icons load successfully.
- Confirm `_headers` security headers are present on the live deployment.
- Confirm `index.html` CSP `<meta>` and `_headers` `Content-Security-Policy` are byte-identical. `verify-cloudflare-parity.mjs` must also assert this locally.

## Service worker checks

- Confirm `service-worker.js` reports `SW_VERSION = '24.0.2'`.
- Confirm `CORE` includes `midwest-stack-authority.js?v=24.0.2` and `vendor/xlsx.full.min.js`.
- Confirm the install-blocking critical shell includes the authority overlay and bundled SheetJS.
- Confirm old caches are removed after activation.
- Confirm a device on v24.0.1 upgrades to v24.0.2 rather than continuing to serve stale assets.
- Confirm offline reload opens the app shell.
- Confirm Excel import (`.xlsx`) works offline immediately after a fresh install.
- Confirm the service worker does not cache cross-origin API responses.
- Confirm share-target POST still redirects to `./index.html#share`.

## Decision / confidence authority checks

- Evaluator verdict, grade, economics, and bid range must come only from the canonical client-owned Unified Decision Engine.
- Confidence + Evidence remains descriptive only and cannot relax floors, alter True RPM, alter grade, or manufacture a bid.
- A fully known decision must project through Worker `/evaluate` without a competing Worker calculation.
- A canonical `UNAVAILABLE` decision with null True RPM, grade `?`, and suppressed/null bid must remain `UNAVAILABLE`; the Worker must not manufacture `0`, `F`, `REJECT`, or `$0`.
- Failed/unavailable evidence sources must remain visibly absent/LOW rather than being read as favorable zero-signal evidence.

## Lifecycle + normalized-evidence checks

- Confirm a real v13→v15 IndexedDB upgrade creates `loadLifecycle` and `normalizedEvidence` plus their required indexes.
- Confirm `EXPIRED` and `CANCELLED` remain outside the ordinary `WON + LOST` win-rate denominator.
- Confirm repeated/reused broker order numbers never select or merge lifecycle solely by external order number.
- Confirm the UI correction path resolves stable lifecycle identity/internal source references; ambiguous legacy links remain unresolved.
- Confirm background lifecycle dual-write cannot downgrade a newer user-confirmed state after a revision conflict.
- Confirm both manual Opportunity Intake and historical import persist normalized evidence **before** attempting lifecycle linkage.
- Confirm an exact no-op evidence re-import preserves the existing row/revision/`recordedAt` rather than churning history.
- Confirm lifecycle delta backup executes both zero-change and changed-lifecycle cases without a runtime exception.
- Confirm full backup + retained deltas + restore preserve lifecycle/evidence rows, de-duplicated `sourceRefs`, and scalar/provenance pairing.
- Confirm local JSON export/import preserves lifecycle + normalized evidence and reconciles protected records by revision rather than blind overwrite.
- Confirm protected checksum verification detects lifecycle-only or normalized-evidence-only export mutation.
- Confirm pre-v24.2/pre-v15 backup/import payloads with no lifecycle/evidence section remain valid legacy input.

## Milestone 5A/5B ingestion checks

- Confirm manual and historical/email-derived intake feed the same normalized opportunity contract.
- Confirm `SHIPPER_BOOKABLE_PRICE`, `OPERATOR_BID`, board target/posting, and market benchmark values remain evidence and do **not** become canonical carrier revenue.
- Confirm only proven carrier-payout/settled semantics or explicit field-specific operator revenue confirmation populate canonical revenue.
- Confirm typed/manual values receive truthful field-specific provenance; they must not be mislabeled as `PRIMARY_DOCUMENT` or whole-row `OPERATOR_CORRECTION` without evidence.
- Confirm missing material facts remain null/UNKNOWN rather than zero.
- Confirm displayed-total mileage never silently becomes loaded mileage.
- Confirm reused external identifiers do not collapse separate opportunities.
- Confirm manual intake works offline and does not fabricate provider API authorization.

## Midwest Stack overlay checks

- Open Evaluate and confirm the Midwest Stack authority overlay is advisory only.
- Enter revenue, loaded miles, and deadhead miles and confirm the canonical decision updates deterministically.
- Confirm Dead Zone Exit cannot reach a take/accept verdict unless canonical DZ gates pass, including the exact `0.90` absolute floor.
- Confirm Cincinnati and Toledo remain Tier 1 and Level X+ grade boundaries remain exact.

## Worker v13 checks

Expected source generation: `cloud-backup-worker.js` **Worker `13`**.

- `GET /health` returns `{ ok: true, version: '13', ... }` matching source.
- Admin routes reject without `X-Admin-Token`.
- Driver backup/evaluate/extract routes reject without `X-Backup-Token`.
- `GET /backup/delta` returns the expected delta envelope for an authenticated user/device.
- `POST /evaluate` preserves canonical available and unavailable decisions.
- Worker confidence context is explanatory only.
- `OPTIONS` preflight returns 204.
- CORS allows only the configured app origin.
- Worker secrets/bindings required by runtime are present: `ADMIN_TOKEN`, `OPENAI_API_KEY`, KV `BACKUPS`, `ALLOWED_ORIGIN`, and optional `OPENAI_MODEL`.

## Automated gate

Before final certification, on the **exact candidate head**:

- `node tests/run-all.mjs` is green with no skipped acceptance gate used to manufacture success;
- lane/path/lock checks are green;
- `node scripts/m7-certify.mjs --suite` completes its automated gates and correctly refuses certification while canonical HOLD remains current;
- Worker build is green;
- `scripts/verify-cloudflare-parity.mjs --static-only` is green using app `24.0.2` and Worker `13`;
- the Cloudflare preview/deployment reports the same exact source commit.

## Live / field gate — required before changing HOLD

Repository CI and a successful preview deployment are not substitutes for this gate.

- Verify the **production** app deployment is sourced from the merged `main` release SHA.
- Verify live Worker `/health` reports version `13`.
- Smoke authenticated `/evaluate`, `/extract`, full backup, delta backup, and restore.
- Verify unauthorized admin/driver requests are denied.
- On the physical iPhone, complete the finite `FIELD_TEST_CHECKLIST.md` Safari/PWA install-update, offline/airplane-mode reload and Excel import, GPS/background/permission-removal resilience, and M5B evidence-durability checks.
- Record proof against the exact merged SHA.
- Only then create a new certification-state document that explicitly supersedes the current HOLD and mark Issue #119 complete.

Until those checks pass, the release state is **HOLD — code candidate ready, live/physical certification outstanding**.
