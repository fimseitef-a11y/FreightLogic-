# Cloudflare Deployment Parity Checklist

Use this checklist after every FreightLogic repository update.

## Goal

Prove that the live Cloudflare Pages site and Cloudflare Worker are running the same generation as GitHub `main`. Automate as much of this as possible with `scripts/verify-cloudflare-parity.mjs` (run it first — it covers the version-marker and CSP-parity checks below without manual clicking).

## Pages / PWA checks

- Open the deployed Pages URL in a private/incognito browser session.
- Open DevTools or Safari Web Inspector if available.
- Confirm `index.html` loads without console syntax errors.
- Confirm `app.js?v=24.0.1` loads.
- Confirm `voice-load.js?v=24.0.1` loads.
- Confirm `sw-bridge.js?v=24.0.1` loads.
- Confirm `midwest-stack-authority.js?v=24.0.1` loads after service-worker activation.
- Confirm `manifest.json?v=24.0.1` loads, and its `name` field reads `FreightLogic v24.0.1`.
- Confirm `vendor/xlsx.full.min.js` loads (X-10, v23.9 — bundled SheetJS, no CDN fallback).
- Confirm icons load with 200 status.
- Confirm `_headers` security headers are visible on the deployed site.
- Confirm `index.html`'s CSP `<meta>` tag and the `_headers` `Content-Security-Policy` line
  are byte-identical (Amendment 5, v23.9 — `verify-cloudflare-parity.mjs` asserts this
  locally/statically, no network needed; a real drift here was found and fixed in v23.9 —
  `_headers` was missing the Google Fonts origins `index.html` requires).

## Service worker checks

- Confirm `service-worker.js` contains `SW_VERSION = '24.0.1'`.
- Confirm `CORE` includes `midwest-stack-authority.js?v=24.0.1` and `vendor/xlsx.full.min.js`.
- Confirm the `install` event's **critical** (install-blocking) shell array — distinct from
  the broader `CORE` list — also includes `midwest-stack-authority.js?v=24.0.1` and
  `vendor/xlsx.full.min.js` (X-08/X-10, v23.9). Before v23.9, the overlay script was only in
  `CORE`, so a first offline install could complete and serve the app shell before the
  TRUE_RPM decision layer was actually cached, with no error surfaced.
- Confirm old caches are deleted after activation.
- Confirm offline reload still opens the app shell.
- Confirm Excel import (.xlsx) works with the device offline immediately after a fresh
  install (X-10, v23.9 — proves the bundled vendor file, not a CDN fetch, is what's loading).
- Confirm the service worker does not cache cross-origin API responses.
- Confirm share-target POST flow still redirects to `./index.html#share`.

## Midwest Stack overlay checks

- Open the Evaluate view.
- Confirm `Bid Strategy · Advisory` appears below the evaluator output area, with copy stating that the canonical decision above is authoritative and this panel is supporting market/bid evidence.
- Enter revenue, loaded miles, and deadhead miles.
- Confirm a blank deadhead field is treated as **UNKNOWN** and blocks a calculated decision; entering an explicit `0` is accepted as verified zero deadhead.
- Confirm True RPM, grade, realistic win, ask, verdict, and risk flags update once all required material facts are present.
- Confirm these modes are available:
  - Realistic Win
  - Protect Floor
  - Escape / Recovery
  - Dead Zone Exit
- Confirm Dead Zone Exit mode does **not** reach a `TAKE_IF_LIVE` verdict without all four
  canonical gates passing (X-04, v23.9 — `isDeadZoneEligible()` in `app.js`, called by both
  this overlay and the main evaluator): 1000+ mi from home, 200+ mi "distance saved," True
  RPM in the `[0.90, 1.25)` survival band, and the `#mwDZNoReloadToggle` confirmation
  checkbox checked. `tests/integration/dz-gate-parity.spec.mjs` covers this automatically.

## v24.0 decision-authority checks

- Confirm the evaluator's verdict, grade, economics, and bid range all come from the
  canonical client-owned decision object in `app.js` (v24.0 Unified Decision Engine) —
  the USA layer is evidence-only and the Midwest overlay is an advisory adapter.
- Confirm incomplete canonical facts remain unavailable/UNKNOWN: no missing revenue or mileage is projected as zero; no unknown grade becomes `F`; no suppressed bid range becomes `$0`.
- Confirm a `/evaluate` response *projects* the canonical verdict/grade/True RPM/bid
  rather than publishing a competing calculation of its own.
- `tests/unit/v24-unified-decision.spec.mjs`,
  `tests/integration/v24-authority-boundaries.spec.mjs`,
  `tests/integration/v24-economics-bid.spec.mjs`, and the Milestone-1 doctrine-integrity regression suite cover this automatically; the full suite must be green before a deploy is considered parity-verified.

## Worker checks

Expected source file: `cloud-backup-worker.js` v13.

- `GET /health` should return JSON with `ok: true`, `version: '13'`, and a timestamp.
- Confirm `/evaluate` preserves canonical unavailable/UNKNOWN states and does **not** sanitize missing verdict/grade/True RPM/bid into `REJECT`, `F`, `$0.00`, or `$0`.
- Admin routes must reject without `X-Admin-Token`.
- Driver backup/evaluate/extract routes must reject without `X-Backup-Token`.
- `GET /backup/delta` should return `{ ok: true, deltas: [...], retainedCount, totalCreated }`
  for an authenticated user+device (X-01, v23.9 — new in v11; a pre-v11 Worker 404s here,
  which the app treats as "unverifiable" and shows a partial-restore warning rather than a
  silent success — see `docs/BACKUP_CONTRACT.md`).
- `OPTIONS` preflight should return 204.
- CORS should allow the configured Pages origin only.
- Worker secrets must exist:
  - `ADMIN_TOKEN`
  - `OPENAI_API_KEY`
- Worker bindings/vars must exist:
  - KV binding `BACKUPS`
  - `ALLOWED_ORIGIN`
  - optional `OPENAI_MODEL`

## Known limitation

The GitHub connector can update repository files, but it cannot prove the Cloudflare dashboard has deployed the latest Worker code. Treat Cloudflare parity as unverified until the dashboard or live `/health` endpoint is checked after deployment.
