# Cloudflare Deployment Parity Checklist

Use this checklist after every FreightLogic repository update.

## Goal

Prove that the live Cloudflare Pages site and Cloudflare Worker are running the same generation as GitHub `main`.

## Pages / PWA checks

- Open the deployed Pages URL in a private/incognito browser session.
- Open DevTools or Safari Web Inspector if available.
- Confirm `index.html` loads without console syntax errors.
- Confirm `app.js?v=23.5.0` loads.
- Confirm `voice-load.js?v=23.5.0` loads.
- Confirm `sw-bridge.js?v=23.5.0` loads.
- Confirm `midwest-stack-authority.js?v=23.5.1` loads after service-worker activation.
- Confirm `manifest.json?v=23.5.0` loads.
- Confirm icons load with 200 status.
- Confirm `_headers` security headers are visible on the deployed site.

## Service worker checks

- Confirm `service-worker.js` contains `SW_VERSION = '23.5.1'`.
- Confirm `CORE` includes `midwest-stack-authority.js?v=23.5.1`.
- Confirm old caches are deleted after activation.
- Confirm offline reload still opens the app shell.
- Confirm the service worker does not cache cross-origin API responses.
- Confirm share-target POST flow still redirects to `./index.html#share`.

## Midwest Stack overlay checks

- Open the Evaluate view.
- Confirm `Midwest Stack v2 Authority` appears below the evaluator output area.
- Enter revenue, loaded miles, and deadhead miles.
- Confirm True RPM, grade, realistic win, ask, verdict, and risk flags update.
- Confirm these modes are available:
  - Realistic Win
  - Protect Floor
  - Escape / Recovery
  - Dead Zone Exit

## Worker checks

Expected source file: `cloud-backup-worker.js` v10.

- `GET /health` should return JSON with `ok: true`, `version: '10'`, and a timestamp.
- Admin routes must reject without `X-Admin-Token`.
- Driver backup/evaluate/extract routes must reject without `X-Backup-Token`.
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
