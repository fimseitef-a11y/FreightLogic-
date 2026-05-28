# FreightLogic Source Authority v23.5.1

Date: 2026-05-27  
Status: Active authority package  
Repository: fimseitef-a11y/FreightLogic-

## Authority order

1. Live GitHub repository `fimseitef-a11y/FreightLogic-` on `main` is the active code authority.
2. Cloudflare Pages / Worker deployment must be verified against this repository before being treated as production-current.
3. Older uploaded source ZIPs are historical snapshots only unless rebuilt from this repository.
4. Midwest Stack v2 is the active freight-decision authority layer for cargo-van bid logic and positioning.
5. May 2026 cargo-van compression override is active whenever realistic winning-bid guidance is requested.

## Active runtime files

- `index.html` — PWA shell and embedded design system.
- `app.js` — FreightLogic v23.5.0 core engine.
- `service-worker.js` — v23.5.1 cache and overlay injector.
- `sw-bridge.js` — service-worker update bridge.
- `voice-load.js` — voice load-entry module.
- `admin-driver-ui.js` — admin/driver management UI overlay.
- `cloud-backup-worker.js` — Cloudflare Worker v10 source for backup, AI evaluate, AI extract, and health.
- `manifest.json` — PWA manifest.
- `_headers` — Cloudflare Pages security headers.

## New authority files added in v23.5.1

- `midwest-stack-authority.js` — safe Midwest Stack v2 runtime overlay.
- `midwest-stack-config.json` — canonical Midwest Stack v2 rules/config.
- `rate-overrides-2026-05.json` — May 2026 realistic cargo-van rate override.
- `schemas/screenshot-intake-schema.json` — load-board screenshot intake schema.
- `schemas/broker-memory-schema.json` — broker outcome memory schema.
- `schemas/positioning-memory-schema.json` — market/positioning memory schema.

## v23.5.1 implementation notes

The app core was intentionally not rewritten. `app.js` is large and stable; this update uses a service-worker-injected overlay to add Midwest Stack v2 bid modes and live calculation support without destabilizing existing finance, backup, trip, voice, and PWA functionality.

The service worker now caches and injects `midwest-stack-authority.js?v=23.5.1` and caches the new JSON authority files. Existing users may need to reload once after the service worker activates.

## Required post-deploy checks

1. Open the app fresh in Safari/Chrome.
2. Confirm the service worker reports version `23.5.1`.
3. Open Evaluate and confirm the `Midwest Stack v2 Authority` panel appears.
4. Test all four bid modes: Realistic Win, Protect Floor, Escape / Recovery, Dead Zone Exit.
5. Test offline reload after the service worker activates.
6. Confirm `/health` on the Cloudflare Worker returns Worker v10.
7. Confirm admin endpoints reject without `X-Admin-Token`.
8. Confirm driver endpoints reject without `X-Backup-Token`.

## Do not replace this source with older ZIPs

Older project ZIPs remain useful for history, but they are behind the live repository. Any future downloadable source pack should be rebuilt from this repository after v23.5.1.
