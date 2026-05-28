# FreightLogic v23.5.1 Release Notes

Date: 2026-05-27  
Release type: Authority overlay + deployment hardening  
Risk level: Low-to-medium, because app core `app.js` was not rewritten.

## What changed

### Midwest Stack v2 authority overlay

Added `midwest-stack-authority.js`, a safe runtime overlay that exposes:

- `window.FreightLogicMidwestStack.version`
- `window.FreightLogicMidwestStack.config`
- `window.FreightLogicMidwestStack.rateOverride`
- `window.FreightLogicMidwestStack.assessLoad(input)`
- `window.FreightLogicMidwestStack.classifyMarket(place)`

The overlay adds a `Midwest Stack v2 Authority` panel to the evaluator when the required FreightLogic DOM IDs are present.

### New bid modes

- `REALISTIC_WIN` — compressed DispatchLand/Sylectus cargo-van clearing mode.
- `PROTECT_FLOOR` — normal business-health pricing.
- `ESCAPE_RECOVERY` — position-first recovery mode.
- `DEAD_ZONE` — manual dead-zone exit gate only.

### New source authority files

- `midwest-stack-config.json`
- `rate-overrides-2026-05.json`
- `schemas/screenshot-intake-schema.json`
- `schemas/broker-memory-schema.json`
- `schemas/positioning-memory-schema.json`
- `docs/FREIGHTLOGIC_SOURCE_AUTHORITY_v23_5_1.md`
- `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`

### Service worker update

`service-worker.js` is now v23.5.1 and caches/injects:

- `midwest-stack-authority.js?v=23.5.1`
- `midwest-stack-config.json`
- `rate-overrides-2026-05.json`
- `manifest.json?v=23.5.1`

The service worker continues to preserve existing app-core URLs:

- `app.js?v=23.5.0`
- `voice-load.js?v=23.5.0`
- `admin-driver-ui.js?v=23.5.0`
- `sw-bridge.js?v=23.5.0`

This avoids a false full-version bump of app files that were not rewritten.

### Manifest update

`manifest.json` now displays `FreightLogic v23.5.1` and describes Midwest Stack v2 realistic bid guidance.

## Why this approach was chosen

`app.js` is large and stable. Instead of rewriting core production logic, this release adds a standalone authority module and service-worker overlay. That keeps the existing production app stable while making the new Midwest Stack v2 rules active and testable.

## Known limitations

- Existing users may need one reload after service-worker activation before the Midwest Stack panel appears.
- A completely fresh first page load may not show the overlay until the service worker has installed and served the app shell.
- Live Cloudflare Worker parity still must be verified from the dashboard or by checking the deployed `/health` endpoint after deployment.
- The GitHub connector only showed one accessible FreightLogic repository: `fimseitef-a11y/FreightLogic-`.

## Post-deploy acceptance tests

1. Open the deployed app.
2. Reload once to activate `service-worker.js` v23.5.1.
3. Open Evaluate.
4. Confirm `Midwest Stack v2 Authority` appears.
5. Enter revenue, loaded miles, and deadhead miles.
6. Confirm recommendations change when switching between bid modes.
7. Confirm offline reload still opens the app.
8. Confirm Cloudflare Worker `/health` returns Worker v10.
