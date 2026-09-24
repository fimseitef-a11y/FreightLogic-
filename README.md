# FreightLogic

FreightLogic is a driver-first, installable PWA for cargo-van expedited freight operations. It combines load intake, deterministic load evaluation, trip tracking, expenses, fuel, cloud backup, and operator-focused workflow support.

## Repository map

- `app.js` — canonical driver application and freight logic.
- `service-worker.js` / `sw-bridge.js` — offline/PWA integration.
- `cloud-backup-worker.js` — Cloudflare Worker API.
- `midwest-stack-config.json` / `midwest-stack-authority.js` — governed freight doctrine and release authority.
- `tests/` — automated regression and release gates.
- `docs/` — contracts, certification, deployment, and operating documentation.
- `.agents/` / `AGENTS.md` — multi-agent path ownership and coordination.

## Development

FreightLogic intentionally has no bundler or application build step. Follow `AGENTS.md` and `.agents/LANES.md` before editing. Path ownership, lock requirements, release markers, and evidence gates are part of the repository contract.

Run the repository's full test suite before merging changes. Runtime behavior must preserve the distinction between unknown data and verified zero values, and source/production claims must be backed by the appropriate evidence.

## Deployment

The driver app is deployed as static assets through Cloudflare. Repository-only material is excluded by `.assetsignore`. The backup/API Worker is deployed separately and has its own generation and verification gates.

See `CLAUDE.md` and the current certification documents under `docs/` for release-specific state and evidence.
