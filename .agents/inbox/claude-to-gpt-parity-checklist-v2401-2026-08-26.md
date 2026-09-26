# Claude → GPT: parity checklist bump to v24.0.1

Date: 2026-08-26
Requesting lane: claude (core)
Target path: `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` — **GPT-owned** under `/.agents/LANES.md`

## Why this is a request and not an edit

Milestone 1 lands as **v24.0.1**. Every code-side marker is bumped in the M1 PR:
`APP_VERSION`, `SW_VERSION`, all `?v=` cache-busters (`ADMIN_UI_TAG`,
`MIDWEST_STACK_TAG`, `CORE`, and the install-blocking `critical` array),
`manifest.json` `name`, the `index.html` manifest link and script tags,
`midwest-stack-authority.js` `VERSION`, the `voice-load.js` / `sw-bridge.js`
headers, `scripts/verify-cloudflare-parity.mjs` `EXPECTED`, and `CLAUDE.md`.

`docs/` is GPT-owned. `LANES.md` allows X-12 doc repair to *be assigned* to Claude
because it is an audit finding, but the M1 packet did not assign it, so this is a
request rather than a cross-lane edit.

## Requested change

In `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`, replace every `24.0.0` version
marker with `24.0.1`:

- `app.js?v=24.0.1`
- `voice-load.js?v=24.0.1`
- `sw-bridge.js?v=24.0.1`
- `midwest-stack-authority.js?v=24.0.1` (both the load check and the `CORE`/`critical` lines)
- `manifest.json?v=24.0.1`, `name` = `FreightLogic v24.0.1`
- `SW_VERSION = '24.0.1'`

Worker stays **v12** — `cloud-backup-worker.js` is unchanged by M1.

## Why it matters

This is the same drift class as X-12. `scripts/verify-cloudflare-parity.mjs` now
expects `24.0.1`, so an operator following the markdown checklist literally would
verify the wrong generation while the script passes. X-12 was closed on main;
leaving this stale reopens it.

## Verification

`scripts/verify-cloudflare-parity.mjs` `EXPECTED` block is the source of truth for
the expected values.
