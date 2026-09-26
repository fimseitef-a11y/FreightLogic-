# GPT -> Claude Code: final version-freeze audit

Date: 2026-08-28
Purpose: endgame-only checklist for Issue #119 after Batch A + Batch B are green. This does not authorize an early version bump and does not add feature scope.

## Current pre-freeze marker state on main `a2b30274b89f800464d65f60bbee9ae6b1a44128`

- `app.js`: FreightLogic / `APP_VERSION` generation 24.0.1.
- `service-worker.js`: `SW_VERSION = '24.0.1'`, cache name derived from it; ADMIN/Midwest injected tags and CORE cache-busters are 24.0.1.
- `manifest.json`: `FreightLogic v24.0.1`.
- `index.html`: manifest query is `?v=24.0.1`; remaining script-query markers are governed by CLAUDE.md and M7 checks.
- `midwest-stack-authority.js`: header + `VERSION = '24.0.1'`.
- `voice-load.js`: header 24.0.1.
- `sw-bridge.js`: header 24.0.1.
- `scripts/verify-cloudflare-parity.mjs`: expects SW/manifest/overlay 24.0.1 and Worker v12.
- `cloud-backup-worker.js`: Worker v12; `/health` reports Worker generation 12 in current runtime.
- `CLAUDE.md`: still describes project/key constants/PWA as 24.0.1 and contains the authoritative release-bump contract.
- `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md`: must be reconciled at freeze, not earlier.

Current main has a successful Cloudflare production build check: build ID `bf4b2652-86e4-49f9-923a-cfdd24e89d8c`, Worker Version ID `2796d56b-4a8e-4abe-b5af-3fc54da15bfe`. This is provenance for the pre-freeze generation only.

## Critical observation

Current `scripts/m7-certify.mjs` checks only a subset of CLAUDE.md's full release-bump contract. A green M7 run alone must not be used to infer every version/cache marker is synchronized.

CLAUDE.md requires all of the following at the final release freeze:

1. `APP_VERSION` in `app.js` + a new top changelog entry; do not relabel an old entry.
2. `SW_VERSION` + header in `service-worker.js`.
3. Every service-worker `?v=` cache-buster: `ADMIN_UI_TAG`, `MIDWEST_STACK_TAG`, all relevant CORE entries.
4. `manifest.json` name.
5. `index.html` manifest `?v=`.
6. `index.html` `app.js`, `voice-load.js`, `sw-bridge.js` `?v=` script tags.
7. Design-system/header version comment near top of `index.html` where applicable.
8. `midwest-stack-authority.js` VERSION + header.
9. `voice-load.js` and `sw-bridge.js` headers.
10. Version references in `CLAUDE.md`: Project Overview, Key Constants, PWA section.
11. `scripts/verify-cloudflare-parity.mjs`: EXPECTED SW/manifest/overlay + every inline version assertion; Worker expected generation must match corrected Worker.
12. CSP parity: `index.html` CSP meta and `_headers` CSP line remain byte-identical.
13. `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` concrete markers + expected Worker generation.
14. Service-worker install-blocking `critical` shell still contains `midwest-stack-authority.js` and `vendor/xlsx.full.min.js`.

Also verify injected `admin-driver-ui.js` query markers even though the current M7 marker map does not independently compare its own file header.

## Sequencing

Do NOT choose/bump the final release version while Batch A or Batch B is still changing runtime/schema behavior.

After A+B are green:

1. select one final semantic app version and one final Worker generation;
2. apply the full 14-point parity list in one coherent commit;
3. update `scripts/m7-certify.mjs` semantics so HOLD/preflight cannot claim certification and extend marker checks where useful;
4. run the exact full suite + lanes on that exact SHA;
5. confirm Cloudflare Workers build SUCCESS for that exact SHA and record its Build ID + Version ID;
6. run live `/health`, unauthorized-admin denial, `/evaluate`, `/extract` smoke tests;
7. perform the finite iPhone field checklist on the same candidate;
8. record rollback SHA;
9. only then clear HOLD/freeze.

Do not create a version-only release to mask unresolved correctness work.