# FreightLogic Admin Console — Phase A/B draft

This directory is the isolated administrative onboarding surface approved by issue #231.

Security contract:
- separate origin from the driver PWA;
- runtime defense-in-depth refuses to initialize admin authentication if this bundle is accidentally served from the driver origin;
- online-only MVP with no offline credential cache;
- admin access is supplied at runtime and retained only in browser session storage;
- only identity/onboarding operations are available: list, invite, re-invite, revoke;
- driver onboarding uses short-lived claim-code links (`#i=`), never transported permanent driver credentials;
- no freight, trip, expense, receipt, tax, GPS, or driver-history APIs;
- Worker authorization remains authoritative.

## Deployment hold

Do not deploy or merge this surface as production-ready until a real distinct admin origin exists, that exact origin is configured in the Worker CORS allowlist, and live admin-auth/list/invite/re-invite/revoke smoke tests pass. The runtime same-origin guard is defense-in-depth only; the driver deployment must still exclude this privileged surface rather than treating a hidden /admin-console/ path as separation. Phase C removal of the legacy driver-app admin surface remains gated on that live proof.


## Static-host deployment contract

Deploy this directory as the **site root** of its own project/origin so `_headers` is applied as response metadata rather than served as an ordinary nested file. The response policy intentionally adds controls a CSP `<meta>` element cannot provide reliably, including `frame-ancestors 'none'`, plus `no-store`, `nosniff`, no-referrer, clickjacking defense, and denial of device capabilities the admin MVP does not use.

Do not add `Access-Control-Allow-Origin` here. API CORS remains the Worker's exact-origin security boundary and must explicitly allow the deployed admin origin.

## Cloudflare separate-origin deployment (preferred no-computer path)

This subtree now carries its own Workers Static Assets deployment seam:

- `wrangler.jsonc` deploys a distinct Worker named `freightlogic-admin-console`;
- `worker.js` runs before every static asset and applies the privileged response headers itself;
- `.assetsignore` prevents `worker.js`, Wrangler config, README, `_headers`, and the ignore file from becoming browser-downloadable assets;
- the only intended browser assets are `index.html`, `app.js`, and `styles.css`.

Expected Workers.dev origin for the current account:
`https://freightlogic-admin-console.fimseitef.workers.dev`

This is intentionally a different origin from the driver PWA. The existing repository Cloudflare API token may be reused only through a Claude-owned/manual deployment workflow; no token belongs in this subtree or in source.

Before treating this as production-ready:
1. deploy this subtree with its `wrangler.jsonc`;
2. add the exact deployed admin origin to the backup/API Worker's exact CORS allowlist;
3. verify response security headers on the admin origin;
4. live-test admin auth/list/invite/re-invite/revoke;
5. only then perform Phase C removal of the driver-app admin surface.

The Netlify project created during fallback investigation may remain undeployed; it is not needed if this dedicated Cloudflare origin is verified.

