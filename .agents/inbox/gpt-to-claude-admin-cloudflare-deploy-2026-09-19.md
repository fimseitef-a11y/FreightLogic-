# GPT → Claude — Admin Console Cloudflare deployment integration

Operator directive remains: finish FreightLogic without requiring a local computer.

## Why this handoff changed

The Netlify fallback project exists, but its source upload path requires a local uploader and the current sandbox cannot resolve the Netlify upload host. The repo already has a working GitHub Actions Cloudflare token and a proven manual Worker deployment workflow, so the cleaner no-computer path is now a dedicated Cloudflare Worker origin for the Admin Console.

## GPT-owned implementation ready in PR #250

Current GPT branch: `agent/gpt/admin-console-phase-a`

New isolated files inside GPT-owned `admin-console/`:
- `worker.js` — Worker-first wrapper around the ASSETS binding; applies privileged response headers to every asset response and never adds API CORS.
- `wrangler.jsonc` — Worker name `freightlogic-admin-console`, static assets from this subtree only, `ASSETS` binding, `run_worker_first: true`.
- `.assetsignore` — excludes worker/config/README/_headers/.assetsignore from browser assets.
- README documents the dedicated Workers.dev origin and release sequence.

Expected origin:
`https://freightlogic-admin-console.fimseitef.workers.dev`

The existing Netlify project can remain undeployed; it is no longer required if this Cloudflare origin is verified.

## GPT tests now fail closed until your cross-lane pieces exist

`tests/integration/admin-console.spec.mjs` now contains:
- ADMIN-09: `scripts/wrangler.backup-worker.jsonc` must set
  `ALLOWED_ORIGIN = https://freightlogic-admin-console.fimseitef.workers.dev`.
- ADMIN-12: actual static Worker response wrapper must preserve asset status/headers and add CSP/no-store/no-referrer/nosniff/XFO/permissions policy with no CORS.
- ADMIN-13: deployment/control-plane files must be excluded from static assets.
- ADMIN-14: repo must expose `.github/workflows/deploy-admin-console.yml`, manual-dispatch only, explicit DEPLOY confirmation, existing `CLOUDFLARE_API_TOKEN`, exact `admin-console/wrangler.jsonc`, and post-deploy checks against the dedicated origin.

The spec is still not registered in Claude-owned `tests/run-all.mjs`; RH-01 remains the current aggregate failure until you integrate it.

## Exact Claude-owned integration work

Please create a Claude integration branch from current main, bring in the final GPT PR #250 commits, then:

1. **Register the exact test**
   - add only `integration/admin-console.spec.mjs` to `tests/run-all.mjs`.
   - do not weaken RH-01.

2. **Configure exact second CORS origin**
   - in `scripts/wrangler.backup-worker.jsonc`, change the current `ALLOWED_ORIGIN` var from the driver origin to:
     `https://freightlogic-admin-console.fimseitef.workers.dev`
   - this is safe with current Worker semantics because the driver production origin is already permanently present in `ALLOWED_ORIGINS`; `env.ALLOWED_ORIGIN` is the exact-match hook for one additional origin.
   - no `cloud-backup-worker.js` code change is needed solely for this CORS addition.

3. **Add `.github/workflows/deploy-admin-console.yml`**
   - manual `workflow_dispatch` only.
   - required choice `CANCEL|DEPLOY`; refuse unless DEPLOY.
   - checkout + Node 22.
   - fail early unless existing `CLOUDFLARE_API_TOKEN` is present.
   - `npx --yes wrangler@4 deploy -c admin-console/wrangler.jsonc --dry-run`
   - then deploy the same config.
   - post-deploy check:
     - GET dedicated origin returns 200 and title/Admin Console shell.
     - security headers include CSP with `frame-ancestors 'none'`, Cache-Control no-store, nosniff, X-Frame-Options DENY.
     - config/control paths such as `/wrangler.jsonc`, `/worker.js`, `/README.md`, `/_headers`, `/.assetsignore` are not exposed as 200 downloadable assets.

4. **Deploy/update backup Worker only after the CORS config is integrated**
   - use the existing `Deploy Backup Worker` workflow.
   - Worker generation/source does not need a bump merely for changing the deployment var unless repository release discipline says otherwise; follow exact current tests rather than guessing.
   - verify driver origin still receives exact CORS and admin origin now receives itself, never wildcard.

5. **Live Admin Console smoke**
   - missing/invalid admin auth must fail closed.
   - with real admin auth supplied interactively/session-only: list, invite, re-invite and revoke.
   - never paste or log the admin credential.
   - only after live Phase B succeeds should Phase C remove the driver-app admin surface.

## Evidence already collected

- Cloudflare branch preview of PR #250 renders the Admin Console successfully.
- From that unapproved preview origin, browser fetches to Worker `/health` and `/admin/users` are CORS-blocked today. That is expected and confirms the Worker does not currently bless arbitrary origins.
- Current backup Worker source already exact-matches `env.ALLOWED_ORIGIN` and retains the driver production origin in the built-in allowlist.
- Current deploy config still points `ALLOWED_ORIGIN` at the driver origin, so ADMIN-09 intentionally requires the integration change above.

Do not merge/deploy PR #250 as a finished privileged surface until the registered full suite, dedicated-origin deploy, exact CORS and live auth smoke all pass.
