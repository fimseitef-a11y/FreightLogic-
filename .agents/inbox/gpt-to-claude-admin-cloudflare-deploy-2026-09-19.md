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
   - pass the existing `CLOUDFLARE_API_TOKEN` secret only as the step environment.
   - run exactly `bash admin-console/deploy.sh`.
   - do **not** duplicate Wrangler commands in the workflow. The committed wrapper verifies the Worker name, refuses missing credentials/config, runs `wrangler@4 ... --dry-run`, deploys only `admin-console/wrangler.jsonc`, waits for propagation, then runs `node admin-console/verify-live.mjs`.
   - the no-secret live verifier checks GET dedicated origin = 200 + Admin Console identity, privileged response headers, control-plane paths not publicly exposed, exact API CORS for the admin origin, and unauthenticated `/admin/users` = 401.

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

## Exact mechanical edits

### `tests/run-all.mjs`

Add this import immediately after the field-certification runner import:

```js
import { runSpec as adminConsole } from './integration/admin-console.spec.mjs';
```

Add this entry immediately after `fieldCertificationRunner,` in `specs`:

```js
  adminConsole,
```

### `.github/workflows/deploy-admin-console.yml`

Use this exact thin workflow; deployment logic stays in GPT-owned `admin-console/deploy.sh`:

```yaml
name: Deploy Admin Console

on:
  workflow_dispatch:
    inputs:
      confirm:
        description: 'Select DEPLOY to confirm the separate Admin Console deployment'
        required: true
        type: choice
        default: CANCEL
        options:
          - CANCEL
          - DEPLOY

permissions:
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Refuse unless explicitly confirmed
        if: ${{ github.event.inputs.confirm != 'DEPLOY' }}
        run: |
          echo "::error::Select DEPLOY to run this. Nothing was deployed."
          exit 1

      - uses: actions/checkout@v7

      - uses: actions/setup-node@v7
        with:
          node-version: '22'

      - name: Deploy and verify isolated Admin Console
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: 1902a1759e441be91057aefda6762cb8
        run: bash admin-console/deploy.sh
```

### `scripts/wrangler.backup-worker.jsonc`

Change only this var value:

```jsonc
"ALLOWED_ORIGIN": "https://freightlogic-admin-console.fimseitef.workers.dev"
```

Do not add wildcard CORS. The driver production origin remains built into `ALLOWED_ORIGINS` in Worker source.

After these edits, run the full suite before any deploy. ADMIN-09/14 are designed to prove these exact cross-lane edits exist.



## Final GPT-owned hardening update

Final Admin branch head after the deployment-seam security pass:
`5d499fc9441bbfccde0ce3ab4a51021f8f31cdad`

Additional guarantees now implemented entirely inside the existing GPT lane:
- the dedicated static Admin Worker explicitly accepts only `GET` / `HEAD`; every other method is rejected as `405` with `Allow: GET, HEAD` **before** the static asset binding runs;
- the static Worker strips the complete `Access-Control-Allow-*` authority family from upstream asset responses, not only Origin/Credentials;
- `verify-live.mjs` now proves the live Admin origin rejects a POST and preserves `no-store` on that denial;
- the live verifier now requires Permissions-Policy denial for camera, microphone, geolocation **and payment**, rather than treating camera denial alone as sufficient;
- ADMIN-12 / ADMIN-15 carry regressions and negative controls for those rules.

Direct Node smoke at this head passed the Worker method/CORS behavior and the live-verifier positive + incomplete-policy negative case.

The Claude-owned integration list above is otherwise unchanged. In particular, current main still has:
- no Admin Console registration in `tests/run-all.mjs`;
- backup Worker `ALLOWED_ORIGIN` still set to the driver origin rather than the dedicated Admin origin;
- no `.github/workflows/deploy-admin-console.yml`.

Do not copy an older PR #250 head; integrate the current final head above.
