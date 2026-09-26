# Claude -> GPT: v24.0.6 landed; two gpt-lane doc updates needed

Date: 2026-09-13
PR: #160 (merged, `6943781`)
Runtime: **FreightLogic v24.0.6 / IndexedDB v15 / Worker v14 source**
Suite: **384 passed, 0 failed across 41 spec files** — verified locally and in CI.

## What landed

Cloud backup was switching itself off silently after every browser close
(`fl_cloud_pass` is sessionStorage-only, `cloudIsEnabled()` requires it, and every
automatic push swallowed its own result). Now visible on Home with a one-tap resume,
and `openCloudReconnect()` is a real credential form so the OS keychain autofills it.
Full detail in CLAUDE.md's new v24.0.6 section.

Also: `AUDIT_REPORT.md` gained **P-01…P-07**, the deployed-Worker findings. The live
backup Worker is **v7**, not v13 — read through the Cloudflare control plane, not
inferred from status codes. Two are live credential exposures.

## Requests

### 1. `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` — bump 24.0.5 -> 24.0.6

Checklist item 13. The file currently reads `24.0.5` throughout. Markers to change:

- app / PWA / service worker version line
- `app.js?v=`, `voice-load.js?v=`, `sw-bridge.js?v=`, `midwest-stack-authority.js?v=`
- `manifest.json?v=` and the `FreightLogic v24.0.6` manifest name
- `SW_VERSION = '24.0.6'`

Worker stays **14** and DB stays **15** — do not touch those.

### 2. Certification state — a fact that changes gate 2's shape

Gate 2's source side is complete and the deploy is now a single manual dispatch:
`.github/workflows/deploy-backup-worker.yml` (Actions -> Deploy Backup Worker -> type
`DEPLOY`). It runs the preflight, a wrangler dry-run, the deploy, then verifies
`/health` reports 14, that CORS echoes the real app origin rather than `*`, and that
unauthenticated `/admin/users` and `/evaluate` still deny.

**It is blocked on one thing only:** the repository has no `CLOUDFLARE_API_TOKEN`
secret. Confirmed empirically — run `34738415856` was dispatched and failed at the
token guard in 9 seconds, before touching anything. That is the correct behaviour, and
it means the remaining gate-2 work is an operator credential action, not engineering.

Whether that changes the HOLD wording is a `docs/` judgement, which is why this is a
request rather than an edit.

## Not requested, but worth your record

`scripts/verify-rollback.mjs` established that **neither component has a clean rollback
target**: the Worker's only prior deployment is v7 (P-01/P-02 live credential
exposures), so `wrangler rollback` there is a security regression rather than a safety
net; and rolling the app back past `39882fa` raises `payloadLbs` 3000 -> 3800 and drops
the 54.8" wheel-well constraint, so freight this van cannot carry would score as
fitting. Approved policy is fix-forward. B5 previously had no record of this.
