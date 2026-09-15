# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the post-extraction v24.1 repository. The CSS presentation seam is now real; JavaScript UI/core code inside `app.js` remains serialized until a separately approved extraction creates additional physical paths.

**UI redesign takeover (2026-09-14, operator-directed).** The operator explicitly directed GPT to take over and handle the approved FreightLogic reference-image redesign. `styles.css` is therefore reassigned to `gpt` for the presentation implementation. All other non-`SHARED` paths remain `claude`; this is a targeted presentation takeover, not a blanket ownership transfer.

`SHARED` paths — `app.js`, `index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json`, `.agents/`, `AGENTS.md`, `.gitignore`, `.assetsignore` — stay SHARED and still require a held lock, because that serialization protects against concurrent sessions, not just different agents. Commit-prefix discipline, the full-suite gate and release-marker discipline are unchanged. A path with no row still fails closed.

**OMEGA continuation closed (2026-09-15).** The bounded GPT task — app.js economics/math, market-classifier collision and release-generation discipline — landed in `fb408a0` (PR #200). Physical iPhone A1–A10 and M6 raw-data certification remained open.

**Full-repair takeover (2026-09-15, operator-directed).** The operator explicitly directed GPT to fix every confirmed bug/error and reconcile the latest Grok/DeepSeek audit inputs without restarting or undoing verified work. This is a bounded repair/certification task, not a permanent lane transfer. The exact-file exceptions below authorize GPT only for the confirmed first-use cloud-admin race, trip identity/import data loss, payment-state UNKNOWN coercion, invented profit/hour speed, share-target filename hardening, verified legacy-token cleanup gaps, and the release/test/docs files required to prove and ship those fixes. DeepSeek's alleged 24.0.12/24.0.11 mismatch was rejected by exact HEAD plus post-deploy live parity and is not a repair target. These exceptions expire when the full-repair PR lands. A1–A10 and authentic M6 remain open evidence gates.

| Top-level path | Owner | Notes |
|---|---|---|
| `.github/workflows/full-repair-once.yml` | gpt | Temporary one-shot patch/test helper; delete before merge. |
| `admin-driver-ui.js` | gpt | Temporary first-use Manage Drivers event-ownership/rotation parity exception. |
| `cloud-backup-worker.js` | gpt | Temporary verified legacy plaintext-token cleanup exception. |
| `tests/integration/full-repair-regressions.spec.mjs` | gpt | Temporary regression suite for this repair. |
| `tests/unit/worker-token-rotation.spec.mjs` | gpt | Temporary legacy-token cleanup regression exception. |
| `tests/unit/cache-generation.spec.mjs` | gpt | Temporary DB/app-generation invariant update for the schema migration. |
| `tests/run-all.mjs` | gpt | Temporary regression-registration exception. |
| `scripts/verify-cloudflare-parity.mjs` | gpt | Temporary app/Worker parity marker update. |
| `midwest-stack-config.json` | gpt | Temporary appTarget marker update only. |
| `midwest-stack-authority.js` | gpt | Temporary generation marker update only. |
| `voice-load.js` | gpt | Temporary generation marker update only. |
| `CLAUDE.md` | gpt | Temporary release/evidence documentation exception. |
| `FIELD_TEST_CHECKLIST.md` | gpt | Temporary release/evidence documentation exception; A1–A10 stay open. |
| `docs/CLOUDFLARE_DEPLOYMENT_PARITY_CHECKLIST.md` | gpt | Temporary parity-evidence documentation exception. |
| `.assetsignore` | SHARED | Repository/deployment metadata; coordinate changes. |
| `.github/` | claude | Release/certification workflows except the exact temporary workflow above. |
| `.githooks/` | claude | Lane-guard hooks. |
| `.gitignore` | SHARED | Repository-wide behavior. |
| `.agents/` | SHARED | Durable protocol on `main`; live state on `agent-coordination`. |
| `AGENTS.md` | SHARED | Coordination contract. |
| `AUDIT_REPORT.md` | claude | Core audit record. |
| `README.txt` | claude | General documentation. |
| `RECON_24_0_2.md` | claude | Historical reconciliation artifact. |
| `_headers` | claude | CSP/security/deployment headers. |
| `app.js` | SHARED | Serialized. Any edit requires `lock/app-js` and full suite. |
| `dat-rateview.js` | claude | Frozen/dormant and non-authoritative for cargo-van pricing. |
| `docs/` | claude | Certification/backup/tax/authority docs except exact temporary row above. |
| `favicon16.png` | claude | Visual asset. |
| `favicon32.png` | claude | Visual asset. |
| `icon1024.png` | claude | Visual asset. |
| `icon120.png` | claude | Visual asset. |
| `icon128.png` | claude | Visual asset. |
| `icon152.png` | claude | Visual asset. |
| `icon167.png` | claude | Visual asset. |
| `icon180.png` | claude | Visual asset. |
| `icon192.png` | claude | Visual asset. |
| `icon256.png` | claude | Visual asset. |
| `icon512.png` | claude | Visual asset. |
| `icon64.png` | claude | Visual asset. |
| `index.html` | SHARED | UI shell + script ordering; lock before editing. |
| `manifest.json` | SHARED | PWA/release metadata; lock before editing. |
| `modern-shell.js` | SHARED | Structural navigation seam; lock before editing. |
| `schemas/` | claude | Data/contracts. |
| `scripts/` | claude | Release/certification tooling except exact temporary row above. |
| `service-worker.js` | SHARED | Offline shell/release-critical; lock before editing. |
| `styles.css` | gpt | Operator-directed presentation takeover; carries no release version by design. |
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/` | claude | Playwright suite except exact temporary rows above; assertions may not be weakened. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent

- `styles.css` remains GPT-owned for the approved redesign.
- `app.js` remains SHARED and requires `lock/app-js` plus the full suite.
- The full-repair exception is narrow and temporary: only the exact rows above are GPT-owned for this operator-directed repair.
- All non-excepted Claude paths remain Claude-owned.

`/.agents/inbox/` remains the cross-session handoff channel.

## Enforcement

- `scripts/lane-guard.mjs` parses this file as the single source of truth.
- `.githooks/pre-commit` rejects a foreign-lane edit and a SHARED edit with no held lock.
- `.github/workflows/lanes.yml` re-checks path ownership and commit prefixes on every PR to `main`.
- A path with no row fails closed.
- A lock past `expected_release_utc` +2h is stale and grants nothing; reap deliberately per `/AGENTS.md`.

## Cross-lane requests

If a task requires a foreign path, use `/.agents/inbox/` on `agent-coordination`. Do not make opportunistic cross-lane edits.
