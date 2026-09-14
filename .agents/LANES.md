# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the post-extraction v24.1 repository. The CSS presentation seam is now real; JavaScript UI/core code inside `app.js` remains serialized until a separately approved extraction creates additional physical paths.

| Top-level path | Owner | Notes |
|---|---|---|
| `.assetsignore` | SHARED | Repository/deployment metadata; coordinate changes. |
| `.github/` | claude | CI/release/security workflows. |
| `.githooks/` | claude | Lane-guard git hooks; enforcement tooling for this map. |
| `.gitignore` | SHARED | Repository-wide behavior. |
| `.agents/` | SHARED | Durable protocol on `main`; live state on `agent-coordination`. Do not edit another agent's live lock/inbox entry except per protocol. |
| `AGENTS.md` | SHARED | Coordination contract. |
| `AUDIT_REPORT.md` | claude | Core audit record; GPT may request changes through inbox. |
| `CLAUDE.md` | claude | Core architecture/operations context. |
| `FIELD_TEST_CHECKLIST.md` | gpt | Non-core field-facing documentation; changes that alter test policy require Claude review. |
| `README.txt` | gpt | General/non-core documentation. |
| `RECON_24_0_2.md` | claude | Read-only core reconciliation/audit artifact; maintained with the Claude core/audit lane. |
| `_headers` | claude | CSP/security/deployment headers. |
| `admin-driver-ui.js` | gpt | Presentation/admin UI; if a change touches auth/storage semantics, hand off through inbox. |
| `app.js` | SHARED | **Serialized until split. Any edit requires `lock/app-js` and full suite.** Decision/runtime/core behavior remains Claude-owned unless explicitly reassigned. |
| `cloud-backup-worker.js` | claude | Worker/auth/storage/backup core. |
| `dat-rateview.js` | claude | Freight-rate source client. Frozen/dormant and non-authoritative per the completion plan; may not influence canonical cargo-van pricing without operator re-authorization. |
| `docs/` | gpt | General docs by default. Security/backup/tax/authority contract changes require Claude review; X-12 doc repair may be assigned to Claude because it is an audit finding. |
| `favicon16.png` | gpt | Visual asset. |
| `favicon32.png` | gpt | Visual asset. |
| `icon1024.png` | gpt | Visual asset. |
| `icon120.png` | gpt | Visual asset. |
| `icon128.png` | gpt | Visual asset. |
| `icon152.png` | gpt | Visual asset. |
| `icon167.png` | gpt | Visual asset. |
| `icon180.png` | gpt | Visual asset. |
| `icon192.png` | gpt | Visual asset. |
| `icon256.png` | gpt | Visual asset. |
| `icon512.png` | gpt | Visual asset. |
| `icon64.png` | gpt | Visual asset. |
| `index.html` | SHARED | UI shell + CSP/script ordering; lock before editing. |
| `manifest.json` | SHARED | PWA/release + visual metadata; lock before editing. |
| `midwest-stack-authority.js` | claude | Decision/bid advisory core and DZ gate integration. |
| `midwest-stack-config.json` | claude | Decision/bid configuration. |
| `modern-shell.js` | SHARED | Driver-facing structural navigation seam. Reuses canonical app renderers/state; lock before editing and run the full suite for behavior changes. |
| `schemas/` | claude | Data/contracts. |
| `scripts/verify-rollback.mjs` | gpt | Operator-directed 2026-09-14 completion takeover: B5 read-only rollback/fix-forward evidence only. Broader `scripts/` ownership remains Claude. |
| `scripts/` | claude | Verification/release/tooling scripts. |
| `service-worker.js` | SHARED | Offline shell/release-critical. Lock before editing; full suite required. |
| `styles.css` | gpt | Primary extracted presentation stylesheet. GPT may make presentation-only changes here without an `app.js` lock; behavior, data, decision, persistence, auth, or service-worker changes must stay in their owning/shared lanes. |
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/run-all.mjs` | gpt | Operator-directed 2026-09-14 completion takeover: wire the two exact release-gate regressions below into the aggregate suite. |
| `tests/unit/rollback-verifier-current.spec.mjs` | gpt | Operator-directed 2026-09-14 completion takeover: current B5 verifier regression only. |
| `tests/integration/six-width-layout.spec.mjs` | gpt | Operator-directed 2026-09-14 completion takeover: browser geometry acceptance only. |
| `tests/` | claude | Test harness and assertions. GPT does not edit other Claude-owned suites unless explicitly reassigned later. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `voice-load.js` | claude | Functional intake/parser behavior. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent after CSS extraction

Claude owns core implementation, audit remediation, security/storage/decision logic, `app.js` runtime behavior, and the test harness. GPT owns `styles.css`, bounded presentation assets, `admin-driver-ui.js` within its presentation-only boundary, and non-core documentation.

The CSS seam is the first safe independent application presentation lane. It does **not** authorize GPT to edit conceptual UI sections that still live inside `app.js`; those remain SHARED/serialized and core-owned unless a later approved extraction creates additional physical presentation paths.

### Operator-directed completion takeover — 2026-09-14

The operator explicitly directed GPT to take over and complete the app. That approval is implemented narrowly rather than as a wholesale core-lane transfer: only `scripts/verify-rollback.mjs`, `tests/run-all.mjs`, `tests/unit/rollback-verifier-current.spec.mjs`, and `tests/integration/six-width-layout.spec.mjs` are GPT-owned for the remaining v24.0.9 release-evidence gates. `app.js`, Worker/auth/storage code, the service worker, `.github/`, and every other script/test remain under their existing ownership/lock rules.

## Enforcement

This map is enforced mechanically, not by recollection:

- `scripts/lane-guard.mjs` parses **this file** as the single source of truth. There is no generated copy to drift from it.
- `.githooks/pre-commit` rejects a staged change to a foreign lane, and a staged change to a `SHARED` path with no held lock covering that path. Enable per clone: `git config core.hooksPath .githooks` and `git config freightlogic.agent <claude|gpt>`.
- `.github/workflows/lanes.yml` re-checks path ownership and commit prefixes on every PR to `main`. The hook is fast feedback and is bypassable; CI is the boundary.
- A path with **no row in this table** fails closed. Adding a file means adding its row.
- A lock past `expected_release_utc` + 2h is reported as **stale** and grants nothing — to its holder either. It is never auto-stolen; reap it deliberately per `/AGENTS.md`.

## Cross-lane requests

If a task requires a foreign path, write a request under `/.agents/inbox/` on `agent-coordination`. Do not make an opportunistic cross-lane edit.
