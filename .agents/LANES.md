# FreightLogic Path Ownership

Ownership is physical-path based. Conceptual ownership does not authorize an edit outside the paths below. `SHARED` means serialized through the lock protocol in `/AGENTS.md`.

This map reflects the post-extraction v24.1 repository. The CSS presentation seam is now real; JavaScript UI/core code inside `app.js` remains serialized until a separately approved extraction creates additional physical paths.

**UI redesign takeover (2026-09-14, operator-directed).** The operator explicitly directed GPT to take over and handle the approved FreightLogic reference-image redesign. `styles.css` is therefore reassigned to `gpt` for the presentation implementation. All other non-`SHARED` paths remain `claude`; this is a targeted presentation takeover, not a blanket ownership transfer.

`SHARED` paths — `app.js`, `index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json`, `.agents/`, `AGENTS.md`, `.gitignore`, `.assetsignore` — stay SHARED and still require a held lock, because that serialization protects against concurrent sessions, not just different agents. Commit-prefix discipline, the full-suite gate and release-marker discipline are unchanged. A path with no row still fails closed.

**OMEGA continuation (2026-09-15, operator-directed).** The operator explicitly asks GPT to verify and repair the remaining app.js economics/math paths, market classifier collision, and release-generation discipline, with regressions and exact-head gates. This bounded task authorizes those shared app.js behaviors under lock/app-js. The exact file exceptions below cover its regressions, generation markers, and evidence; other Claude paths retain their ownership. These assignments do not close physical iPhone A1–A10 or M6 raw-data certification.

| Top-level path | Owner | Notes |
|---|---|---|
| `docs/OMEGA_CONTINUATION_2026-09-15.md` | gpt | Bounded operator-directed OMEGA continuation. |
| `scripts/verify-cloudflare-parity.mjs` | gpt | Bounded operator-directed OMEGA continuation. |
| `scripts/verify-release-generation.mjs` | gpt | Bounded operator-directed OMEGA continuation. |
| `tests/run-all.mjs` | gpt | Bounded operator-directed OMEGA continuation. |
| `tests/unit/release-generation-discipline.spec.mjs` | gpt | Bounded operator-directed OMEGA continuation. |
| `tests/integration/omega-economics.spec.mjs` | gpt | Bounded operator-directed OMEGA continuation. |
| `.assetsignore` | SHARED | Repository/deployment metadata; coordinate changes. |
| `.github/` | claude | Consolidated to the Claude completion lane on 2026-09-14; release/certification workflows. |
| `.githooks/` | claude | Lane-guard git hooks; enforcement tooling for this map. |
| `.gitignore` | SHARED | Repository-wide behavior. |
| `.agents/` | SHARED | Durable protocol on `main`; live state on `agent-coordination`. Do not edit another agent's live lock/inbox entry except per protocol. |
| `AGENTS.md` | SHARED | Coordination contract. |
| `AUDIT_REPORT.md` | claude | Core audit record; findings are recorded with their reproduction and their live production status. |
| `CLAUDE.md` | claude | Core architecture/operations context. |
| `FIELD_TEST_CHECKLIST.md` | claude | Physical-iPhone verification instrument maintained with release certification. |
| `README.txt` | claude | General/non-core documentation. |
| `RECON_24_0_2.md` | claude | Read-only core reconciliation/audit artifact; maintained with the Claude core/audit lane. |
| `_headers` | claude | CSP/security/deployment headers. |
| `admin-driver-ui.js` | claude | Admin UI. Auth/storage semantics here are core: the session-scoped admin token and `purgeLegacyTok()` are load-bearing and documented in CLAUDE.md. |
| `app.js` | SHARED | **Serialized until split. Any edit requires `lock/app-js` and full suite.** Decision/runtime/core behavior remains Claude-owned unless explicitly reassigned. |
| `cloud-backup-worker.js` | claude | Backup/API Worker source. Worker v17 (monotonic backup/delta key clock) is the current generation. |
| `dat-rateview.js` | claude | Freight-rate source client. Frozen/dormant and non-authoritative per the completion plan; may not influence canonical cargo-van pricing without operator re-authorization. |
| `docs/` | claude | Certification, backup/tax/authority contracts, completion plan and release documentation. |
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
| `index.html` | SHARED | UI shell + CSP/script ordering; lock before editing. |
| `manifest.json` | SHARED | PWA/release + visual metadata; lock before editing. |
| `midwest-stack-authority.js` | gpt | **Temporary bounded OMEGA exception:** v24.0.11 generation marker plus verified market-identity collision repair only; restore Claude ownership immediately after this repair lands. |
| `midwest-stack-config.json` | claude | Decision/bid configuration. |
| `modern-shell.js` | SHARED | Driver-facing structural navigation seam. Reuses canonical app renderers/state; lock before editing and run the full suite for behavior changes. |
| `schemas/` | claude | Data/contracts. |
| `scripts/` | claude | Release/certification tooling and the deploy-asset inventory. |
| `service-worker.js` | SHARED | Offline shell/release-critical. Lock before editing; full suite required. |
| `styles.css` | gpt | Operator-directed 2026-09-14 presentation takeover for the approved reference UI redesign. It carries **no version string** by design — `tests/unit/cache-generation.spec.mjs` CG-11 asserts the absence. |
| `sw-bridge.js` | SHARED | Service-worker integration/release-critical. |
| `tests/` | claude | Playwright suite. Assertions may not be weakened or quarantined to make a release green. |
| `vendor/` | claude | Bundled runtime dependencies/security provenance. |
| `voice-load.js` | gpt | **Temporary bounded OMEGA exception:** v24.0.11 shipped-module header marker only; restore Claude ownership immediately after this repair lands. |
| `wrangler.jsonc` | claude | Worker deployment/configuration. |

## Current lane intent

The targeted UI takeover changes only presentation ownership:

- `styles.css` is GPT-owned for the approved redesign and can be changed without an `app.js` lock.
- `app.js` is `SHARED` and needs `lock/app-js` plus a full suite for any edit. It remains a 1.1MB single-IIFE file where concurrent edits can lose work.
- The rest of the `SHARED` set (`index.html`, `service-worker.js`, `sw-bridge.js`, `modern-shell.js`, `manifest.json`, `.agents/`, `AGENTS.md`, `.gitignore`, `.assetsignore`) remains serialized because it is release-critical or protocol surface.
- Every other non-`SHARED` path remains Claude-owned except the exact temporary OMEGA exceptions named above.

The CSS seam stays a real physical boundary and is worth keeping: presentation changes in `styles.css` do not need an `app.js` lock. It does **not** cover UI sections that still live inside `app.js` — those remain `SHARED` until an approved extraction creates more physical paths.

`/.agents/inbox/` remains the cross-session handoff channel.

## Enforcement

This map is enforced mechanically, not by recollection:

- `scripts/lane-guard.mjs` parses **this file** as the single source of truth. There is no generated copy to drift from it.
- `.githooks/pre-commit` rejects a staged change to a foreign lane, and a staged change to a `SHARED` path with no held lock covering that path. Enable per clone: `git config core.hooksPath .githooks` and `git config freightlogic.agent <claude|gpt>`.
- `.github/workflows/lanes.yml` re-checks path ownership and commit prefixes on every PR to `main`. The hook is fast feedback and is bypassable; CI is the boundary.
- A path with **no row in this table** fails closed. Adding a file means adding its row.
- A lock past `expected_release_utc` + 2h is reported as **stale**. It grants nothing and is never auto-stolen; reap it deliberately per `/AGENTS.md`.

## Cross-lane requests

If a task requires a foreign path, write a request under `/.agents/inbox/` on `agent-coordination`. Do not make an opportunistic cross-lane edit.
